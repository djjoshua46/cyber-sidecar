import http from "k6/http";
import { check, sleep } from "k6";
import k6crypto from "k6/crypto";
import encoding from "k6/encoding";

// import { randomItem } from "https://jslib.k6.io/k6-utils/1.4.0/index.js";

// ---- CONFIG ----
const BASE = __ENV.SIDECAR_BASE || "http://127.0.0.1:8000";
const PROXY_URL = `${BASE}/proxy/http`;

// Scenarios selector: comma-separated names or "all"
const SCENARIOS = (__ENV.SCENARIOS || "all").split(",").map(s => s.trim()).filter(Boolean);

// IMPORTANT: treat 409/401 as "expected" because your proxy uses 409 for tone handshake
http.setResponseCallback(http.expectedStatuses({ min: 200, max: 499 }));

// ---- TONE CACHE (per identity) ----
const toneCache = new Map();
function toneKeyFromHeaders(h) {
  // these are required in mkHeaders()
  return `${h["X-Org-Id"]}|${h["X-User-Id"]}|${h["X-Session-Id"]}|${h["X-Device-Id"]}`;
}

function randomItem(arr) {
  return arr[Math.floor(Math.random() * arr.length)];
}

// ---- UTIL ----
// function mkExportBody(target_url, method = "GET") {
//   return {
//     target_url,
//     method,
//     headers: {},
//     body: null,
//   };
// }

function b64urlBytes(ab) {
  const b = new Uint8Array(ab);
  return encoding.b64encode(b, "rawurl");
}
function b64urlJson(obj) {
  return encoding.b64encode(JSON.stringify(obj), "rawurl");
}
function sha256_b64url_str(s) {
  const h = k6crypto.sha256(s, "binary"); // returns ArrayBuffer
  return b64urlBytes(h);
}
function randomJti() {
  const b = k6crypto.randomBytes(16);
  return encoding.b64encode(b, "rawurl");
}

async function importDpopKeypairFromEnv() {
  const privStr = __ENV.DPOP_JWK_PRIVATE || "";
  const pubStr  = __ENV.DPOP_JWK_PUBLIC || "";
  if (!privStr || !pubStr) return null;

  const jwkPriv = JSON.parse(privStr);
  const jwkPub  = JSON.parse(pubStr);

  const privateKey = await crypto.subtle.importKey(
    "jwk",
    jwkPriv,
    { name: "ECDSA", namedCurve: "P-256" },
    false,
    ["sign"]
  );

  return { jwkPub, privateKey };
}

function cleanEnvJson(s) {
  if (!s) return s;
  s = s.trim();
  s = s.replace(/^DPOP_JWK_PUBLIC\s*=\s*/i, '');
  s = s.replace(/^DPOP_JWK_PRIVATE\s*=\s*/i, '');
  if ((s.startsWith('"') && s.endsWith('"')) || (s.startsWith("'") && s.endsWith("'"))) {
    s = s.slice(1, -1);
  }
  return s;
}

const DPOP_JWK_PUBLIC = JSON.parse(cleanEnvJson(__ENV.DPOP_JWK_PUBLIC || ""));
const DPOP_JWK_PRIVATE = JSON.parse(cleanEnvJson(__ENV.DPOP_JWK_PRIVATE || ""));

function utf8Bytes(s) {
  // safe for tokens/URLs/ASCII; also works for general UTF-8
  const esc = encodeURIComponent(String(s));
  const bytes = [];
  for (let i = 0; i < esc.length; i++) {
    const c = esc[i];
    if (c === "%") {
      bytes.push(parseInt(esc.slice(i + 1, i + 3), 16));
      i += 2;
    } else {
      bytes.push(c.charCodeAt(0));
    }
  }
  return new Uint8Array(bytes);
}

async function makeDpopProof({ keypair, method, url, tone }) {
  const now = Math.floor(Date.now() / 1000);

  const header = {
    typ: "dpop+jwt",
    alg: "ES256",
    jwk: keypair.jwkPub,
  };

  const payload = {
    htm: String(method || "POST").toUpperCase(),
    htu: String(url),
    iat: now,
    jti: randomJti(),
    th: sha256_b64url_str(String(tone || "")), // binds proof to tone
  };

  const signingInput = `${b64urlJson(header)}.${b64urlJson(payload)}`;

  const sig = await crypto.subtle.sign(
    { name: "ECDSA", hash: "SHA-256" },
    keypair.privateKey,
    utf8Bytes(signingInput)
  );

  return `${signingInput}.${b64urlBytes(sig)}`;
}

function effIs(r, codes) {
  // r can be {res,json,effective} OR a raw http.Response
  const eff = (r && typeof r.effective === "number") ? r.effective : r.status;
  return codes.includes(eff);
}

function effectiveStatus(res, j) {
  // Proxy wraps decisions in JSON; HTTP often stays 200
  if (j && typeof j.status_code === "number") return j.status_code;
  // some older versions might use status_code_effective
  if (j && typeof j.status_code_effective === "number") return j.status_code_effective;
  return res.status;
}


function parseJsonSafe(res) {
  try { return res.json(); } catch (e) { return null; }
}

/**
 * Core helper: call /proxy/http and auto-handle the "tone_required / retry_with_tone" handshake.
 * Your proxy returns:
 *   - 409 with { next_action: "retry_with_tone", tone: "..." } when tone missing/invalid
 *   - 401 when biometric required
 *   - 200 when allowed (or honeypot payload)
 */
async function proxyCallWithTone({
  headers,
  body,
  maxRetries = 2,
  expectedEffective = null,
  checkLabel = "proxy: effective status ok",
} = {}) {
  let h = Object.assign({}, headers);

  const k = toneKeyFromHeaders(h);
  const cached = toneCache.get(k);
  if (cached && !h["X-Tone"]) {
    h = Object.assign({}, h, { "X-Tone": String(cached) });
  }

  let last = null;

  for (let attempt = 0; attempt <= maxRetries; attempt++) {
        // If DPoP is enabled, attach a fresh proof per request (binds to current tone)
    if (__ENV.SIDECAR_REQUIRE_DPOP === "1" && h["X-Tone"]) {
      if (!globalThis.__dpopKeypair) {
        // lazy import once per VU
        globalThis.__dpopKeypair = await importDpopKeypairFromEnv();
        if (!globalThis.__dpopKeypair) {
          throw new Error("DPoP enabled but DPOP_JWK_PRIVATE / DPOP_JWK_PUBLIC not set.");
        }
      }
      const proof = await makeDpopProof({
        keypair: globalThis.__dpopKeypair,
        method: body.method,         // bind to payload.method
        url: body.target_url,        // bind to payload.target_url
        tone: h["X-Tone"],
      });
      h = Object.assign({}, h, { DPoP: proof });
    }

    const res = http.post(PROXY_URL, JSON.stringify(body), { headers: h });
    if (!res) {
      last = { res: { status: 0, headers: {} }, json: null, headersUsed: h, effective: 0 };
      return last;
    }

    const j = parseJsonSafe(res);
    const eff = effectiveStatus(res, j);

    last = { res, json: j, headersUsed: h, effective: eff };

    const codes = (j && j.reason_codes) ? j.reason_codes : [];
    const toneRequired = codes.indexOf("tone_required") !== -1;

    if (
      (eff === 401 || eff === 409) &&
      j &&
      j.tone &&
      (j.next_action === "retry_with_tone" || toneRequired)
    ) {
      const k2 = toneKeyFromHeaders(h);
      toneCache.set(k2, String(j.tone));
      h = Object.assign({}, h, { "X-Tone": String(j.tone) });
      continue;
    }

    if (
      eff === 401 &&
      j &&
      (j.next_action === "reauth" || j.next_action === "reauth_biometric")
    ) {
      h = Object.assign({}, h, { "X-Reauth-Result": "ok" });
      continue;
    }

    if (Array.isArray(expectedEffective)) {
      check(res, { [checkLabel]: () => effIs(last, expectedEffective) });
    }

    return last;
  }

  // Exhausted retries: return last attempt, no extra HTTP call
  if (Array.isArray(expectedEffective) && last) {
    check(last.res, { [checkLabel]: () => effIs(last, expectedEffective) });
  }
  return last;
}


function mkIdentity({ orgN = 1, userN = 1, sessN = 1, devN = 1, ip = "10.0.0.10", ua = "k6-sidecar/1.0" } = {}) {
  const org = `org-${orgN}`;
  const user = `user-org-${orgN}-${userN}`;
  const session = `sess-org-${orgN}-${sessN}`;
  const device = `device-org-${orgN}-${devN}`;
  return { org, user, session, device, ip, ua };
}

function mkHeaders(id) {
  return {
    "Content-Type": "application/json",
    "X-Org-Id": id.org,
    "X-User-Id": id.user,
    "X-Session-Id": id.session,
    "X-Device-Id": id.device,
    "X-Client-Ip": id.ip,
    "User-Agent": id.ua,
  };
}

function mkExportBody(target_url, intent_bytes = 0, intent_rows = 0, method = "GET") {
  return {
    target_url,                 // ✅ REQUIRED by ProxyRequest
    method,
    headers: {},
    body: null,

    // Optional extras (proxy ignores them today; harmless to send)
    intent_bytes,
    intent_rows,
  };
}

function isCsvish(resText) {
  return typeof resText === "string" && (resText.includes(",") || resText.includes("\n"));
}

// ---- k6 OPTIONS ----
function enabled(name) {
  return SCENARIOS.includes("all") || SCENARIOS.includes(name);
}

function buildScenarios() {
  const s = {};

  if (enabled("missing_tone_probe")) {
    s.missing_tone_probe = { executor: "constant-vus", vus: 1, duration: "10s", exec: "missingToneProbe" };
  }
  if (enabled("normal_users")) {
    s.normal_users = { executor: "constant-vus", vus: 8, duration: "30s", exec: "normalUsers" };
  }
  if (enabled("huge_with_stepup")) {
    s.huge_with_stepup = { executor: "constant-vus", vus: 3, duration: "20s", exec: "hugeWithStepup" };
  }
  if (enabled("huge_without_stepup")) {
    s.huge_without_stepup = { executor: "constant-vus", vus: 3, duration: "20s", exec: "hugeWithoutStepup" };
  }
  if (enabled("stolen_stable_ip_ua_flip")) {
    s.stolen_stable_ip_ua_flip = { executor: "constant-vus", vus: 2, duration: "20s", exec: "stolenStableIpUaFlip" };
  }
  if (enabled("ua_rotation_churn")) {
    s.ua_rotation_churn = { executor: "constant-vus", vus: 2, duration: "20s", exec: "uaRotationChurn" };
  }
  if (enabled("hostile_force_block")) {
    s.hostile_force_block = { executor: "constant-vus", vus: 2, duration: "20s", exec: "hostileForceBlock" };
  }
  if (enabled("hostile_force_honeypot")) {
    s.hostile_force_honeypot = { executor: "constant-vus", vus: 2, duration: "20s", exec: "hostileForceHoneypot" };
  }

  return s;
}

export const options = {
  discardResponseBodies: false,   // <-- ADD THIS (forces bodies to be kept)
  thresholds: {
    // strict only for normal traffic
    "http_req_duration{scenario:normal_users}": ["p(95)<1500"],

    // looser for huge / hostile
    "http_req_duration{scenario:huge_with_stepup}": ["p(95)<3000"],
    "http_req_duration{scenario:huge_without_stepup}": ["p(95)<3000"],
  },
  scenarios: buildScenarios(),
};

function baseHeaders(extra = {}) {
  return {
    "user-agent": "k6-test",
    "x-k6-scenario": exec.scenario.name,   // 👈 IMPORTANT (also used for training)
    ...extra,
  };
}
// ---- SCENARIO FILTER ----
// function enabled(name) {
//   return SCENARIOS.includes("all") || SCENARIOS.includes(name);
// }

// ---- SCENARIOS ----
export async function normalUsers() {
  if (!enabled("normal_users")) return;

  const orgN = randomItem([1, 2, 3]);
  const userN = randomItem([1, 4, 10, 13, 16, 19, 21, 24]);
  const id = mkIdentity({ orgN, userN, sessN: userN, devN: userN, ip: "10.0.0.10", ua: "k6-normal/1.0" });

  const headers = mkHeaders(id);
  const body = mkExportBody("http://host.docker.internal:8099/export/small.csv");

  const r = await proxyCallWithTone({ headers, body });

  if (__ITER < 2) {
    console.log(`DEBUG normal_users keys=${Object.keys(r.json || {}).join(",")} eff=${r.effective} http=${r.res.status}`);
    console.log(`DEBUG normal_users json=${JSON.stringify(r.json || {}, null, 2)}`);
  }

  check(r.res, {
    "normal: allowed (effective 200)": () => r.effective === 200,
    "normal: csv-ish": () => {
      const j = r.json || {};
      const ct = (r.res.headers["Content-Type"] || r.res.headers["content-type"] || "").toLowerCase();
      const hdrs = (r && r.res && r.res.headers) ? r.res.headers : {};

      // If proxy returned raw CSV, validate directly
      if (ct.includes("text/csv") || ct.includes("application/csv")) {
        return isCsvish(String(r.res.body || ""));
      }

      // Otherwise try wrapper fields, then fall back to body
      const txt =
        j.upstream_body ??
        j.body ??
        j.body_text ??
        j.response_body ??
        j.preview ??
        r.res.body ??
        "";

      return isCsvish(String(txt));
    },
  });

  sleep(0.2);
}

export async function hugeWithStepup() {
  if (!enabled("huge_with_stepup")) return;

  const id = mkIdentity({ orgN: 3, userN: 3, sessN: 3, devN: 3, ip: "10.0.0.10", ua: "k6-huge-step/1.0" });
  const headers = mkHeaders(id);

  const body = mkExportBody("http://host.docker.internal:8099/export/huge.csv", 5_000_000, 5_000);
  const r = await proxyCallWithTone({ headers, body });

  check(r.res, {
    "huge step: effective 200 or 401": () => r.effective === 200 || r.effective === 401,
    "huge step: if 401 -> biometric": () => {
      if (r.effective !== 401) return true;
      const j = r.json;
      return j && (j.next_action === "reauth" || j.next_action === "reauth_biometric" || j.action === "biometric");
    },
  });

  sleep(0.2);
}

export async function hugeWithoutStepup() {
  if (!enabled("huge_without_stepup")) return;

  const id = mkIdentity({ orgN: 2, userN: 5, sessN: 5, devN: 5, ip: "10.0.0.10", ua: "k6-huge-nostep/1.0" });
  const headers = mkHeaders(id);
  const body = mkExportBody("http://host.docker.internal:8099/export/huge.csv", 5_000_000, 5_000);

  const r = await proxyCallWithTone({ headers, body });

  check(r.res, {
    "huge no-step: effective 200 or 401": () => effIs(r, [200, 401]),
    "huge no-step: if 401 -> step-up": () => {
      if (r.effective !== 401) return true;
      const j = r.json;
      return j && (j.next_action === "reauth" || j.next_action === "reauth_biometric" || j.action === "biometric");
    },
  });

  sleep(0.2);
}


export async function stolenStableIpUaFlip() {
  if (!enabled("stolen_stable_ip_ua_flip")) return;

  // Phase A: establish session with UA1
  const idA = mkIdentity({ orgN: 1, userN: 7, sessN: 7, devN: 7, ip: "10.0.0.10", ua: "k6-UA-A/1.0" });
  const headersA = mkHeaders(idA);
  const small = mkExportBody("http://host.docker.internal:8099/export/small.csv", 10_000, 5);

  const r1 = await proxyCallWithTone({ headers: headersA, body: small });
  check(r1.res, { "stolen UA flip: phaseA effective 200": () => r1.effective === 200 });

  // Phase B: same IP/session/device, different UA
  const headersB = mkHeaders({ ...idA, ua: "k6-UA-B/9.9" });
  const huge = mkExportBody("http://host.docker.internal:8099/export/huge.csv", 5_000_000, 5_000);

  const r2 = await proxyCallWithTone({ headers: headersB, body: huge });

  check(r2.res, {
    "stolen UA flip: effective 401 or 200": () => effIs(r2, [200, 401]),
  });

  sleep(0.2);
}

export async function uaRotationChurn() {
  if (!enabled("ua_rotation_churn")) return;

  const base = mkIdentity({ orgN: 1, userN: 10, sessN: 10, devN: 10, ip: "10.0.0.10", ua: "k6-rot/0" });
  const body = mkExportBody("http://host.docker.internal:8099/export/medium.csv", 500_000, 800);

  const ua = `k6-rot/${Math.floor(Math.random() * 100000)}`;
  const headers = mkHeaders({ ...base, ua });

  const r = await proxyCallWithTone({ headers, body });

  check(r.res, {
    "ua-rotate: effective valid": () => [200, 401, 409].includes(r.effective),
  });

  sleep(0.1);
}


export function missingToneProbe() {
  if (!enabled("missing_tone_probe")) return;

  // identity
  const org = "org-2";
  const user = "user-org-2-17";
  const session = "sess-org-2-17";
  const device = "device-org-2-17";

  // IMPORTANT: omit X-Tone on purpose
  const headers = {
    "Content-Type": "application/json",
    "X-Org-Id": org,
    "X-User-Id": user,
    "X-Session-Id": session,
    "X-Device-Id": device,
    "X-Client-Ip": "10.0.0.10",
    "User-Agent": "k6-missing-tone/1.0",
  };

  const body = mkExportBody("http://host.docker.internal:8099/export/small.csv");

  const res = http.post(PROXY_URL, JSON.stringify(body), { headers });
  const j = parseJsonSafe(res);
  const eff = effectiveStatus(res, j);

  if (__ITER < 1) {
    console.log(`DEBUG missingToneProbe http=${res.status} eff=${eff} ct=${res.headers["Content-Type"]}`);
    console.log(`DEBUG missingToneProbe body_len=${(res.body || "").length}`);
    console.log(`DEBUG missingToneProbe body_head=${String(res.body || "").slice(0, 200)}`);
    console.log(`DEBUG missingToneProbe json=${JSON.stringify(j)}`);
  }

  const okHandshake = (eff === 401 || eff === 409) && j && j.next_action === "retry_with_tone" && !!j.tone;

  // If server is force-setting reauth/reauth_biometric, accept that too (no tone issued)
  const okForced = (eff === 401) && j && (j.next_action === "reauth" || j.next_action === "reauth_biometric");

  if (!okHandshake && !okForced) {
    console.log(`missingToneProbe FAIL http=${res.status} eff=${eff} json=${JSON.stringify(j)}`);
  }

  check(res, {
    "missing tone: effective handshake (409/401 retry_with_tone) OR forced step-up": () => okHandshake || okForced,
    "missing tone: has next_action (retry_with_tone or reauth*)": () => {
      if (!j) return false;
      if (j.next_action === "retry_with_tone") return !!j.tone;
      if (j.next_action === "reauth" || j.next_action === "reauth_biometric") return true;
      return false;
    },
  });

  sleep(0.2);
}

export async function hostileForceBlock() {
  if (!enabled("hostile_force_block")) return;

  const id = mkIdentity({ orgN: 9, userN: 9, sessN: 9, devN: 9, ip: "10.0.0.66", ua: "k6-hostile-block/1.0" });
  const headers = mkHeaders(id);

  const body = mkExportBody("http://host.docker.internal:8099/export/huge.csv", 9_000_000, 9_999, "GET");

  const r = await proxyCallWithTone({ headers, body });

  check(r.res, {
    "hostile_force_block: effective 401/403/429/200/409": () => effIs(r, [200, 401, 403, 409, 429]),
  });

  sleep(0.2);
}


export async function hostileForceHoneypot() {
  if (!enabled("hostile_force_honeypot")) return;

  const id = mkIdentity({ orgN: 9, userN: 10, sessN: 10, devN: 10, ip: "10.0.0.77", ua: "k6-hostile-honey/1.0" });
  const headers = mkHeaders(id);

  const body = mkExportBody("http://host.docker.internal:8099/export/honeypot.csv", 123_456, 123, "GET");

  const r = await proxyCallWithTone({ headers, body });

  check(r.res, {
    "hostile_force_honeypot: effective 200/401/409": () => effIs(r, [200, 401, 409]),
  });

  sleep(0.2);
}