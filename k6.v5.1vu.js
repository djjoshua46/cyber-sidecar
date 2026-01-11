import http from "k6/http";
import { check, sleep } from "k6";
// import { randomItem } from "https://jslib.k6.io/k6-utils/1.4.0/index.js";

// ---- CONFIG ----
const BASE = __ENV.SIDECAR_BASE || "http://127.0.0.1:8000";
const PROXY_URL = `${BASE}/proxy/http`;

// Scenarios selector: comma-separated names or "all"
const SCENARIOS = (__ENV.SCENARIOS || "all").split(",").map(s => s.trim()).filter(Boolean);

// IMPORTANT: treat 409/401 as "expected" because your proxy uses 409 for tone handshake
http.setResponseCallback(http.expectedStatuses({ min: 200, max: 499 }));

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
function proxyCallWithTone({ headers, body, maxRetries = 2 }) {
  let h = Object.assign({}, headers);

  for (let attempt = 0; attempt <= maxRetries; attempt++) {
    const res = http.post(PROXY_URL, JSON.stringify(body), { headers: h });
    const j = parseJsonSafe(res);

    // Your proxy may use 401 or 409 for the tone handshake depending on config/version.
    // If proxy tells us to retry with a tone, attach it and retry immediately.
    if (
      (res.status === 401 || res.status === 409) &&
      j &&
      j.next_action === "retry_with_tone" &&
      j.tone
    ) {
      h["X-Tone"] = String(j.tone);
      continue;
    }

    return { res, json: j, headersUsed: h };
  }

  // If we somehow exhausted retries, return last try (should be rare)
  const res = http.post(PROXY_URL, JSON.stringify(body), { headers: h });
  return { res, json: parseJsonSafe(res), headersUsed: h };
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
    s.normal_users = { executor: "constant-vus", vus: 1, duration: "30s", exec: "normalUsers" };
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

  return s;
}

export const options = {
  thresholds: { "http_req_duration{status:200}": ["p(95)<1500"] },
  scenarios: buildScenarios(),
};


// ---- SCENARIO FILTER ----
// function enabled(name) {
//   return SCENARIOS.includes("all") || SCENARIOS.includes(name);
// }

// ---- SCENARIOS ----
export function normalUsers() {
  if (!enabled("normal_users")) return;

  const orgN = randomItem([1, 2, 3]);
  const userN = randomItem([1, 4, 10, 13, 16, 19, 21, 24]);
  const id = mkIdentity({ orgN, userN, sessN: userN, devN: userN, ip: "10.0.0.10", ua: "k6-normal/1.0" });

  const headers = mkHeaders(id);
  const body = mkExportBody("http://127.0.0.1:8099/export/small.csv");

  const { res } = proxyCallWithTone({ headers, body });

  check(res, {
    "normal: 200": (r) => r.status === 200,
    "normal: csv-ish": (r) => isCsvish(r.body),
  });

  sleep(0.2);
}

export function hugeWithStepup() {
  if (!enabled("huge_with_stepup")) return;

  const id = mkIdentity({ orgN: 3, userN: 3, sessN: 3, devN: 3, ip: "10.0.0.10", ua: "k6-huge-step/1.0" });
  const headers = mkHeaders(id);

  const body = mkExportBody("http://127.0.0.1:8099/export/huge.csv", 5_000_000, 5_000);
  const { res, json } = proxyCallWithTone({ headers, body });

  check(res, {
    "huge step: 200 or 401": (r) => r.status === 200 || r.status === 401,
    "huge step: if 401 -> biometric": (r) => {
      if (r.status !== 401) return true;
      return json && (json.next_action === "reauth" || json.next_action === "reauth_biometric" || json.action === "biometric");
    },
  });

  sleep(0.2);
}

export function hugeWithoutStepup() {
  if (!enabled("huge_without_stepup")) return;

  const id = mkIdentity({ orgN: 2, userN: 5, sessN: 5, devN: 5, ip: "10.0.0.10", ua: "k6-huge-nostep/1.0" });
  const headers = mkHeaders(id);
  const body = mkExportBody("http://127.0.0.1:8099/export/huge.csv", 5_000_000, 5_000);

  const { res, json } = proxyCallWithTone({ headers, body });

  check(res, {
    "huge no-step: 401 or 200": (r) => r.status === 401 || r.status === 200,
    "huge no-step: if 401 -> step-up": (r) => {
      if (r.status !== 401) return true;
      return json && (json.next_action === "reauth" || json.next_action === "reauth_biometric" || json.action === "biometric");
    },
  });

  sleep(0.2);
}

export function stolenStableIpUaFlip() {
  if (!enabled("stolen_stable_ip_ua_flip")) return;

  // Phase A: establish session with UA1
  const idA = mkIdentity({ orgN: 1, userN: 7, sessN: 7, devN: 7, ip: "10.0.0.10", ua: "k6-UA-A/1.0" });
  const headersA = mkHeaders(idA);
  const small = mkExportBody("http://127.0.0.1:8099/export/small.csv", 10_000, 5);

  const r1 = proxyCallWithTone({ headers: headersA, body: small });
  check(r1.res, { "stolen UA flip: phaseA 200": (r) => r.status === 200 });

  // Phase B: same IP/session/device, different UA
  const headersB = mkHeaders({ ...idA, ua: "k6-UA-B/9.9" });
  const huge = mkExportBody("http://127.0.0.1:8099/export/huge.csv", 5_000_000, 5_000);

  const r2 = proxyCallWithTone({ headers: headersB, body: huge });

  check(r2.res, {
    "stolen UA flip: 401 or 200": (r) => r.status === 401 || r.status === 200,
  });

  sleep(0.2);
}

export function uaRotationChurn() {
  if (!enabled("ua_rotation_churn")) return;

  const base = mkIdentity({ orgN: 1, userN: 10, sessN: 10, devN: 10, ip: "10.0.0.10", ua: "k6-rot/0" });
  const body = mkExportBody("http://127.0.0.1:8099/export/medium.csv", 500_000, 800);

  const ua = `k6-rot/${Math.floor(Math.random() * 100000)}`;
  const headers = mkHeaders({ ...base, ua });

  const { res } = proxyCallWithTone({ headers, body });

  check(res, {
    "ua-rotate: valid status": (r) => [200, 401, 409].includes(r.status),
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

  const body = mkExportBody("http://127.0.0.1:8099/export/small.csv");

  const res = http.post(PROXY_URL, JSON.stringify(body), { headers });

  let j = null;
  try { j = res.json(); } catch (e) {}

  const ok1 = res.status === 401;
  const ok2 = j && j.next_action === "retry_with_tone" && !!j.tone;

  if (!ok1 || !ok2) {
    console.log(`missingToneProbe FAIL status=${res.status} body=${res.body}`);
  }

  check(res, {
    "missing tone: handshake (401/409)": () => res.status === 401 || res.status === 409,
    "missing tone: has next_action retry": () => ok2,
  });

  sleep(0.2);
}
