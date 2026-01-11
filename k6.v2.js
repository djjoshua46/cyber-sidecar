import http from "k6/http";
import { check, sleep } from "k6";
import { uuidv4 } from "https://jslib.k6.io/k6-utils/1.4.0/index.js";

const toneCache = {}; // key: `${orgId}|${userId}|${deviceId}`
/**
 * Sidecar load test with 3 traffic shapes:
 *  - legit: normal employees
 *  - low_slow: patient exfiltration-like cadence
 *  - rake: noisy/abusive traffic
 *
 * Usage examples:
 *  k6 run -e MODE=legit -e VUS=50 -e DURATION=2m -e ORGS=5 -e SIDECAR=http://127.0.0.1:8000 -e UPSTREAM=http://127.0.0.1:8099 k6.js
 *  k6 run -e MODE=low_slow -e VUS=5 -e DURATION=10m k6.js
 *  k6 run -e MODE=rake -e VUS=200 -e DURATION=2m k6.js
 */

// IMPORTANT: do NOT count 4xx as "failed" because 401/409 are expected in this workflow.
http.setResponseCallback(http.expectedStatuses({ min: 200, max: 499 }));

const SIDECAR = __ENV.SIDECAR || "http://127.0.0.1:8000";
const UPSTREAM = __ENV.UPSTREAM || "http://127.0.0.1:8099";
const MODE = (__ENV.MODE || "legit").toLowerCase();

const VUS = parseInt(__ENV.VUS || "10", 10);
const DURATION = __ENV.DURATION || "60s";
const ORGS = parseInt(__ENV.ORGS || "1", 10);

let currentSessionId = null;
let sessionBornAt = 0;
let sessionTtlMs = 0;

// Targets you can expand later
const TARGETS = [
  "/export/small.csv",
  "/export/medium.csv",
  "/export/large.csv",
  "/export/huge.csv",
];

function pickOrgId() {
  if (ORGS <= 1) return "org-1";
  const n = ((__VU - 1) % ORGS) + 1; // stable org per VU
  return `org-${n}`;
}

function buildProxyPayload(targetPath, method = "GET") {
  return JSON.stringify({
    target_url: `${UPSTREAM}${targetPath}`,
    method,
    headers: {},
  });
}

/**
 * Do a Sidecar call with tone handshake handling:
 * - If 409: extract tone from JSON and retry once
 * - If 401: treat as "reauth required" (expected) and stop this iteration
 */
function sidecarCallWithTone(payload, baseHeaders, identityKey) {
  let headers = { ...baseHeaders };

  // If we already have a tone, send it
  if (toneCache[identityKey]) {
    headers["X-Tone"] = toneCache[identityKey];
  }

  let res = http.post(`${SIDECAR}/proxy/http`, payload, { headers });

  function tryExtractTone(r) {
    try {
      const body = r.json();
      if (body && body.tone) return String(body.tone);
    } catch (_) {}
    return null;
  }

  // 409 = tone required or rotated -> cache + retry once
  if (res.status === 409) {
    const newTone = tryExtractTone(res);
    if (newTone) {
      toneCache[identityKey] = newTone;

      res = http.post(`${SIDECAR}/proxy/http`, payload, {
        headers: { ...baseHeaders, "X-Tone": newTone },
      });
      return res;
    }
  }

  // 401 can also carry a tone (tone_required / reauth) in some flows -> cache + retry once
  if (res.status === 401) {
    const newTone = tryExtractTone(res);
    if (newTone) {
      toneCache[identityKey] = newTone;

      // simulate reauth pass so preflight can proceed (proxy checks this)
      const retryHeaders = {
        ...baseHeaders,
        "X-Tone": newTone,
        "X-Reauth-Result": "ok",
      };

      res = http.post(`${SIDECAR}/proxy/http`, payload, { headers: retryHeaders });
      return res;
    } else {
      // if it's "invalid_tone" with no new tone, drop cached tone so next iter can re-handshake
      delete toneCache[identityKey];
      return res;
    }
  }

  return res;
}

function maybeRotateSession(orgId) {
  // Default: stable session per VU (normal user behavior)
  const base = `sess-${orgId}-${__VU}`;

  // Optional rotation knobs (env vars)
  const rotate = (__ENV.ROTATE_SESSION === "1");
  const p = Number(__ENV.SESSION_ROTATE_P || "0"); // 0.0 to 1.0

  if (!rotate) return base;

  // Rotate sometimes (simulate odd behavior / session churn / attacker replay)
  if (Math.random() < p) {
    return `${base}-${Date.now()}-${__ITER}`;
  }

  return base;
}


export const options = (() => {
  // Use scenarios so each mode has a stable cadence.
  if (MODE === "low_slow") {
  return {
    scenarios: {
      low_slow: {
        executor: "constant-vus",
        vus: VUS,                 // e.g. 3–10
        duration: DURATION,       // e.g. 10m
      },
    },
  };
}


  if (MODE === "rake") {
    return {
      scenarios: {
        rake: {
          executor: "constant-vus",
          vus: VUS,
          duration: DURATION,
        },
      },
    };
  }

  // default: legit
  return {
    scenarios: {
      legit: {
        executor: "constant-vus",
        vus: VUS,
        duration: DURATION,
      },
    },
  };
})();

export default function () {
  // Identity anchors (required by Sidecar preflight)
  const orgId = pickOrgId();
  const userId = `user-${orgId}-${__VU}`;          // stable per VU
  const deviceId = `device-${orgId}-${__VU}`;      // stable per VU
  const sessionId = maybeRotateSession(orgId);

  // Base headers for Sidecar
  const headers = {
    "Content-Type": "application/json",
    "X-Org-Id": orgId,
    "X-User-Id": userId,
    "X-Device-Id": deviceId,
    "X-Session-Id": sessionId,
  };

  if (MODE === "rake") {
    // Aggressive: mostly invalid/empty tone, high rate, many targets.
    // Goal: stress preflight + logging + upstream protection.
    const targetPath = TARGETS[Math.floor(Math.random() * TARGETS.length)];
    const payload = buildProxyPayload(targetPath);

    // Deliberately add garbage tone sometimes to simulate spoof attempts.
    if (Math.random() < 0.6) headers["X-Tone"] = `bad-${uuidv4()}`;

    const res = http.post(`${SIDECAR}/proxy/http`, payload, { headers });

    // We still accept 200/401/409; rake is about capacity, not success.
    check(res, {
      "rake: status is 200/401/409": (r) => r.status === 200 || r.status === 401 || r.status === 409,
    });

    // Very short sleep -> high QPS
    sleep(0.02);
    return;
  }

  if (MODE === "low_slow") {
    // Patient: consistent cadence, usually same high-value target.
    // Use tone handshake properly (looks "legit") but extracts steadily.
    const targetPath = "/export/medium.csv";
    const payload = buildProxyPayload(targetPath);

    const identityKey = `${orgId}|${userId}|${deviceId}|${sessionId}`;
    const res = sidecarCallWithTone(payload, headers, identityKey);

    // Cadence intentionally slow (blend into day-to-day)
    sleep(2.0 + Math.random()); // 2-3s
    return;
  }

  // legit: mixed traffic, reasonable pacing
  const r = Math.random();
  const targetPath =
    r < 0.70 ? "/export/small.csv" :
    r < 0.90 ? "/export/medium.csv" :
              "/export/huge.csv";
  const payload = buildProxyPayload(targetPath);

  const identityKey = `${orgId}|${userId}|${deviceId}|${sessionId}`;
  const res = sidecarCallWithTone(payload, headers, identityKey);

  // Think-time / human-ish pauses
  sleep(0.2 + Math.random() * 0.6); // 0.2-0.8s
}