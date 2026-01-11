import http from "k6/http";
import { check, sleep } from "k6";
import { uuidv4 } from "https://jslib.k6.io/k6-utils/1.4.0/index.js";

// IMPORTANT: do NOT count 4xx as "failed" because 401/409 are expected.
http.setResponseCallback(http.expectedStatuses({ min: 200, max: 499 }));

const SIDECAR = __ENV.SIDECAR || "http://127.0.0.1:8000";
const UPSTREAM = __ENV.UPSTREAM || "http://127.0.0.1:8099";
const MODE = (__ENV.MODE || "baseline").toLowerCase(); // baseline | adversary

export const options = {
  vus: __ENV.VUS ? parseInt(__ENV.VUS, 10) : 10,
  duration: __ENV.DURATION || "20s",
};

function headersFor({ userId, deviceId, sessionId, tone }) {
  const h = {
    "Content-Type": "application/json",
    "X-User-Id": userId,
    "X-Device-Id": deviceId,
    "X-Session-Id": sessionId,
  };
  if (tone) h["X-Tone"] = tone;
  return h;
}

function proxyPayload(targetUrl) {
  return JSON.stringify({
    target_url: targetUrl,
    method: "GET",
    headers: {},
    body: null,
  });
}

export default function () {
  const userId = "josh";

  // Stable per VU identity (baseline)
  let deviceId = `laptop-${__VU}`;
  let sessionId = `sess-${__VU}-${uuidv4()}`;

  // In adversary mode we rotate session/device frequently
  if (MODE === "adversary") {
    deviceId = `laptop-${uuidv4().slice(0, 6)}`;
    sessionId = `sess-${uuidv4()}`;
  }

  // Weighted target selection
  const roll = Math.random();
  let targetUrl;
  if (roll < 0.6) targetUrl = `${UPSTREAM}/export/small.csv`;
  else if (roll < 0.9) targetUrl = `${UPSTREAM}/export/medium.csv`;
  else targetUrl = `${UPSTREAM}/export/huge.csv`;

  const payload = proxyPayload(targetUrl);

  // 1) preflight
  const res = http.post(`${SIDECAR}/proxy/http`, payload, {
    headers: headersFor({ userId, deviceId, sessionId }),
    tags: { phase: "preflight" },
  });

  check(res, {
    "preflight: status is 200/401/409": (r) =>
      r.status === 200 || r.status === 401 || r.status === 409,
  });

  // 2) retry if 409 w/ tone
  if (res.status === 409) {
    let tone = null;
    try {
      const body = res.json();
      tone = body && body.tone;
    } catch (e) {
      tone = null;
    }

    if (tone) {
      const res2 = http.post(`${SIDECAR}/proxy/http`, payload, {
        headers: headersFor({ userId, deviceId, sessionId, tone }),
        tags: { phase: "retry" },
      });

      check(res2, {
        "retry: status is 200/401/409": (r) =>
          r.status === 200 || r.status === 401 || r.status === 409,
      });
    }
  }

  sleep(0.2);
}
