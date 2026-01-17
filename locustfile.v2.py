"""
Locust load test for Sidecar with three traffic shapes:
  - legit: normal employees
  - low_slow: patient exfil cadence
  - rake: noisy abusive traffic

Run examples:
  # Legit business day
  set MODE=legit
  locust -f locustfile.v2.py --host=http://127.0.0.1:8000

  # Low-and-slow
  set MODE=low_slow
  set ORGS=5
  locust -f locustfile.v2.py --host=http://127.0.0.1:8000

  # Rake attack
  set MODE=rake
  locust -f locustfile.v2.py --host=http://127.0.0.1:8000

Env vars:
  MODE=legit|low_slow|rake
  UPSTREAM=http://127.0.0.1:8099
  ORGS=1..N
"""
import os
import random
from dataclasses import dataclass
from typing import Dict, Any

from locust import HttpUser, task, between

UPSTREAM = os.getenv("UPSTREAM", "http://127.0.0.1:8099").rstrip("/")
MODE = (os.getenv("MODE", "legit") or "legit").lower().strip()
ORGS = int(os.getenv("ORGS", "1"))

TARGETS = [
    "/export/small.csv",
    "/export/medium.csv",
    "/export/large.csv",
]


def pick_org_id(vu_id: int) -> str:
    if ORGS <= 1:
        return "org-1"
    n = (vu_id % ORGS) + 1
    return f"org-{n}"


@dataclass
class Identity:
    org_id: str
    user_id: str
    device_id: str
    session_id: str

    def headers(self) -> Dict[str, str]:
        return {
            "Content-Type": "application/json",
            "X-Org-Id": self.org_id,
            "X-User-Id": self.user_id,
            "X-Device-Id": self.device_id,
            "X-Session-Id": self.session_id,
        }


def sidecar_post_with_tone(client, payload: Dict[str, Any], headers: Dict[str, str]) -> int:
    """
    Call /proxy/http with tone handshake:
      - first POST may return 409 with JSON {"tone": "..."} -> retry once with X-Tone
      - 401 means "reauth required" (expected in some modes); treat as success for load shape
    Returns final HTTP status.
    """
    r1 = client.post("/proxy/http", json=payload, headers=headers, name="/proxy/http")
    if r1.status_code == 409:
        tone = None
        try:
            body = r1.json()
            tone = body.get("tone")
        except Exception:
            tone = None
        if tone:
            headers2 = dict(headers)
            headers2["X-Tone"] = str(tone)
            r2 = client.post("/proxy/http", json=payload, headers=headers2, name="/proxy/http (retry)")
            return r2.status_code
    return r1.status_code


class SidecarUser(HttpUser):
    """
    One Locust user == one employee device/session.
    We keep identity stable so Sidecar can build baselines.
    """
    if MODE == "low_slow":
        wait_time = between(2.0, 3.0)
    elif MODE == "rake":
        wait_time = between(0.01, 0.05)
    else:
        wait_time = between(0.2, 0.8)

    def on_start(self):
        # Each Locust user instance gets a stable identity
        vu = getattr(self.environment.runner, "user_count", 1)
        # We can't directly read VU index; use random stable ids.
        org_id = pick_org_id(random.randint(1, 10_000))
        self.ident = Identity(
            org_id=org_id,
            user_id=f"user-{org_id}-{random.randint(1, 10_000)}",
            device_id=f"device-{org_id}-{random.randint(1, 10_000)}",
            session_id=f"sess-{org_id}-{random.randint(1, 10_000)}",
        )

    @task
    def traffic(self):
        if MODE == "rake":
            self._rake()
        elif MODE == "low_slow":
            self._low_slow()
        else:
            self._legit()

    def _legit(self):
        target = "/export/small.csv" if random.random() < 0.8 else "/export/medium.csv"
        payload = {"target_url": f"{UPSTREAM}{target}", "method": "GET", "headers": {}}
        status = sidecar_post_with_tone(self.client, payload, self.ident.headers())
        # Accept 200/401/409 as workflow-expected
        if status not in (200, 401, 409):
            # Let Locust count it as failure
            raise Exception(f"Unexpected status={status}")

    def _low_slow(self):
        # Patient, steady extraction of a higher-value target
        payload = {"target_url": f"{UPSTREAM}/export/medium.csv", "method": "GET", "headers": {}}
        status = sidecar_post_with_tone(self.client, payload, self.ident.headers())
        if status not in (200, 401, 409):
            raise Exception(f"Unexpected status={status}")

    def _rake(self):
        # Noisy: random targets and often garbage tone
        target = random.choice(TARGETS)
        payload = {"target_url": f"{UPSTREAM}{target}", "method": "GET", "headers": {}}
        headers = self.ident.headers()
        if random.random() < 0.6:
            headers = dict(headers)
            headers["X-Tone"] = "bad-tone"
        r = self.client.post("/proxy/http", json=payload, headers=headers, name="/proxy/http (rake)")
        if r.status_code not in (200, 401, 409):
            raise Exception(f"Unexpected status={r.status_code}")
