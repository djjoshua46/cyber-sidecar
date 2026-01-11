from locust import HttpUser, task, between, events
import os
import uuid

SIDECAR_HOST = os.getenv("SIDECAR_HOST", "http://127.0.0.1:8000")
UPSTREAM = os.getenv("UPSTREAM", "http://127.0.0.1:8099")

# MODE:
#   baseline = stable session per user (what you want for “normal usage”)
#   adversary = rotates session/device more aggressively (chaos)
MODE = os.getenv("MODE", "baseline").lower()


class SidecarUser(HttpUser):
    host = SIDECAR_HOST
    wait_time = between(0.1, 0.3)

    def on_start(self):
        # stable identity per Locust user
        self.user_id = os.getenv("USER_ID", "josh")
        self.device_id = f"laptop-{uuid.uuid4().hex[:6]}"
        self.session_id = f"sess-{uuid.uuid4()}"  # stable per user in baseline mode

    def _headers(self, tone: str | None = None, reauth_ok: bool = False) -> dict:
        h = {
            "X-User-Id": self.user_id,
            "X-Device-Id": self.device_id,
            "X-Session-Id": self.session_id,
        }
        if tone:
            h["X-Tone"] = tone
        if reauth_ok:
            h["X-Reauth-Result"] = "ok"
        return h

    def _payload(self, target_url: str) -> dict:
        return {
            "target_url": target_url,
            "method": "GET",
            "headers": {},
            "body": None,
        }

    def _do_proxy_call(self, target_url: str, name_prefix: str):
        # In adversary mode we rotate more often (worst-case “attacker” behavior)
        if MODE == "adversary":
            self.session_id = f"sess-{uuid.uuid4()}"
            if uuid.uuid4().int % 5 == 0:
                self.device_id = f"laptop-{uuid.uuid4().hex[:6]}"

        headers = self._headers()
        payload = self._payload(target_url)

        # 1) preflight
        with self.client.post(
            "/proxy/http",
            json=payload,
            headers=headers,
            name=f"{name_prefix} (preflight)",
            catch_response=True,
        ) as r:
            if r.status_code in (200, 401, 409):
                r.success()
            else:
                r.failure(f"unexpected preflight status {r.status_code}: {r.text[:200]}")
                return

            # 2) retry with X-Tone if challenged
            if r.status_code == 409:
                try:
                    body = r.json()
                except Exception:
                    body = {}

                tone = body.get("tone")
                if not tone:
                    r.failure("409 without tone in body")
                    return

                headers2 = self._headers(tone=tone)

                with self.client.post(
                    "/proxy/http",
                    json=payload,
                    headers=headers2,
                    name=f"{name_prefix} (retry)",
                    catch_response=True,
                ) as r2:
                    if r2.status_code in (200, 401, 409):
                        r2.success()
                    else:
                        r2.failure(f"unexpected retry status {r2.status_code}: {r2.text[:200]}")

    @task(6)
    def export_small(self):
        self._do_proxy_call(f"{UPSTREAM}/export/small.csv", "/proxy/http small")

    @task(3)
    def export_medium(self):
        self._do_proxy_call(f"{UPSTREAM}/export/medium.csv", "/proxy/http medium")

    @task(1)
    def export_huge(self):
        # This is the one most likely to trigger deception depending on your policy thresholds
        self._do_proxy_call(f"{UPSTREAM}/export/huge.csv", "/proxy/http huge")
