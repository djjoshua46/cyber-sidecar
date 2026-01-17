"""
adversary_harness.py

Runs a local upstream "customer export" service AND drives Sidecar's /proxy/http
to verify:
  - allow
  - reauth_biometric
  - deception (honeypot response)
  - (optional) block (if policy mode blocks high)

Usage (PowerShell):
  python adversary_harness.py --sidecar http://127.0.0.1:8000

What it assumes about your sidecar:
  - POST {sidecar}/proxy/http exists (mounted by app.include_router(proxy.router))
  - GET  {sidecar}/proxy/replay/session/{session_id} exists
  - ProxyRequest shape: {target_url, method, headers, body}
"""

from __future__ import annotations

import argparse
import json
import threading
import time
import uuid
from dataclasses import dataclass
from typing import Dict, Optional

import httpx
from fastapi import FastAPI, Response
import uvicorn


# ----------------------------
# Upstream (fake customer app)
# ----------------------------

def make_csv(rows: int) -> bytes:
    # header + rows
    lines = ["id,val"]
    for i in range(rows):
        lines.append(f"{i},{i*i}")
    return ("\n".join(lines) + "\n").encode("utf-8")


def build_upstream_app() -> FastAPI:
    app = FastAPI(title="UpstreamFakeCustomer")

    @app.get("/export/small.csv")
    def export_small():
        return Response(content=make_csv(5), media_type="text/csv")

    @app.get("/export/medium.csv")
    def export_medium():
        # enough to add noticeable row_count/byte_size
        return Response(content=make_csv(800), media_type="text/csv")

    @app.get("/export/huge.csv")
    def export_huge():
        # big enough to trigger risk_engine export spike + honeypot
        return Response(content=make_csv(5000), media_type="text/csv")

    @app.get("/export/binary")
    def export_binary():
        # non-csv path
        blob = b"\x00" * (1024 * 512)  # 512KB
        return Response(content=blob, media_type="application/octet-stream")

    return app


def start_upstream_in_thread(host: str, port: int) -> threading.Thread:
    app = build_upstream_app()
    config = uvicorn.Config(app, host=host, port=port, log_level="warning")
    server = uvicorn.Server(config)

    t = threading.Thread(target=server.run, daemon=True)
    t.start()

    # crude wait until it's listening
    time.sleep(0.6)
    return t


# ----------------------------
# Harness runner
# ----------------------------

@dataclass
class Scenario:
    name: str
    target_path: str
    headers: Dict[str, str]
    expect_next_action_in: set[str]
    expect_deception: Optional[bool] = None


async def call_sidecar_proxy(
    client: httpx.AsyncClient,
    sidecar_base: str,
    target_url: str,
    headers: Dict[str, str],
) -> dict:
    payload = {
        "target_url": target_url,
        "method": "GET",
        "headers": {},
        "body": None,
    }
    r = await client.post(f"{sidecar_base}/proxy/http", headers=headers, json=payload)
    # sidecar may 403 for blocks
    if r.status_code == 403:
        try:
            detail = r.json()
        except Exception:
            detail = {"detail": r.text}
        return {"_blocked": True, "_status": 403, "_detail": detail}

        # Don't crash the harness on "expected" security outcomes
    if r.status_code in (401, 403, 409, 429):
        try:
            return r.json()
        except Exception:
            return {"status_code": r.status_code, "raw": r.text}

    # For everything else, keep failing loudly so we notice real bugs
    r.raise_for_status()
    return r.json()


async def fetch_timeline(
    client: httpx.AsyncClient,
    sidecar_base: str,
    session_id: str,
) -> dict:
    r = await client.get(f"{sidecar_base}/proxy/replay/session/{session_id}")
    r.raise_for_status()
    return r.json()


def assert_condition(ok: bool, msg: str) -> None:
    if not ok:
        raise AssertionError(msg)


async def run():
    parser = argparse.ArgumentParser()
    parser.add_argument("--sidecar", default="http://127.0.0.1:8085", help="Sidecar base URL")
    parser.add_argument("--upstream-host", default="127.0.0.1")
    parser.add_argument("--upstream-port", type=int, default=8099)
    args = parser.parse_args()

    sidecar = args.sidecar.rstrip("/")
    upstream_host = args.upstream_host
    upstream_port = args.upstream_port

    # Start upstream local service
    start_upstream_in_thread(upstream_host, upstream_port)
    upstream_base = f"http://{upstream_host}:{upstream_port}"

    # A stable identity to build baseline, then deliberately violate it
    user_id = "josh"
    device_id = "laptop-1"

    # Scenarios:
    # - allow: identity present, small export
    # - biometric: change device_id (new device anomaly) + medium export
    # - deception: new device + new session + huge export -> should hit honeypot
    # - optional block: depends on your policy.mode / thresholds
    scenarios = []

    # 1) Allow
    s1_session = str(uuid.uuid4())
    scenarios.append(
        Scenario(
            name="ALLOW_small_export",
            target_path="/export/small.csv",
            headers={
                "X-User-Id": user_id,
                "X-Session-Id": s1_session,
                "X-Device-Id": device_id,
            },
            expect_next_action_in={"allow", "reauth_biometric"},
            expect_deception=False,
        )
    )

    # 2) Biometric: new device should add risk (anomaly_new_device in risk_engine)
    s2_session = str(uuid.uuid4())
    scenarios.append(
        Scenario(
            name="BIOMETRIC_new_device_medium_export",
            target_path="/export/medium.csv",
            headers={
                "X-User-Id": user_id,
                "X-Session-Id": s2_session,
                "X-Device-Id": "laptop-2",  # new device fingerprint
            },
            expect_next_action_in={"reauth_biometric", "allow"},  # allow if your thresholds are still mild
            expect_deception=False,
        )
    )

    # 3) Deception: huge export + new device + new session should cross honeypot (>=80)
    s3_session = str(uuid.uuid4())
    scenarios.append(
        Scenario(
            name="DECEPTION_huge_export_new_device_new_session",
            target_path="/export/huge.csv",
            headers={
                "X-User-Id": user_id,
                "X-Session-Id": s3_session,
                "X-Device-Id": "laptop-3",
            },
            expect_next_action_in={"deception", "reauth_biometric", "allow"},  # depends on current scoring
            expect_deception=None,  # we'll print & you can confirm
        )
    )

    # 4) Identity incomplete: missing anchors should push tone_risk high in proxy
    # This often forces reauth/deception depending on your policy + deception engine.
    s4_session = str(uuid.uuid4())
    scenarios.append(
        Scenario(
            name="SUSPICIOUS_missing_identity_anchors",
            target_path="/export/medium.csv",
            headers={
                # intentionally missing X-User-Id / X-Device-Id / X-Session-Id
                "X-Session-Id": s4_session,
            },
            expect_next_action_in={"reauth_biometric", "deception"},
            expect_deception=None,
        )
    )

    async with httpx.AsyncClient(timeout=20) as client:
        print("\n=== Sidecar Adversary Harness ===")
        print(f"Sidecar:  {sidecar}")
        print(f"Upstream: {upstream_base}\n")

        for sc in scenarios:
            target_url = upstream_base + sc.target_path
            # session id is needed for timeline lookup; ensure it exists
            sess = sc.headers.get("X-Session-Id") or "unknown-session"

            print(f"\n--- Scenario: {sc.name} ---")
            print(f"Target: {target_url}")
            print(f"Headers: {json.dumps(sc.headers, indent=2)}")

            out = await call_sidecar_proxy(client, sidecar, target_url, sc.headers)

            # =========================
            # PRE-FLIGHT RESOLUTION LOOP
            # =========================
            MAX_STEPS = 5
            step = 0

            cur = out
            headers = dict(sc.headers)

            while step < MAX_STEPS:
                step += 1
                action = cur.get("next_action")

                # Done: allowed through (or deception/deny handling later)
                if action == "allow":
                    break

                # 1) Tone handshake requested
                if action == "retry_with_tone":
                    tone = cur.get("tone")
                    if not tone:
                        raise RuntimeError("Sidecar asked retry_with_tone but returned no tone")
                    headers["X-Tone"] = tone
                    cur = await call_sidecar_proxy(client, sidecar, target_url, headers)
                    continue

                # 2) Reauth requested
                if action == "reauth_biometric":
                    # Simulate the user completing biometric/passkey successfully.
                    # IMPORTANT: if anchors were missing, a real client would now re-send WITH anchors.
                    headers = dict(headers)
                    headers["X-Reauth-Result"] = "ok"

                    # If missing anchors, add them now (this is what resolves the loop)
                    if "X-User-Id" not in headers:
                        headers["X-User-Id"] = "josh"
                    if "X-Device-Id" not in headers:
                        headers["X-Device-Id"] = "laptop-reauth"

                    cur = await call_sidecar_proxy(client, sidecar, target_url, headers)
                    out = cur
                    continue

                # Unknown action → stop
                break

            # Replace `out` with the final resolved output for the rest of the scenario prints/asserts
            out = cur

            has_anchors = bool(headers.get("X-User-Id") and headers.get("X-Device-Id") and headers.get("X-Session-Id"))

            if not has_anchors and out.get("next_action") == "reauth_biometric":
                # Expected terminal state for the suspicious/missing-anchors scenario
                pass
            else:
                if out.get("next_action") in ("reauth_biometric", "retry_with_tone"):
                    # If anchors are missing, it is EXPECTED to remain at reauth_biometric.
                    # We can't “resolve” without the client providing X-User-Id and X-Device-Id.
                    anchors_missing = ("X-User-Id" not in headers) or ("X-Device-Id" not in headers)
                    if out.get("next_action") == "reauth_biometric" and anchors_missing:
                        # Accept as terminal for this scenario
                        pass
                    else:
                        raise AssertionError(
                            f"Preflight did not resolve in {MAX_STEPS} steps, last action={out.get('next_action')}"
                        )


            if out.get("next_action") == "retry_with_tone":
                tone = out.get("tone")
                if not tone:
                    raise RuntimeError("Sidecar asked retry_with_tone but returned no tone")
                sc.headers["X-Tone"] = tone
                out = await call_sidecar_proxy(client, sidecar, target_url, sc.headers)

            print("Proxy envelope keys:", sorted(out.keys()))
            print("risk_score:", out.get("risk_score"), "risk_level:", out.get("risk_level"))
            print("deception_used:", out.get("deception_used"), "reason:", out.get("deception_reason"))
            print("next_action:", out.get("next_action"))
            print("behavior_score:", out.get("behavior_score"), "behavior_level:", out.get("behavior_level"))

            # Assertions (soft but useful)
            next_action = out.get("next_action")
            assert_condition(
                next_action in sc.expect_next_action_in,
                f"Expected next_action in {sc.expect_next_action_in} but got {next_action}",
            )
            if sc.expect_deception is not None:
                assert_condition(
                    bool(out.get("deception_used")) == sc.expect_deception,
                    f"Expected deception_used={sc.expect_deception} but got {out.get('deception_used')}",
                )

            # Timeline
            try:
                tl = await fetch_timeline(client, sidecar, sess)
                events = tl.get("events", [])
                exports = tl.get("exports", [])
                print(f"Timeline: events={len(events)} exports={len(exports)}")
                # sanity: you should see export_started and export_completed in events
                types = {e.get("type") for e in events}
                print("Event types:", sorted(list(types))[:12])
            except Exception as e:
                print(f"(timeline fetch failed for session {sess}): {e}")

        print("\n✅ Harness finished.\n")


if __name__ == "__main__":
    import asyncio
    asyncio.run(run())
