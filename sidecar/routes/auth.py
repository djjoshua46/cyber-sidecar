# sidecar/routes/auth.py
from __future__ import annotations

import base64
import os
from typing import Any, Dict

from fastapi import APIRouter, HTTPException, Request, Header
from starlette.responses import JSONResponse
from ..tone_engine import issue_tone_redis

router = APIRouter(prefix="/auth", tags=["auth"])

# In-memory store for dev only (restarts wipe it).
# Replace with DB or Redis keyed by session/user/device in production.
_CHALLENGES: dict[str, bytes] = {}


def _b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("utf-8")


def _b64url_to_bytes(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode((s + pad).encode("utf-8"))


@router.post("/webauthn/challenge")
async def create_challenge(payload: Dict[str, Any]):
    """
    Client sends at least:
      { "session_id": "...", "user_id": "...", "device_id": "..." }

    We return:
      { "challenge": "<base64url>" }

    NOTE: This is a minimal dev stub. Real WebAuthn uses rpId, allowCredentials,
    user verification, etc. The important part is: server issues challenge and stores it.
    """
    session_id = str(payload.get("session_id") or "")
    if not session_id:
        raise HTTPException(status_code=400, detail="session_id is required")

    challenge = os.urandom(32)
    _CHALLENGES[session_id] = challenge
    return {"challenge": _b64url(challenge)}


@router.post("/webauthn/verify")
async def verify_webauthn(payload: Dict[str, Any]):
    """
    Minimal dev stub:
    Client sends:
      {
        "session_id": "...",
        "challenge": "<base64url>",
        "assertion": { ... }   # optional for now
      }

    We validate the challenge matches what we issued.
    Real WebAuthn verification must validate:
      - origin / rpId
      - authenticator data
      - signature against public key
      - signCount, user verification, etc.
    """
    session_id = str(payload.get("session_id") or "")
    if not session_id:
        raise HTTPException(status_code=400, detail="session_id is required")

    expected = _CHALLENGES.get(session_id)
    if not expected:
        raise HTTPException(status_code=400, detail="No outstanding challenge for session")

    provided_challenge = payload.get("challenge")
    if not isinstance(provided_challenge, str) or not provided_challenge:
        raise HTTPException(status_code=400, detail="challenge is required")

    try:
        provided_bytes = _b64url_to_bytes(provided_challenge)
    except Exception:
        raise HTTPException(status_code=400, detail="challenge is not valid base64url")

    if provided_bytes != expected:
        raise HTTPException(status_code=403, detail="Challenge mismatch")

    # one-time use
    _CHALLENGES.pop(session_id, None)

    return {"status": "ok", "message": "WebAuthn challenge verified (dev stub)"}

@router.post("/tone/refresh")
async def tone_refresh(
    request: Request,
    x_user_id: str = Header(..., alias="X-User-Id"),
    x_device_id: str = Header(..., alias="X-Device-Id"),
    x_org_id: str = Header(..., alias="X-Org-Id"),
    x_session_id: str = Header(..., alias="X-Session-Id"),
):
    redis_client = getattr(request.app.state, "redis", None)
    if not redis_client:
        return JSONResponse(status_code=500, content={"error": "redis_required"})

    issued = await issue_tone_redis(
        redis_client,
        tenant_id=x_org_id,
        user_id=x_user_id,
        device_id=x_device_id,
        session_id=x_session_id,
        min_sec=10,
        max_sec=30,
    )
    return JSONResponse(status_code=200, content={
        "tone": issued["tone"],
        "expires_at": issued["expires_at"].isoformat(),
        "ttl_seconds": issued["ttl_seconds"],
    })