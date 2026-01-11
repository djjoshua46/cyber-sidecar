import base64
import hashlib
import json
import os
import time
from typing import Any, Dict, Optional, Sequence
from urllib.request import Request, urlopen

import jwt


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def sha256_b64url(s: str) -> str:
    return _b64url(hashlib.sha256(s.encode("utf-8")).digest())


def _now() -> int:
    return int(time.time())


def _load_static_jwks() -> Optional[Dict[str, Any]]:
    """
    Load JWKS from a mounted file (customer-provided).
    e.g. /etc/sidecar/reauth_jwks.json
    """
    path = os.getenv("SIDECAR_REAUTH_JWKS_FILE", "").strip()
    if not path:
        return None
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


def _fetch_jwks_url() -> Optional[Dict[str, Any]]:
    """
    Fetch JWKS from URL (customer IdP).
    """
    url = os.getenv("SIDECAR_REAUTH_JWKS_URL", "").strip()
    if not url:
        return None
    try:
        req = Request(url, headers={"Accept": "application/json"})
        with urlopen(req, timeout=2.5) as resp:
            raw = resp.read().decode("utf-8", errors="replace")
            return json.loads(raw)
    except Exception:
        return None


def _select_jwk(jwks: Dict[str, Any], kid: Optional[str]) -> Optional[Dict[str, Any]]:
    keys = (jwks or {}).get("keys") or []
    if not keys:
        return None
    if kid:
        for k in keys:
            if k.get("kid") == kid:
                return k
    # fallback: first key
    return keys[0]


async def verify_reauth_proof(
    *,
    jwt_proof: str,
    tenant_id: str,
    user_id: str,
    session_id: str,
    device_id: str,
    tone: Optional[str],
    method: str,
    target_url: str,
    redis_client=None,
    max_age_sec: int = 180,
    fail_mode: str = "closed",   # "open" or "closed"
) -> Dict[str, Any]:
    """
    Verify a signed reauth proof JWT that asserts step-up was completed.

    Required claims:
      - tenant_id, user_id, session_id, device_id
      - result == "ok"
      - iat, exp, jti
      - th == sha256_b64url(tone)   (tone binding)

    Optional:
      - reqh == sha256_b64url(f"{method}|{target_url}")  (request binding)

    Replay protection:
      - jti must be unseen (Redis)
    """
    if not jwt_proof:
        raise ValueError("reauth_proof_missing")

    if fail_mode not in ("open", "closed"):
        fail_mode = "closed"

    # 1) header (kid/alg)
    try:
        header = jwt.get_unverified_header(jwt_proof)
    except Exception as e:
        raise ValueError("reauth_proof_header_invalid") from e

    kid = header.get("kid")
    alg = header.get("alg")
    if not alg:
        raise ValueError("reauth_proof_alg_missing")

    # 2) load key set (static preferred, else JWKS URL)
    jwks = _load_static_jwks() or _fetch_jwks_url()
    if not jwks:
        # Key discovery failed
        if fail_mode == "open":
            raise ValueError("reauth_proof_key_unavailable_open")
        raise ValueError("reauth_proof_key_unavailable_closed")

    jwk = _select_jwk(jwks, kid)
    if not jwk:
        raise ValueError("reauth_proof_kid_not_found")

    # 3) verify signature
    try:
        payload = jwt.decode(
            jwt_proof,
            key=jwk,
            algorithms=[alg],
            options={"verify_aud": False},
        )
    except Exception as e:
        raise ValueError("reauth_proof_sig_invalid") from e

    # 4) validate claims
    req_tenant = str(payload.get("tenant_id", ""))
    req_user = str(payload.get("user_id", ""))
    req_session = str(payload.get("session_id", ""))
    req_device = str(payload.get("device_id", ""))
    result = str(payload.get("result", ""))
    iat = payload.get("iat")
    exp = payload.get("exp")
    jti = str(payload.get("jti", ""))

    if not all([req_tenant, req_user, req_session, req_device, result, iat, exp, jti]):
        raise ValueError("reauth_proof_claims_missing")

    if req_tenant != str(tenant_id):
        raise ValueError("reauth_proof_tenant_mismatch")
    if req_user != str(user_id):
        raise ValueError("reauth_proof_user_mismatch")
    if req_session != str(session_id):
        raise ValueError("reauth_proof_session_mismatch")
    if req_device != str(device_id):
        raise ValueError("reauth_proof_device_mismatch")

    if result.lower() not in ("ok", "pass", "true", "1"):
        raise ValueError("reauth_proof_result_not_ok")

    now = _now()
    if now - int(iat) > max_age_sec:
        raise ValueError("reauth_proof_too_old")
    if int(exp) < now:
        raise ValueError("reauth_proof_expired")

    # tone binding
    if not tone:
        raise ValueError("reauth_proof_tone_missing")
    th = str(payload.get("th", ""))
    if not th or th != sha256_b64url(tone):
        raise ValueError("reauth_proof_tone_mismatch")

    # optional request binding
    reqh = payload.get("reqh")
    if reqh:
        expected = sha256_b64url(f"{method.upper()}|{target_url}")
        if str(reqh) != expected:
            raise ValueError("reauth_proof_req_mismatch")

    # 5) replay protection
    if redis_client:
        key = f"reauth:jti:{jti}"
        try:
            if await redis_client.get(key):
                raise ValueError("reauth_proof_replay")
            ttl = max(1, min(max_age_sec, int(exp) - now))
            await redis_client.setex(key, ttl, "1")
        except Exception:
            # Redis unavailable
            if fail_mode == "closed":
                raise ValueError("reauth_replay_cache_unavailable_closed")
            # open mode: allow but mark in caller via reason code
            # we signal by raising a distinct code
            raise ValueError("reauth_replay_cache_unavailable_open")

    return payload
