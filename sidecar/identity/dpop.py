import base64
import hashlib
import time
from typing import Optional, Dict, Any

import jwt  # PyJWT

def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")

def sha256_b64url(s: str) -> str:
    return b64url(hashlib.sha256(s.encode("utf-8")).digest())

def canonical_htu(htu: str) -> str:
    # Keep it simple: scheme://host/path (NO query)
    # You can tighten later if you want query binding too.
    from urllib.parse import urlsplit, urlunsplit
    u = urlsplit(htu)
    return urlunsplit((u.scheme, u.netloc, u.path, "", ""))

async def verify_dpop(
    *,
    dpop_jwt: str,
    http_method: str,
    http_url: str,
    tone: Optional[str],
    redis_client=None,
    iat_skew_sec: int = 120,
    require_tone_binding: bool = True,
) -> Dict[str, Any]:
    """
    Verifies a DPoP proof JWT.
    - Signature must verify against embedded 'jwk' in header.
    - htm/htu/iat/jti must be valid.
    - Optional: bind proof to tone via claim 'th' = b64url(sha256(tone)).
    - Optional: replay protection via Redis key on jti.
    """
    if not dpop_jwt:
        raise ValueError("dpop_missing")

    # 1) read header to get jwk
    header = jwt.get_unverified_header(dpop_jwt)
    jwk = header.get("jwk")
    alg = header.get("alg")

    if not jwk or not alg:
        raise ValueError("dpop_header_invalid")

    # 2) verify signature
    # PyJWT can accept jwk dict directly as key for EC/RSA depending on alg
    try:
        payload = jwt.decode(
            dpop_jwt,
            key=jwk,
            algorithms=[alg],
            options={"verify_aud": False},
        )
    except Exception as e:
        raise ValueError("dpop_sig_invalid") from e

    # 3) method/url binding
    htm = payload.get("htm")
    htu = payload.get("htu")
    iat = payload.get("iat")
    jti = payload.get("jti")

    if not htm or not htu or not iat or not jti:
        raise ValueError("dpop_claims_missing")

    if htm.upper() != http_method.upper():
        raise ValueError("dpop_htm_mismatch")

    if canonical_htu(htu) != canonical_htu(http_url):
        raise ValueError("dpop_htu_mismatch")

    now = int(time.time())
    if abs(now - int(iat)) > iat_skew_sec:
        raise ValueError("dpop_iat_out_of_range")

    # 4) bind to tone (prevents “steal tone, sign with your own key”)
    if require_tone_binding:
        if not tone:
            raise ValueError("dpop_tone_missing")
        th = payload.get("th")
        if not th or th != sha256_b64url(tone):
            raise ValueError("dpop_tone_mismatch")

    # 5) replay protection (jti must be one-time)
    if redis_client:
        key = f"dpop:jti:{jti}"
        if await redis_client.get(key):
            raise ValueError("dpop_replay")
        # TTL roughly equals skew window
        await redis_client.setex(key, iat_skew_sec, "1")

    return payload
