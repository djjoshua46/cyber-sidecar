# sidecar/tone_crypto.py
import os, hmac, hashlib, secrets
from typing import Tuple

_TONE_SECRET = os.getenv("SIDECAR_TONE_SECRET", "")
if not _TONE_SECRET:
    raise RuntimeError("SIDECAR_TONE_SECRET must be set")

def new_raw_tone() -> str:
    # ~256 bits randomness
    return secrets.token_urlsafe(32)

def tone_hmac(raw: str) -> str:
    key = _TONE_SECRET.encode("utf-8")
    msg = raw.encode("utf-8")
    return hmac.new(key, msg, hashlib.sha256).hexdigest()
