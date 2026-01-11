import time
from typing import Dict
import jwt

from ..config import settings

def issue_access_token(sub: str, claims: Dict) -> str:
    now = int(time.time())
    payload = {
        "sub": sub,
        "iat": now,
        "exp": now + settings.ACCESS_TOKEN_TTL_SECONDS,
        **claims
    }
    return jwt.encode(payload, settings.JWT_SECRET, algorithm=settings.JWT_ALG)

def verify_access_token(token: str) -> Dict:
    return jwt.decode(token, settings.JWT_SECRET, algorithms=[settings.JWT_ALG])
