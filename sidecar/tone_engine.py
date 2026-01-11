from __future__ import annotations

import hmac, hashlib, os, time, secrets, random, json
import logging
from datetime import datetime, timedelta
from typing import Optional, Tuple, Any, Dict

from sqlalchemy.orm import Session

from .models import EphemeralSessionKey
from .tone_crypto import new_raw_tone, tone_hmac

TONE_LIFETIME_SECONDS_MAX = 30  # hard max (seconds)
TONE_LIFETIME_SECONDS_MIN = 10  # random floor (seconds)
HASH_ALGO = "sha256"
TONE_ROTATE_MIN = 10
TONE_ROTATE_MAX = 30
TONE_REDIS_TTL = 120  # seconds (active + overlap)
TONE_SECRET = os.environ.get("SIDECAR_TONE_SECRET", "dev-secret-change-me")
OVERLAP_SECONDS = 5
logger = logging.getLogger("sidecar")

def _get_secret() -> bytes:
    raw = os.getenv("SIDECAR_TONE_SECRET", "CHANGE_ME_DEV_TONE_SECRET")
    return raw.encode("utf-8")

def _generate_raw_tone(*, user_id: str, device_id: str, session_id: str, tenant_id: str) -> str:
    ts = int(time.time())
    payload = f"{tenant_id}:{user_id}:{device_id}:{session_id}:{ts}".encode("utf-8")
    return hmac.new(_get_secret(), payload, hashlib.sha256).hexdigest()

def _hash_tone(raw_tone: str) -> str:
    # store/compare hashes only
    return hashlib.sha256(raw_tone.encode("utf-8")).hexdigest()

def _tone_hmac(tone: str) -> str:
    return hmac.new(
        TONE_SECRET.encode(),
        tone.encode(),
        hashlib.sha256
    ).hexdigest()


def _tone_key(tenant_id: str, user_id: str, device_id: str) -> str:
    return f"tone:{tenant_id}:{user_id}:{device_id}"

# async def get_or_rotate_tone(
#     redis_client,
#     tenant_id: str,
#     user_id: str,
#     device_id: str,
# ):
#     key = _tone_key(tenant_id, user_id, device_id)
#     now = time.time()

#     raw_state = await redis_client.get(key)
#     state = json.loads(raw_state) if raw_state else None

#     # If still active, we DO NOT return anything new.
#     if state and now < float(state.get("active_exp", 0)):
#         return None  # means "keep using what you have"

#     # rotate (random 10–30s)
#     new_tone = secrets.token_urlsafe(32)
#     new_hash = _tone_hmac(new_tone)
#     rotate_for = random.randint(TONE_ROTATE_MIN, TONE_ROTATE_MAX)

#     prev_h = state.get("active_h") if state else None
#     prev_exp = float(state.get("active_exp", 0)) + OVERLAP_SECONDS if state else None

#     payload = {
#         "active_h": new_hash,
#         "active_exp": now + rotate_for,
#         "prev_h": prev_h,
#         "prev_exp": prev_exp,
#     }

#     # keep key alive through active window + overlap
#     ttl = rotate_for + OVERLAP_SECONDS
#     await redis_client.setex(key, ttl, json.dumps(payload))

#     return new_tone  # raw tone is ONLY returned to caller


def issue_tone(db, *, tenant_id: str, session_id: str, user_id: str, device_id: str):
    raw = new_raw_tone()
    tone_hash = _hash_tone(raw)

    lifetime = random.randint(TONE_LIFETIME_SECONDS_MIN, TONE_LIFETIME_SECONDS_MAX)
    expires_at = datetime.utcnow() + timedelta(seconds=lifetime)

    row = EphemeralSessionKey(
        tenant_id=tenant_id,
        session_id=session_id,
        user_id=user_id,
        device_id=device_id,
        user_tone=tone_hash,
        combined_tone=tone_hash,
        scope="session",              # <— now valid because model has `scope`
        expires_at=expires_at,
    )
    db.add(row)
    db.flush()
    db.commit()

    return {"tone": raw, "expires_at": expires_at}


async def validate_tone(
    redis_client,
    tenant_id: str,
    user_id: str,
    device_id: str,
    presented_tone: str,
) -> bool:
    key = _tone_key(tenant_id, user_id, device_id)
    raw = await redis_client.get(key)
    if not raw:
        return False

    data = json.loads(raw)
    now = time.time()
    presented_h = _tone_hmac(presented_tone)

    if presented_h == data.get("active_h") and now <= data.get("active_exp"):
        return True

    if (
        data.get("prev_h")
        and presented_h == data["prev_h"]
        and now <= data["prev_exp"]
    ):
        return True

    return False


def validate_tone_db(
    db: Session,
    *,
    tenant_id: str,
    session_id: str,
    user_id: str,
    device_id: str,
    provided_tone: str,
) -> tuple[bool, str]:
    now = datetime.utcnow()
    provided_h = _hash_tone(provided_tone)

    row = (
        db.query(EphemeralSessionKey)
        .filter(
            EphemeralSessionKey.tenant_id == tenant_id,
            EphemeralSessionKey.session_id == session_id,
            EphemeralSessionKey.user_id == user_id,
            EphemeralSessionKey.device_id == device_id,
        )
        .order_by(EphemeralSessionKey.inserted_at.desc())
        .first()
    )

    if not row:
        return False, "tone_unknown_session"
    if row.expires_at < now:
        return False, "tone_expired"
    if row.user_tone != provided_h:
        return False, "tone_mismatch"

    return True, "ok"


def log_tone_rotation_sql(
    db: Session,
    *,
    tenant_id: str,
    session_id: str,
    user_id: str,
    device_id: str,
    raw_tone: str,
    expires_at: datetime,
):
    tone_hash = _hash_tone(raw_tone)
    row = EphemeralSessionKey(
        tenant_id=tenant_id,
        session_id=session_id,
        user_id=user_id,
        device_id=device_id,
        user_tone=tone_hash,
        combined_tone=tone_hash,
        scope="session",
        expires_at=expires_at,
    )
    db.add(row)
    db.commit()

def compute_tone_risk(is_valid: bool, reason: str) -> float:
    """
    Turn tone validation results into a risk contribution (0–100).
    This gets added on top of your export risk.
    """
    if is_valid:
        return 0.0

    if reason in ("tone_missing", "tone_unknown_session"):
        return 40.0

    if reason == "tone_expired":
        return 50.0

    if reason == "tone_mismatch":
        return 80.0

    return 30.0

# Back-compat alias: some modules still import validate_ephemeral_tone
async def validate_ephemeral_tone(
    redis_client,
    db,
    tenant_id: str,
    session_id: str,
    user_id: str,
    device_id: str,
    provided_tone: str,
):
    # 1) Redis fast-path (best effort)
    if redis_client:
        try:
            ok = await validate_tone(
                redis_client,
                tenant_id=tenant_id,
                user_id=user_id,
                device_id=device_id,
                presented_tone=provided_tone,
            )
            if ok:
                return True, "redis_ok"
        except Exception as e:
            # Redis down shouldn't hard-fail auth flow
            logger.warning(f"Redis validate_tone failed: {e}")

    # 2) DB source of truth fallback
    ok, reason = validate_tone_db(
        db,
        tenant_id=tenant_id,
        session_id=session_id,
        user_id=user_id,
        device_id=device_id,
        provided_tone=provided_tone,
    )
    return ok, f"db_{reason}"


async def issue_tone_redis(redis_client, *, tenant_id: str, session_id: str, user_id: str, device_id: str,
                          min_sec: int = 10, max_sec: int = 30) -> Dict[str, Any]:
    key = f"tone:{tenant_id}:{session_id}:{user_id}:{device_id}"

    now = int(time.time())
    ttl = random.randint(min_sec, max_sec)
    exp = now + ttl

    raw = new_raw_tone()
    active_h = tone_hmac(raw)

    # load previous state if present
    prev_h = None
    prev_exp = None
    raw_state = await redis_client.get(key)
    if raw_state:
        state = json.loads(raw_state)
        # shift current active -> prev
        prev_h = state.get("active_h")
        prev_exp = now + OVERLAP_SECONDS

    state = {
        "active_h": active_h,
        "active_exp": exp,
        "prev_h": prev_h,
        "prev_exp": prev_exp,
    }

    # TTL on key should last through active window (+ small overlap)
    await redis_client.setex(key, ttl + OVERLAP_SECONDS, json.dumps(state))

    return {
        "tone": raw,
        "expires_at": datetime.utcnow() + timedelta(seconds=ttl),
        "ttl_seconds": ttl,
    }

async def validate_tone_redis(redis_client, *, tenant_id: str, session_id: str, user_id: str, device_id: str,
                             presented_tone: str) -> bool:
    key = f"tone:{tenant_id}:{session_id}:{user_id}:{device_id}"
    raw_state = await redis_client.get(key)
    if not raw_state:
        return False

    state = json.loads(raw_state)
    now = int(time.time())
    h = tone_hmac(presented_tone)

    if h == state.get("active_h") and now <= int(state.get("active_exp", 0)):
        return True

    if state.get("prev_h") and h == state["prev_h"] and now <= int(state.get("prev_exp", 0)):
        return True

    return False