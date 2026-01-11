from __future__ import annotations
import hashlib, logging
from dataclasses import dataclass, field

from fastapi import Depends, Request, HTTPException, status
from collections.abc import Generator
from sqlalchemy.orm import Session

from .db import SessionLocal, get_db
from .geoip import lookup_ip
from .tone_engine import validate_tone, compute_tone_risk, validate_ephemeral_tone
from .models import Event

from typing import Optional

logger = logging.getLogger("sidecar.security")

def parse_int_header(value: Optional[str]) -> Optional[int]:
    """
    Safely parse an int from a header value, or return None if missing/invalid.
    """
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None
    

@dataclass
class RequestContext:
    # Identity
    user_id: Optional[str] = None
    session_id: Optional[str] = None
    device_id: Optional[str] = None

    # Tone / behavioral
    tone_hash: Optional[str] = None
    tone_label: Optional[str] = None

    # Network
    client_ip: Optional[str] = None          # direct client IP
    origin_ip: Optional[str] = None          # first X-Forwarded-For or client_ip
    forwarded_for: Optional[str] = None      # raw X-Forwarded-For header

    # Geo (legacy + structured)
    country: Optional[str] = None
    region: Optional[str] = None
    city: Optional[str] = None

    geo_country: Optional[str] = None
    geo_region: Optional[str] = None
    geo_city: Optional[str] = None

    # ASN info (for later if you add GeoLite2-ASN)
    asn: Optional[int] = None
    as_org: Optional[str] = None

    # HTTP basics
    url: Optional[str] = None
    method: Optional[str] = None
    path: Optional[str] = None
    user_agent: Optional[str] = None

    # Fingerprints
    user_agent_hash: Optional[str] = None
    header_fingerprint: Optional[str] = None
    client_fingerprint: Optional[str] = None

    # Risk / drift / deception
    risk_score: Optional[float] = None
    risk_level: Optional[str] = None
    drift_score: Optional[float] = None
    deception_used: Optional[bool] = None
    deception_reason: Optional[str] = None
    next_action: Optional[str] = None

    # Policy decisions
    require_biometric: bool = False
    route_to_honey: bool = False

    # Tone / handshake
    tone: Optional[str] = None         # baseline tone from client
    tone2: Optional[str] = None        # optional second tone for sensitive data
    tone_ok: bool = False              # did we get a valid baseline tone?
    dual_tone_ok: bool = False         # did we get both tones?
    tone_reason: Optional[str] = None
    tone_risk: Optional[float] = None


def get_db() -> Generator[Session, None, None]:
    """
    FastAPI dependency that yields a SQLAlchemy Session and
    always closes it afterwards.
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def record_security_event(
    ctx: RequestContext,
    event_type: str,
    outcome: str,
    details: Optional[dict] = None,
) -> None:
    """
    Persist a security-relevant event to the Event table.
    Treats *every* failure as hostile until disproven, and captures as much
    context as possible for forensic work.
    """
    db = SessionLocal()
    try:
        payload = {
            "method": ctx.method,
            "path": ctx.path,
            "tone": ctx.tone,
            "tone_hash": ctx.tone_hash,
            "tone_label": ctx.tone_label,
            "tone_ok": ctx.tone_ok,
            "client_ip": ctx.client_ip,
            "origin_ip": ctx.origin_ip,
            "forwarded_for": ctx.forwarded_for,
            "user_agent": ctx.user_agent,
            "ua_hash": ctx.ua_hash,
            "headers": ctx.headers,   # beware of PII, but for now this is useful
        }

        if details:
            payload.update(details)

        event = Event(
            tenant_id=ctx.tenant_id,
            user_id=ctx.user_id,
            device_id=ctx.device_id,
            session_id=ctx.session_id,
            source="security",
            event_type=event_type,      # e.g. "tone_missing", "tone_mismatch", "tone_ok"
            resource=ctx.path,
            ip=ctx.client_ip,
            geo=None,                   # fill later when you add GeoIP
            details=payload,
        )

        db.add(event)
        db.commit()
    except Exception:
        logger.exception("Failed to record security event")
    finally:
        db.close()


def get_request_context(request: Request) -> RequestContext:
    """
    Build a rich RequestContext from incoming HTTP headers.

    This is the single place we:
      - read x-user-id / x-session-id / x-device-id
      - parse tone, risk, drift, deception, etc
      - resolve origin_ip and forwarded_for
      - hash/fingerprint headers and user agent
      - run geo + drift/deception + policy engines
    """
    h = request.headers

    # 1) Basic IDs + tone
    user_id = h.get("x-user-id")
    session_id = h.get("x-session-id")
    device_id = h.get("x-device-id")

    # risk gateway is sending us a tone hash
    tone_hash = h.get("x-tone") or h.get("x-tone-hash")
    tone_label = h.get("x-tone-label")

    # 2) IPs + User-Agent
    client_ip = request.client.host if request.client else None
    forwarded_for_raw = h.get("x-forwarded-for")
    origin_ip = (forwarded_for_raw.split(",")[0].strip()
                 if forwarded_for_raw else client_ip)
    user_agent = h.get("user-agent")

    # 3) Geo from headers (if an upstream edge already did GeoIP)
    geo_country = h.get("x-geo-country")
    geo_region = h.get("x-geo-region")
    geo_city = h.get("x-geo-city")

    # 4) Risk fields from headers
    def _safe_float(v: Optional[str]) -> Optional[float]:
        try:
            return float(v) if v is not None else None
        except ValueError:
            return None

    risk_score = _safe_float(h.get("x-risk-score"))
    drift_score = _safe_float(h.get("x-drift-score"))
    risk_level = h.get("x-risk-level")

    deception_used_header = h.get("x-deception-used")
    deception_reason = h.get("x-deception-reason")
    next_action = h.get("x-next-action")

    deception_used: Optional[bool] = None
    if deception_used_header is not None:
        deception_used = deception_used_header.lower() in ("1", "true", "yes")

    # 5) Fingerprints (user agent + headers + identity)
    # user agent hash
    if user_agent:
        ua_hash = hashlib.sha256(user_agent.encode("utf-8")).hexdigest()
    else:
        ua_hash = None

    # header fingerprint: sorted header names + values (minus obvious secrets)
    # This is intentionally simple for now.
    header_items = []
    for k, v in h.items():
        lk = k.lower()
        if lk in ("authorization", "cookie", "set-cookie"):
            continue
        header_items.append(f"{lk}:{v}")
    header_items.sort()
    header_str = "|".join(header_items)
    header_fp = hashlib.sha256(header_str.encode("utf-8")).hexdigest() if header_items else None

    # client fingerprint: "who is this thing" across sessions
    fp_parts = [
        user_id or "",
        device_id or "",
        origin_ip or "",
        user_agent or "",
    ]
    client_fp_str = "|".join(fp_parts)
    client_fp = hashlib.sha256(client_fp_str.encode("utf-8")).hexdigest() if client_fp_str.strip() else None

    tone = request.headers.get("x-tone")
    tone2 = request.headers.get("x-tone-2")

    # TODO: once you have real tone validation, call that here.
    tone_ok = tone is not None and tone.strip() != ""
    dual_tone_ok = tone_ok and tone2 is not None and tone2.strip() != ""

    # Device metadata
    device_display_name: Optional[str] = None

    # Risk / investigation
    risk_score: Optional[float] = None
    risk_flags: list[str] = []

    # Behavior / human-profile hooks (reserved for later)
    mouse_profile: Optional[dict] = None  # e.g. {"avg_speed": ..., "jitter": ...}
    key_profile: Optional[dict] = None    # e.g. {"avg_latency": ...}

    # 6) Build the ctx
    ctx = RequestContext(
        user_id=user_id,
        session_id=session_id,
        device_id=device_id,

        # ✅ keep tone_hash separate
        tone_hash=tone_hash,
        tone_label=tone_label,

        client_ip=client_ip,
        origin_ip=origin_ip,
        forwarded_for=forwarded_for_raw,

        country=geo_country,
        region=geo_region,
        city=geo_city,

        geo_country=geo_country,
        geo_region=geo_region,
        geo_city=geo_city,

        url=str(request.url),
        method=request.method,
        path=request.url.path,
        user_agent=user_agent,

        user_agent_hash=ua_hash,
        header_fingerprint=header_fp,
        client_fingerprint=client_fp,

        risk_score=risk_score,
        risk_level=risk_level,
        drift_score=drift_score,
        deception_used=deception_used,
        deception_reason=deception_reason,
        next_action=next_action,

        # ✅ THIS is the only tone=
        tone=tone,
        tone2=tone2,
        tone_ok=tone_ok,
        dual_tone_ok=dual_tone_ok,
    )

    # 7) Enrich with our engines
    geoip_enrich(ctx)
    drift_and_deception_enrich(ctx)
    policy_enforce(ctx)

    return ctx


def geoip_enrich(ctx: RequestContext) -> None:
    """
    Geo-IP engine: if geo_* not already set, fill them from ctx.origin_ip.
    """
    if ctx.geo_country or ctx.geo_region or ctx.geo_city:
        # Caller already provided geo; don't override.
        return

    if not ctx.origin_ip:
        return

    info = lookup_ip(ctx.origin_ip)
    ctx.geo_country = info.get("country")
    ctx.geo_region = info.get("region")
    ctx.geo_city = info.get("city")



def drift_and_deception_enrich(ctx: RequestContext) -> None:
    """
    Drift / deception engine stub.

    Here you look at historical behavior for user/session/device + geo
    and decide if this session is doing weird things.
    """
    # TODO: plug in real logic.
    # For now, if risk_score is high, mark as deceptive.
    if ctx.risk_score is not None and ctx.risk_score >= 70:
        ctx.deception_used = True
        ctx.deception_reason = "High risk score from risk engine"
        ctx.drift_score = (ctx.drift_score or 0.0) + 10.0


def policy_enforce(ctx: RequestContext) -> None:
    """
    Decide conditional biometrics + honey routing based on risk / deception.
    """
    # 1) Biometrics if risk or engine explicitly demands it
    if ctx.risk_level == "high" or ctx.next_action == "reauth_biometric":
        ctx.require_biometric = True

    # 2) Honey if very high risk or deception flagged
    if (ctx.risk_score is not None and ctx.risk_score >= 80) or ctx.deception_used:
        ctx.route_to_honey = True

# ---------------------------------------------------------------------------
# 🔐 Phase 1: Basic device + tone gate
# ---------------------------------------------------------------------------

def require_device_and_tone(
    ctx: RequestContext = Depends(get_request_context),
    db: Session = Depends(get_db),
) -> RequestContext:
    # Must be known device
    if not ctx.device_id:
        record_security_event(
            db=db,
            ctx=ctx,
            event_type="missing_device_id",
            severity="high",
            details={"reason": "Protected endpoint called without device id"},
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing or unknown device id",
        )

    # Evaluate tone risk and flags
    ctx = evaluate_tone_risk(ctx, db)

    # If tone is missing:
    if not ctx.tone_ok:
        # Phase 1 behavior: log + block.
        # Phase 2: you could use ctx.risk_score to decide between
        # "allow once but flag" vs "honeypot + block".
        record_security_event(
            db=db,
            ctx=ctx,
            event_type="missing_tone",
            severity="high",
            details={
                "reason": "Baseline tone missing on protected endpoint",
            },
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Baseline tone required",
        )

    # Tone is present – treat as successful gate
    record_security_event(
        db=db,
        ctx=ctx,
        event_type="tone_ok",
        severity="info",
        details={"reason": "Baseline tone satisfied for protected endpoint"},
    )

    return ctx


def require_dual_tone(
    ctx: RequestContext = Depends(get_request_context),
    db: Session = Depends(get_db),
) -> RequestContext:
    if not ctx.device_id:
        record_security_event(
            db=db,
            ctx=ctx,
            event_type="missing_device_id",
            severity="high",
            details={"reason": "Sensitive endpoint called without device id"},
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing or unknown device id",
        )

    ctx = evaluate_tone_risk(ctx, db)

    if not ctx.dual_tone_ok:
        record_security_event(
            db=db,
            ctx=ctx,
            event_type="dual_tone_failed",
            severity="critical",
            details={
                "reason": "Dual tone missing or invalid for sensitive endpoint",
            },
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Dual tone required for sensitive operation",
        )

    record_security_event(
        db=db,
        ctx=ctx,
        event_type="dual_tone_ok",
        severity="info",
        details={"reason": "Dual tone satisfied for sensitive endpoint"},
    )

    return ctx


def evaluate_tone_risk(ctx: RequestContext, db: Session) -> RequestContext:
    """
    Use tone + request profile to update risk_score and flags.
    Phase 1: mostly driven by presence/absence and basic validation.
    Later: can include behavior profiles, historical matches, etc.
    """
    base_score = ctx.risk_score or 0.0

    # Case 1: we have a tone → try to validate it with tone_engine
    if ctx.tone:
        is_valid, reason = validate_tone(
            db,
            session_id=ctx.session_id,
            provided_tone=ctx.tone,
        )
        extra = compute_tone_risk(is_valid, reason)
        ctx.risk_score = base_score + extra
        ctx.risk_flags.append(f"tone:{reason}")

    else:
        # Case 2: missing tone → treat as suspicious but we’ll decide how strict below
        ctx.risk_flags.append("tone:missing")
        ctx.risk_score = base_score + 40.0  # you can tune this number

    # Placeholders for behavior-based profiling (mouse/keyboard etc.)
    # Later you can fill ctx.mouse_profile / ctx.key_profile from separate endpoints
    # and adjust risk based on how "human-normal" the pattern is.

    return ctx
