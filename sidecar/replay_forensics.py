# sidecar/replay_forensics.py

from __future__ import annotations

import json
import time
import uuid
import hashlib
from typing import Any, Dict, Optional

from fastapi import Request
from sqlalchemy.orm import Session

from .models import ReplayHttpEvent


def log_http_event(
    db: Session,
    *,
    request: Request,
    status_code: int,
    started_at: Optional[float] = None,
    ctx: Any,
    extra: Optional[Dict[str, Any]] = None,
) -> None:
    """
    Core replay-forensics logger.

    We call this from routes (and later middleware) to capture:
      - Who (user/session/device/ip/geo)
      - What (method/path/url/body hash)
      - When (CreatedUtc + duration)
      - Risk engine outputs (risk_score/drift/deception/tone)
    """
    try:
        # ---- Duration ----
        duration_ms: Optional[int] = None
        if started_at is not None:
            duration_ms = int((time.time() - started_at) * 1000)

        # ---- Identity from ctx ----
        user_id = getattr(ctx, "user_id", None)
        session_id = getattr(ctx, "session_id", None)
        device_id = getattr(ctx, "device_id", None)

        origin_ip = getattr(ctx, "origin_ip", None) or getattr(ctx, "client_ip", None)
        forwarded_for = getattr(ctx, "forwarded_for", None)

        # Prefer geo_*; fall back to legacy fields if needed
        country = getattr(ctx, "geo_country", None) or getattr(ctx, "country", None)
        region = getattr(ctx, "geo_region", None) or getattr(ctx, "region", None)
        city = getattr(ctx, "geo_city", None) or getattr(ctx, "city", None)

        asn = getattr(ctx, "asn", None)
        as_org = getattr(ctx, "as_org", None)

        tone_hash = getattr(ctx, "tone_hash", None)

        risk_score = getattr(ctx, "risk_score", None)
        risk_level = getattr(ctx, "risk_level", None)
        drift_score = getattr(ctx, "drift_score", None)
        deception_used = getattr(ctx, "deception_used", None)
        deception_reason = getattr(ctx, "deception_reason", None)

        # ---- Correlation ----
        request_id = getattr(ctx, "request_id", None) or str(uuid.uuid4())
        correlation_id = request.headers.get("X-Correlation-Id")

        # ---- HTTP basics ----
        url = str(request.url)
        path = request.url.path
        query_string = request.url.query or None
        user_agent = getattr(ctx, "user_agent", None) or request.headers.get("user-agent")
        user_agent_hash = getattr(ctx, "user_agent_hash", None)
        header_fingerprint = getattr(ctx, "header_fingerprint", None)
        client_fingerprint = getattr(ctx, "client_fingerprint", None)

        # ---- Body fingerprint (not full body) ----
        body_hash = None
        body_preview = None
        raw_body = getattr(request.state, "raw_body", None)

        if isinstance(raw_body, (bytes, bytearray)) and raw_body:
            body_hash = hashlib.sha256(raw_body).hexdigest()
            try:
                body_preview = raw_body[:512].decode("utf-8", errors="replace")
            except Exception:
                body_preview = None

        if extra is None:
            extra = {}

        row = ReplayHttpEvent(
            RequestId=request_id,
            CorrelationId=correlation_id,

            Method=getattr(ctx, "method", None) or request.method,
            Path=getattr(ctx, "path", None) or path,
            FullUrl=url,
            QueryString=query_string,

            RequestBodyHash=body_hash,
            RequestBodyPreview=body_preview,

            ResponseStatus=status_code,
            ResponseMs=duration_ms,

            UserId=user_id,
            SessionId=session_id,
            DeviceId=device_id,

            OriginIp=origin_ip,
            # If you later add these to the model, you can persist them too:
            # Asn=asn,
            # AsOrg=as_org,
            Country=country,
            Region=region,
            City=city,

            UserAgent=user_agent,
            UserAgentHash=user_agent_hash,
            HeaderFingerprint=header_fingerprint,
            ClientFingerprint=client_fingerprint,

            RiskScore=risk_score,
            RiskLevel=risk_level,
            DriftScore=drift_score,
            DeceptionUsed=deception_used,
            DeceptionReason=deception_reason,

            ToneHash=tone_hash,
            ExtraJson=json.dumps(extra) if extra else None,
        )

        db.add(row)
        db.commit()
    except Exception as exc:
        # Forensics must NEVER break the live system
        print(f"[replay_forensics] failed to log http event: {exc}")
        db.rollback()


def compute_trace_id(user_id: str | None, session_id: str | None, created_utc) -> str:
    base = f"{user_id or '-'}|{session_id or '-'}|{created_utc.isoformat()}"
    return hashlib.sha256(base.encode("utf-8")).hexdigest()[:16]