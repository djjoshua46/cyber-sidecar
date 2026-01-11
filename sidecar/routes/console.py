# sidecar/routes/console.py
from __future__ import annotations

from datetime import datetime
from typing import List, Optional

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel
from sqlalchemy import text
from sqlalchemy.orm import Session

from ..deps import get_db, get_request_context, RequestContext   # 👈 added ctx import

router = APIRouter(prefix="/api/console", tags=["console"])


class ConsoleEvent(BaseModel):
    id: int
    created_utc: datetime
    method: str
    path: str
    full_url: Optional[str] = None
    origin_ip: Optional[str] = None
    country: Optional[str] = None
    region: Optional[str] = None
    city: Optional[str] = None
    user_id: Optional[str] = None
    session_id: Optional[str] = None
    device_id: Optional[str] = None
    user_agent: Optional[str] = None
    risk_score: Optional[int] = None
    risk_level: Optional[str] = None
    drift_score: Optional[int] = None
    deception_used: Optional[bool] = None
    deception_reason: Optional[str] = None
    honeypot: bool = False  # parsed from ExtraJson if present
    source: Optional[str] = None
    event_type: Optional[str] = None


@router.get("/events", response_model=List[ConsoleEvent])
def list_events(
    db: Session = Depends(get_db),
    ctx: RequestContext = Depends(get_request_context),   # 👈 inject ctx
    limit: int = Query(100, ge=1, le=500),
):
    """
    Return the most recent HTTP replay events with basic risk + geo + deception info.
    Backed directly by ReplayHttpEvents table.

    ctx is currently unused but wired in, so we can later:
      - filter by tenant/user/device
      - adjust behavior if route_to_honey / require_biometric is set
    """
    sql = text(
        """
        SELECT TOP (:limit)
            [Id],
            [CreatedUtc],
            [Method],
            [Path],
            [FullUrl],
            [OriginIp],
            [Country],
            [Region],
            [City],
            [UserId],
            [SessionId],
            [DeviceId],
            [UserAgent],
            [RiskScore],
            [RiskLevel],
            [DriftScore],
            [DeceptionUsed],
            [DeceptionReason],
            [ExtraJson]
        FROM dbo.ReplayHttpEvents
        ORDER BY CreatedUtc DESC
        """
    )

    rows = db.execute(sql, {"limit": limit}).mappings().all()
    events: list[ConsoleEvent] = []

    import json

    for r in rows:
        extra_raw = r.get("ExtraJson")
        honeypot = False
        if extra_raw:
            try:
                extra = json.loads(extra_raw)
                honeypot = bool(extra.get("honeypot"))
            except Exception:
                honeypot = False

        events.append(
            ConsoleEvent(
                id=r["Id"],
                created_utc=r["CreatedUtc"],
                method=r["Method"],
                path=r["Path"],
                full_url=r["FullUrl"],
                origin_ip=r["OriginIp"],
                country=r["Country"],
                region=r["Region"],
                city=r["City"],
                user_id=r["UserId"],
                session_id=r["SessionId"],
                device_id=r["DeviceId"],
                user_agent=r["UserAgent"],
                risk_score=r["RiskScore"],
                risk_level=r["RiskLevel"],
                drift_score=r["DriftScore"],
                deception_used=r["DeceptionUsed"],
                deception_reason=r["DeceptionReason"],
                honeypot=honeypot,
                source="replay",
                event_type="http",

            )
        )

    # -----------------------------
    # ALSO INCLUDE BEACON EVENTS
    # -----------------------------
    try:
        from ..models import Event as EventModel  # dbo.Events

        beacon_rows = (
            db.query(EventModel)
            .filter(EventModel.event_type.like("beacon%"))
            .order_by(EventModel.timestamp_utc.desc())
            .limit(limit)
            .all()
        )

        for e in beacon_rows:
            # Synthesize method/path so the UI can show something useful
            if e.event_type == "beacon_hit":
                path = f"/proxy/beacon/t/{e.resource}"
                method = "GET"
            elif e.event_type == "beacon_armed":
                path = "/proxy/beacon/arm"
                method = "POST"
            else:
                path = f"/events/{e.event_type}"
                method = "EVENT"

            events.append(
                ConsoleEvent(
                    id=e.id,
                    created_utc=e.timestamp_utc,
                    source=e.source,         # "beacon"
                    event_type=e.event_type, # "beacon_hit" / "beacon_armed"
                    method=method,
                    path=path,
                    full_url=None,
                    origin_ip=e.ip,
                    country=None,
                    region=None,
                    city=e.geo,  # Events.geo is a label today; put it somewhere visible
                    user_id=e.user_id,
                    session_id=e.session_id,
                    device_id=e.device_id,
                    user_agent=e.user_agent,
                    risk_score=None,
                    risk_level=None,
                    drift_score=None,
                    deception_used=None,
                    deception_reason=None,
                    honeypot=False,
                )
            )

    except Exception:
        # Don't let console feed break if Events isn't available in some env
        pass

    # Merge-sort and enforce limit
    events.sort(key=lambda x: x.created_utc, reverse=True)
    return events[:limit]


class RiskSummary(BaseModel):
    total_events: int
    high_risk: int
    medium_risk: int
    low_risk: int
    avg_risk: Optional[float] = None
    honeypot_events: int


@router.get("/risk-summary", response_model=RiskSummary)
def risk_summary(
    db: Session = Depends(get_db),
    ctx: RequestContext = Depends(get_request_context),   # 👈 inject ctx here too
):
    """
    Lightweight aggregate over ReplayHttpEvents for the dashboard header cards.

    ctx is available for future multi-tenant filtering or per-device views.
    """
    sql = text(
        """
        SELECT
          COUNT(*) AS total_events,
          SUM(CASE WHEN RiskLevel = 'high' THEN 1 ELSE 0 END) AS high_risk,
          SUM(CASE WHEN RiskLevel = 'medium' THEN 1 ELSE 0 END) AS medium_risk,
          SUM(CASE WHEN RiskLevel = 'low' THEN 1 ELSE 0 END) AS low_risk,
          AVG(CAST(RiskScore AS FLOAT)) AS avg_risk,
          SUM(
            CASE
              WHEN TRY_CONVERT(XML, ExtraJson) IS NULL
                   AND ExtraJson LIKE '%"honeypot": true%'
              THEN 1 ELSE 0
            END
          ) AS honeypot_events
        FROM dbo.ReplayHttpEvents
        """
    )

    row = db.execute(sql).mappings().one()
    return RiskSummary(
        total_events=row["total_events"] or 0,
        high_risk=row["high_risk"] or 0,
        medium_risk=row["medium_risk"] or 0,
        low_risk=row["low_risk"] or 0,
        avg_risk=row["avg_risk"],
        honeypot_events=row["honeypot_events"] or 0,
    )
