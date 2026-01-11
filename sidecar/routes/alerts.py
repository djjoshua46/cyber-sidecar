from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import List, Optional

from fastapi import APIRouter, Depends, Query, Path, HTTPException, Header
from pydantic import BaseModel
from sqlalchemy import and_
from sqlalchemy.orm import Session

from ..deps import get_db, get_request_context, RequestContext
from ..models import Export, RiskFinding
from ..config import TENANT_ID

router = APIRouter()


class AlertOut(BaseModel):
    id: int
    tenant_id: str
    user_id: Optional[str]
    session_id: Optional[str]
    export_id: Optional[str]
    resource: Optional[str]

    risk_score: int
    risk_level: str
    reasons: List[str]

    export_byte_size: Optional[int]
    export_created_at_utc: Optional[datetime]
    finding_created_at_utc: datetime

    is_acknowledged: bool
    acknowledged_by: Optional[str]
    acknowledged_at_utc: Optional[datetime]


def _tenant_from_ctx(ctx: RequestContext) -> str:
    """
    Prefer tenant from request context (derived from headers / identity).
    Fallback is only for local/dev safety.
    """
    # Adjust attribute name if your RequestContext uses a different field.
    t = getattr(ctx, "tenant_id", None) or getattr(ctx, "org_id", None)
    if t:
        return str(t)

    # Last resort fallback (dev): keep previous behavior
    return TENANT_ID


def _decode_reasons(reason_raw: Optional[str]) -> List[str]:
    if not reason_raw:
        return []
    try:
        import json

        decoded = json.loads(reason_raw)
        if isinstance(decoded, list):
            return [str(x) for x in decoded]
        return [str(decoded)]
    except Exception:
        return [reason_raw]


@router.get("/alerts/high", response_model=List[AlertOut])
def get_high_risk_alerts(
    hours: int = Query(24, ge=1, le=168, description="Look-back window in hours"),
    min_score: int = Query(50, ge=0, le=100, description="Minimum risk score"),
    db: Session = Depends(get_db),
    ctx: RequestContext = Depends(get_request_context),
):
    """
    Historical/high-level view of risk findings.
    Good for dashboards and reports.
    """
    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(hours=hours)

    q = (
        db.query(RiskFinding, Export)
        .join(Export, RiskFinding.export_id == Export.export_id, isouter=True)
        .filter(
            and_(
                RiskFinding.tenant_id == _tenant_from_ctx(ctx),
                RiskFinding.risk_score >= min_score,
                RiskFinding.created_at_utc >= cutoff,
            )
        )
        .order_by(RiskFinding.created_at_utc.desc())
    )

    results: List[AlertOut] = []
    for rf, exp in q.all():
        results.append(
            AlertOut(
                id=rf.id,
                tenant_id=rf.tenant_id,
                user_id=rf.user_id,
                session_id=rf.session_id,
                export_id=rf.export_id,
                resource=rf.resource or (exp.resource if exp else None),
                risk_score=rf.risk_score,
                risk_level=rf.risk_level,
                reasons=_decode_reasons(rf.reason),
                export_byte_size=exp.byte_size if exp else None,
                export_created_at_utc=exp.created_at_utc if exp else None,
                finding_created_at_utc=rf.created_at_utc,
                is_acknowledged=bool(rf.is_acknowledged),
                acknowledged_by=rf.acknowledged_by,
                acknowledged_at_utc=rf.acknowledged_at_utc,
            )
        )

    return results


@router.get("/alerts/live", response_model=List[AlertOut])
def get_live_alerts(
    minutes: int = Query(5, ge=1, le=120, description="Look-back window in minutes"),
    min_score: int = Query(50, ge=0, le=100, description="Minimum risk score"),
    db: Session = Depends(get_db),
    ctx: RequestContext = Depends(get_request_context),
):
    """
    'Live' feed: unacknowledged high-risk findings from the last N minutes.
    This is what your UI can poll every few seconds.
    """
    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(minutes=minutes)

    q = (
        db.query(RiskFinding, Export)
        .join(Export, RiskFinding.export_id == Export.export_id, isouter=True)
        .filter(
            and_(
                RiskFinding.tenant_id == _tenant_from_ctx(ctx),
                RiskFinding.risk_score >= min_score,
                RiskFinding.created_at_utc >= cutoff,
                RiskFinding.is_acknowledged == False,  # noqa: E712
            )
        )
        .order_by(RiskFinding.created_at_utc.desc())
    )

    results: List[AlertOut] = []
    for rf, exp in q.all():
        results.append(
            AlertOut(
                id=rf.id,
                tenant_id=rf.tenant_id,
                user_id=rf.user_id,
                session_id=rf.session_id,
                export_id=rf.export_id,
                resource=rf.resource or (exp.resource if exp else None),
                risk_score=rf.risk_score,
                risk_level=rf.risk_level,
                reasons=_decode_reasons(rf.reason),
                export_byte_size=exp.byte_size if exp else None,
                export_created_at_utc=exp.created_at_utc if exp else None,
                finding_created_at_utc=rf.created_at_utc,
                is_acknowledged=bool(rf.is_acknowledged),
                acknowledged_by=rf.acknowledged_by,
                acknowledged_at_utc=rf.acknowledged_at_utc,
            )
        )

    return results


class AckRequest(BaseModel):
    note: Optional[str] = None


@router.post("/alerts/{alert_id}/ack", response_model=AlertOut)
def acknowledge_alert(
    alert_id: int = Path(..., ge=1),
    body: AckRequest = None,
    db: Session = Depends(get_db),
    x_user_id: Optional[str] = Header(None, alias="X-User-Id"),
):
    """
    Mark an alert as acknowledged by a human.
    """
    rf: RiskFinding | None = db.query(RiskFinding).filter(RiskFinding.id == alert_id).one_or_none()
    if rf is None:
        raise HTTPException(status_code=404, detail="Alert not found")

    if rf.is_acknowledged:
        # Already acked – just return current state
        exp = (
            db.query(Export)
            .filter(Export.export_id == rf.export_id)
            .one_or_none()
        )
        return AlertOut(
            id=rf.id,
            tenant_id=rf.tenant_id,
            user_id=rf.user_id,
            session_id=rf.session_id,
            export_id=rf.export_id,
            resource=rf.resource,
            risk_score=rf.risk_score,
            risk_level=rf.risk_level,
            reasons=_decode_reasons(rf.reason),
            export_byte_size=exp.byte_size if exp else None,
            export_created_at_utc=exp.created_at_utc if exp else None,
            finding_created_at_utc=rf.created_at_utc,
            is_acknowledged=bool(rf.is_acknowledged),
            acknowledged_by=rf.acknowledged_by,
            acknowledged_at_utc=rf.acknowledged_at_utc,
        )

    rf.is_acknowledged = True
    rf.acknowledged_by = x_user_id or "unknown"
    rf.acknowledged_at_utc = datetime.now(timezone.utc)

    # Optionally, you could stuff body.note into Reason, or a separate column later.

    db.add(rf)
    db.commit()

    exp = (
        db.query(Export)
        .filter(Export.export_id == rf.export_id)
        .one_or_none()
    )

    return AlertOut(
        id=rf.id,
        tenant_id=rf.tenant_id,
        user_id=rf.user_id,
        session_id=rf.session_id,
        export_id=rf.export_id,
        resource=rf.resource or (exp.resource if exp else None),
        risk_score=rf.risk_score,
        risk_level=rf.risk_level,
        reasons=_decode_reasons(rf.reason),
        export_byte_size=exp.byte_size if exp else None,
        export_created_at_utc=exp.created_at_utc if exp else None,
        finding_created_at_utc=rf.created_at_utc,
        is_acknowledged=bool(rf.is_acknowledged),
        acknowledged_by=rf.acknowledged_by,
        acknowledged_at_utc=rf.acknowledged_at_utc,
    )
