from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Path
from pydantic import BaseModel
from sqlalchemy.orm import Session

from ..deps import get_db
from ..models import Export, RiskFinding
from ..config import TENANT_ID

router = APIRouter()


class DecisionOut(BaseModel):
    export_id: str
    tenant_id: str
    user_id: Optional[str]
    session_id: Optional[str]
    resource: Optional[str]

    risk_score: int
    risk_level: str
    reasons: list[str]

    recommended_action: str  # "allow", "monitor", "step_up_auth", "lock_user"
    explanation: str


def _decode_reasons(reason_raw: Optional[str]) -> list[str]:
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


def _map_action(risk_score: int, reasons: list[str]) -> tuple[str, str]:
    """
    Very simple policy for now.
    Later you'll plug ML or more complex rules here.
    """
    if risk_score < 30:
        return (
            "allow",
            "Risk score < 30. Export within normal bounds.",
        )
    elif risk_score < 50:
        return (
            "monitor",
            "Low–medium risk. Log and monitor the user/device for follow-up.",
        )
    elif risk_score < 80:
        return (
            "step_up_auth",
            "Medium–high risk. Require fresh MFA / re-auth before further sensitive actions.",
        )
    else:
        return (
            "lock_user",
            "Very high risk. Recommend temporarily locking the account / session and investigating.",
        )


@router.get("/decisions/export/{export_id}", response_model=DecisionOut)
def get_decision_for_export(
    export_id: str = Path(..., min_length=1),
    db: Session = Depends(get_db),
):
    """
    Given an export_id, return a recommended action based on the highest
    risk finding associated with that export.

    This is the hook your app / firewall could call in real time.
    """
    # Check the export exists
    exp: Export | None = (
        db.query(Export)
        .filter(
            Export.export_id == export_id,
            Export.tenant_id == TENANT_ID,
        )
        .one_or_none()
    )
    if exp is None:
        raise HTTPException(status_code=404, detail="Export not found")

    # Look up the associated risk finding (there may be multiple in the future;
    # just take the highest score).
    rf: RiskFinding | None = (
        db.query(RiskFinding)
        .filter(
            RiskFinding.export_id == export_id,
            RiskFinding.tenant_id == TENANT_ID,
        )
        .order_by(RiskFinding.risk_score.desc())
        .first()
    )

    if rf is None:
        # No risk finding means we treat it as "allow" with score 0.
        reasons: list[str] = []
        action, explanation = _map_action(0, reasons)
        return DecisionOut(
            export_id=export_id,
            tenant_id=exp.tenant_id,
            user_id=exp.user_id,
            session_id=exp.session_id,
            resource=exp.resource,
            risk_score=0,
            risk_level="none",
            reasons=reasons,
            recommended_action=action,
            explanation=explanation,
        )

    reasons = _decode_reasons(rf.reason)
    action, explanation = _map_action(rf.risk_score, reasons)

    return DecisionOut(
        export_id=export_id,
        tenant_id=rf.tenant_id,
        user_id=rf.user_id or exp.user_id,
        session_id=rf.session_id or exp.session_id,
        resource=rf.resource or exp.resource,
        risk_score=rf.risk_score,
        risk_level=rf.risk_level,
        reasons=reasons,
        recommended_action=action,
        explanation=explanation,
    )
