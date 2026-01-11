# server/app/routes/posture.py

from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from ..deps import get_db
from ..models import Exposure, ExposureHit

router = APIRouter(prefix="/api/console", tags=["console"])


def _alert_level(severity: int, age_hours: float, recent_hits: int) -> str:
    # very simple scoring to start
    score = 0.0
    score += severity * 5.0
    score += min(age_hours, 72.0) * 0.5
    score += min(recent_hits, 20) * 2.0

    if score >= 80:
        return "high"
    if score >= 40:
        return "medium"
    if score >= 10:
        return "low"
    return "none"


@router.get("/posture")
def get_console_posture(db: Session = Depends(get_db)) -> Dict[str, Any]:
    now = datetime.now(timezone.utc)
    since = now - timedelta(minutes=10)

    exposures: List[Exposure] = (
        db.query(Exposure)
        .filter(Exposure.ClosedAt.is_(None))
        .all()
    )

    hits = (
        db.query(ExposureHit)
        .filter(ExposureHit.CreatedUtc >= since)
        .all()
    )

    hits_by_exposure: Dict[int, int] = {}
    for h in hits:
        hits_by_exposure[h.ExposureId] = hits_by_exposure.get(h.ExposureId, 0) + 1

    sql_exposures: List[Dict[str, Any]] = []
    cloud_exposures: List[Dict[str, Any]] = []

    exposures_json: List[Dict[str, Any]] = []

    for e in exposures:
        age = (now - e.OpenedAt).total_seconds() / 3600.0
        hit_count = hits_by_exposure.get(e.Id, 0)
        level = _alert_level(e.Severity, age, hit_count)

        item = {
            "id": e.Id,
            "category": e.Category,
            "resource": e.Resource,
            "environment": e.Environment,
            "owner_team": e.OwnerTeam,
            "opened_at": e.OpenedAt,
            "opened_by": e.OpenedBy,
            "severity": e.Severity,
            "notes": e.Notes,
            "age_hours": age,
            "recent_hits": hit_count,
            "alert_level": level,
        }
        exposures_json.append(item)

        if e.Category.startswith("sql_"):
            sql_exposures.append(item)
        elif e.Category.startswith("cloud_"):
            cloud_exposures.append(item)

    def summarize(group: List[Dict[str, Any]]) -> Dict[str, Any]:
        return {
            "open_count": len(group),
            "high_count": sum(1 for x in group if x["alert_level"] == "high"),
            "medium_count": sum(1 for x in group if x["alert_level"] == "medium"),
            "low_count": sum(1 for x in group if x["alert_level"] == "low"),
        }

    return {
        "summary": {
            "sql": summarize(sql_exposures),
            "cloud": summarize(cloud_exposures),
        },
        "exposures": exposures_json,
    }
