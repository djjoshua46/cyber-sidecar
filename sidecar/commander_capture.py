from __future__ import annotations

from datetime import datetime, timedelta, timezone
from sqlalchemy.orm import Session

from .models import CommanderTrainingEvents, Event, RiskFinding, Exposure
from .risk_engine import USER_BASELINES


def capture_training_snapshot(db: Session, tenant_id: str = "default", window_minutes: int = 15) -> int:
    now = datetime.now(timezone.utc)
    window = now - timedelta(minutes=window_minutes)

    recent_events_q = db.query(Event).filter(Event.timestamp_utc >= window)
    total_events = recent_events_q.count()

    recent_risks_q = db.query(RiskFinding).filter(RiskFinding.created_at_utc >= window)
    high_risk_count = recent_risks_q.filter(RiskFinding.risk_score >= 80).count()
    medium_risk_count = recent_risks_q.filter(
        (RiskFinding.risk_score >= 40) & (RiskFinding.risk_score < 80)
    ).count()

    open_exposures_q = db.query(Exposure).filter(Exposure.ClosedAt.is_(None))
    open_exposures = open_exposures_q.count()
    high_exposures = open_exposures_q.filter(Exposure.Severity >= 7).count()

    all_export_sizes = []
    for base in USER_BASELINES.values():
        for rec in base.get("export_history", []):
            all_export_sizes.append(rec.get("bytes", 0))

    avg_export_size = int(sum(all_export_sizes) / len(all_export_sizes)) if all_export_sizes else 0

    # 🔥 Auto-label based on your intuition of "ok / off / shit hits the fan"
    # You can tweak these thresholds any time:
    if high_risk_count >= 3 or high_exposures >= 2 or open_exposures >= 10:
        label = "lockdown"
    elif medium_risk_count >= 2 or high_exposures >= 1 or open_exposures >= 3:
        label = "watch"
    else:
        label = "benign"

    row = CommanderTrainingEvents(
        TenantId=tenant_id,
        UserId=None,
        SurfaceId=None,
        WindowMinutes=window_minutes,
        ExportCount=total_events,
        AvgExportSize=avg_export_size,
        GeoAnomalyScore=0,
        DeviceChangeScore=0,
        DualSessionScore=int(high_risk_count > 0) * 10,
        TimeOfDayScore=0,
        PortScanScore=open_exposures + high_exposures * 2,
        EmailRiskScore=0,
        Label=label,
    )

    db.add(row)
    db.commit()
    return 1
