from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, Any

try:
    import joblib  # optional; real ML if installed + model present
except ImportError:
    joblib = None  # type: ignore[assignment]

from sqlalchemy.orm import Session

from .models import Event, RiskFinding, Exposure
from .risk_engine import USER_BASELINES

MODEL_PATH = Path(__file__).with_name("commander_model.pkl")
COMMANDER_MODEL = None


def load_commander_model() -> None:
    """
    Try to load commander_model.pkl if joblib is installed.
    If not installed or file missing, we just run with heuristic posture.
    """
    global COMMANDER_MODEL
    if joblib is None:
        COMMANDER_MODEL = None
        return

    if MODEL_PATH.exists():
        COMMANDER_MODEL = joblib.load(MODEL_PATH)
    else:
        COMMANDER_MODEL = None


# Load once when module imports
load_commander_model()


def _time_of_day_score() -> int:
    """Simple heuristic: 1–5 AM UTC is considered 'weird' globally."""
    now_hour = datetime.utcnow().hour
    return 10 if now_hour in (1, 2, 3, 4, 5) else 0


def _compute_baseline_features(db: Session) -> Dict[str, Any]:
    """
    Build a feature snapshot describing 'right now' for the whole system.
    You can later add TenantId filtering if needed.
    """
    now = datetime.now(timezone.utc)
    window = now - timedelta(minutes=15)

    # NOTE: match your actual model fields:
    # Event.timestamp_utc, RiskFinding.created_at_utc, Exposure.ClosedAt, Exposure.Severity
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

    # Export size estimate from USER_BASELINES (rough, but fine for v1)
    all_export_sizes = []
    for base in USER_BASELINES.values():
        for rec in base.get("export_history", []):
            all_export_sizes.append(rec.get("bytes", 0))

    avg_export_size = int(sum(all_export_sizes) / len(all_export_sizes)) if all_export_sizes else 0

    features = {
        "ExportCount": total_events,
        "AvgExportSize": avg_export_size,
        "GeoAnomalyScore": 0,        # extend later
        "DeviceChangeScore": 0,      # extend later
        "DualSessionScore": int(high_risk_count > 0) * 10,
        "TimeOfDayScore": _time_of_day_score(),
        "PortScanScore": open_exposures + high_exposures * 2,
        "EmailRiskScore": 0,         # wired when email sandbox is ready
        "_raw": {
            "total_events": total_events,
            "high_risk_events": high_risk_count,
            "medium_risk_events": medium_risk_count,
            "open_exposures": open_exposures,
            "high_exposures": high_exposures,
        },
    }

    return features


def _ml_classify(features: Dict[str, Any]) -> Dict[str, Any]:
    """
    Use the Commander ML model *if* we have one.
    Returns { label, prob }.
    """
    if COMMANDER_MODEL is None:
        return {"label": "unknown", "prob": 0.0}

    X = [[
        features["ExportCount"],
        features["AvgExportSize"],
        features["GeoAnomalyScore"],
        features["DeviceChangeScore"],
        features["DualSessionScore"],
        features["TimeOfDayScore"],
        features["PortScanScore"],
        features["EmailRiskScore"],
    ]]

    pred = COMMANDER_MODEL.predict(X)[0]
    proba = COMMANDER_MODEL.predict_proba(X)[0]
    max_prob = float(max(proba))

    return {"label": str(pred), "prob": max_prob}


def compute_current_posture(db: Session, tenant_id: str | None = None) -> Dict[str, Any]:
    """
    Main entry: called by /api/console/posture

    Output shape:

    {
      "overall": { "level": "low|medium|high", "score": 0-100 },
      "ml": { "label": "benign|watch|lockdown|unknown", "prob": 0-1 },
      "raw": { ...counts... }
    }
    """
    features = _compute_baseline_features(db)
    raw = features.pop("_raw")

    ml_result = _ml_classify(features)
    ml_label = ml_result["label"]

    # Heuristic base score from counts
    score = 0.0
    score += raw["high_risk_events"] * 15
    score += raw["medium_risk_events"] * 5
    score += raw["high_exposures"] * 10
    score += raw["open_exposures"] * 2

    # Clamp
    score = max(0.0, min(100.0, score))

    # If ML thinks "lockdown", bump score hard
    if ml_label == "lockdown":
        score = max(score, 80.0)
    elif ml_label == "watch":
        score = max(score, 40.0)

    if score >= 80:
        level = "high"
    elif score >= 40:
        level = "medium"
        # below 40
    else:
        level = "low"

    return {
        "overall": {
            "level": level,
            "score": score,
        },
        "ml": ml_result,
        "raw": raw,
    }
