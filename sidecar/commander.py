from datetime import datetime, timezone, timedelta
from sqlalchemy.orm import Session

from .risk_engine import USER_BASELINES
from .models import CommanderTrainingEvents  # after you add this model

import joblib
from joblib import Path

MODEL_PATH = Path("commander_model.pkl")
COMMANDER_MODEL = None

def load_model():
    global COMMANDER_MODEL
    if MODEL_PATH.exists():
        COMMANDER_MODEL = joblib.load(MODEL_PATH)

load_model()

def capture_training_snapshot(db: Session, tenant_id: str):
    """
    Create a training snapshot for the last N minutes.
    """

    WINDOW = 15  # minutes — you can change
    
    now = datetime.now(timezone.utc)
    window_ago = now - timedelta(minutes=WINDOW)

    # Iterate over every user we've seen
    for user_id, base in USER_BASELINES.items():

        snapshot = CommanderTrainingEvents(
            TenantId=tenant_id,
            UserId=user_id,
            SurfaceId=None,
            WindowMinutes=WINDOW,
            ExportCount=len(base.get("export_history", [])),
            AvgExportSize=int(base.get("avg_export_size", 0)),
            GeoAnomalyScore=0,  # risk_engine already embedded it into risk scoring
            DeviceChangeScore=0,
            DualSessionScore=0,
            TimeOfDayScore=0,
            PortScanScore=0,   # we add this later
            EmailRiskScore=0,  # add later with sandboxing
            Label=None
        )

        db.add(snapshot)

    db.commit()

def classify_snapshot(features: dict) -> dict:
    """
    Use trained CommanderAI model to classify current conditions.
    """

    if COMMANDER_MODEL is None:
        return {"label": "unknown", "prob": 0.0}

    X = [
        [
            features["ExportCount"],
            features["AvgExportSize"],
            features["GeoAnomalyScore"],
            features["DeviceChangeScore"],
            features["DualSessionScore"],
            features["TimeOfDayScore"],
            features["PortScanScore"],
            features["EmailRiskScore"]
        ]
    ]

    pred = COMMANDER_MODEL.predict(X)[0]
    prob = max(COMMANDER_MODEL.predict_proba(X)[0])

    return {"label": pred, "prob": float(prob)}