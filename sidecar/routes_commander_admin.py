from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from .deps import get_db
from .commander_capture import capture_training_snapshot

router = APIRouter()


@router.post("/api/admin/commander/capture")
def commander_capture(window_minutes: int = 15, db: Session = Depends(get_db)):
    """
    Capture one training snapshot into CommanderTrainingEvents for the last N minutes.
    """
    inserted = capture_training_snapshot(db, tenant_id="default", window_minutes=window_minutes)
    return {"inserted": inserted}
