from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from .deps import get_db
from .commander_runtime import compute_current_posture

router = APIRouter()


@router.get("/api/console/posture")
def get_posture(db: Session = Depends(get_db)):
    """
    Returns the current overall posture for the system.
    """
    posture = compute_current_posture(db)
    return posture
