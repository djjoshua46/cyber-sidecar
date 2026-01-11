from fastapi import APIRouter, Depends
from pydantic import BaseModel
from typing import Optional, Dict, Any
from sqlalchemy.orm import Session

from ..db import SessionLocal
from ..models import Event
from ..config import TENANT_ID

router = APIRouter()


class EventIn(BaseModel):
    user_id: Optional[str] = None
    device_id: Optional[str] = None
    session_id: Optional[str] = None
    source: str
    event_type: str
    resource: Optional[str] = None
    ip: Optional[str] = None
    geo: Optional[str] = None
    details: Optional[Dict[str, Any]] = None


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@router.post("/")
def create_event(event: EventIn, db: Session = Depends(get_db)):
    db_obj = Event(
        tenant_id=TENANT_ID,
        user_id=event.user_id,
        device_id=event.device_id,
        session_id=event.session_id,
        source=event.source,
        event_type=event.event_type,
        resource=event.resource,
        ip=event.ip,
        geo=event.geo,
        details=event.details,
    )
    db.add(db_obj)
    db.commit()
    db.refresh(db_obj)
    return {"status": "ok", "id": db_obj.id}
