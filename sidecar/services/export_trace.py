import uuid
import hashlib
from typing import Optional
from sqlalchemy.orm import Session

from ..models import Export
from ..config import TENANT_ID


def start_export(
    db: Session,
    user_id: Optional[str],
    session_id: Optional[str],
    resource: Optional[str],
) -> str:
    """
    Create a new Export record and return its export_id.
    """
    export_id = str(uuid.uuid4())
    db_obj = Export(
        export_id=export_id,
        tenant_id=TENANT_ID,
        user_id=user_id,
        session_id=session_id,
        resource=resource,
    )
    db.add(db_obj)
    db.commit()
    return export_id


def finalize_export(
    db: Session,
    export_id: str,
    payload: bytes,
    row_count: Optional[int] = None,
) -> None:
    """
    Compute hash, size (and optionally row_count) and update the Export record.
    """
    file_hash = hashlib.sha256(payload).hexdigest()
    byte_size = len(payload)

    db_obj: Optional[Export] = db.query(Export).filter_by(export_id=export_id).first()
    if not db_obj:
        # In a real system we would log this as an error
        return

    db_obj.file_hash = file_hash
    db_obj.byte_size = byte_size
    db_obj.row_count = row_count
    db.commit()
