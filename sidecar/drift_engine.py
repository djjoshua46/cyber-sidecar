from __future__ import annotations

from datetime import datetime
from typing import Optional

from sqlalchemy.orm import Session

from .models import UserDriftState


def update_and_score_drift(
    db: Session,
    *,
    tenant_id: str,
    user_id: Optional[str],
    ip: Optional[str],
    byte_size: int,
    row_count: int,
) -> float:
    """
    Very simple drift heuristic:
      - tracks last_ip, last_seen_at, totals
      - raises risk if:
          * IP suddenly changes
          * large export shortly after last one
          * export much larger than historical average
    """
    if not user_id:
        return 0.0

    now = datetime.utcnow()

    row = (
        db.query(UserDriftState)
        .filter(
            UserDriftState.tenant_id == tenant_id,
            UserDriftState.user_id == user_id,
        )
        .one_or_none()
    )

    drift = 0.0

    if row is None:
        # First time we've seen this user → establish baseline, no drift yet.
        row = UserDriftState(
            tenant_id=tenant_id,
            user_id=user_id,
            last_ip=ip,
            last_seen_at=now,
            total_exports=1,
            total_bytes=byte_size,
            last_row_count=row_count or None,
        )
        db.add(row)
        db.flush()
        return 0.0

    # Compute heuristics
    if ip and row.last_ip and ip != row.last_ip:
        drift += 20.0

    delta = now - (row.last_seen_at or now)
    seconds = max(delta.total_seconds(), 0.0)

    # Large export very soon after the last one
    if seconds < 60 and byte_size > 5 * 1024 * 1024:  # >5MB within 60 seconds
        drift += 30.0

    # Unusually large vs historical average
    avg_bytes = row.total_bytes / row.total_exports if row.total_exports > 0 else 0
    if avg_bytes > 0 and byte_size > 5 * avg_bytes:
        drift += 25.0

    # Clamp drift to something sane
    drift = max(0.0, min(drift, 60.0))

    # Update state
    row.last_ip = ip or row.last_ip
    row.last_seen_at = now
    row.total_exports = (row.total_exports or 0) + 1
    row.total_bytes = (row.total_bytes or 0) + byte_size
    row.last_row_count = row_count or row.last_row_count
    row.updated_at = now

    return drift
