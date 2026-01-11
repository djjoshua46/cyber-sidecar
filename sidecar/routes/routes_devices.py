# sidecar/routes/routes_devices.py

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel
from sqlalchemy.orm import Session

from sidecar.db import get_db
from sidecar.models import DeviceKey

router = APIRouter(prefix="/api/devices", tags=["devices"])


class DeviceRegisterIn(BaseModel):
    tenant_id: str
    user_id: str
    device_id: str
    public_key_pem: str
    ua_hash: str | None = None
    header_fingerprint: str | None = None
    display_name: str | None = None


class DeviceRegisterOut(BaseModel):
    device_id: str


@router.post("/register", response_model=DeviceRegisterOut)
def register_device(
    payload: DeviceRegisterIn,
    request: Request,
    db: Session = Depends(get_db),
) -> DeviceRegisterOut:
    """
    Idempotent registration:
    - Look up an existing DeviceKey for (tenant, user, device_id)
    - If found: update key + fingerprints + LastSeenAt
    - If not: create a new row
    """
    now = datetime.now(timezone.utc)

    # IMPORTANT: we only key on TenantId + UserId + DeviceId here.
    # ua_hash / header_fingerprint are telemetry, not identity.
    row = (
        db.query(DeviceKey)
        .filter(
            DeviceKey.TenantId == payload.tenant_id,
            DeviceKey.UserId == payload.user_id,
            DeviceKey.DeviceId == payload.device_id,
        )
        .first()
    )

    ua_hash = payload.ua_hash
    header_fp = payload.header_fingerprint

    if row:
        # existing device: refresh metadata
        row.PublicKeyPem = payload.public_key_pem
        row.UaHash = ua_hash
        row.HeaderFingerprint = header_fp
        row.LastSeenAt = now
    else:
        # new device: insert
        row = DeviceKey(
            TenantId=payload.tenant_id,
            UserId=payload.user_id,
            DeviceId=payload.device_id,
            PublicKeyPem=payload.public_key_pem,
            UaHash=ua_hash,
            HeaderFingerprint=header_fp,
            CreatedAt=now,
            LastSeenAt=now,
            Revoked=False,
        )
        db.add(row)

    db.commit()

    # Return the logical device_id (the one from the browser)
    return DeviceRegisterOut(device_id=row.DeviceId)
