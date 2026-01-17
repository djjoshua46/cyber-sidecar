from __future__ import annotations

import hashlib
import time
from typing import Dict, Optional, Any

from fastapi import APIRouter, Depends, Request
from sqlalchemy.orm import Session

from ..deps import get_db, get_request_context
from ..sql_scanner import run_full_sql_scan, log_sql_scan_history
from ..replay_forensics import log_http_event
from ..models import SqlSecurityScanHistory

router = APIRouter()

def _try_float(val: str | None) -> float | None:
    if val is None:
        return None
    try:
        return float(val)
    except ValueError:
        return None

def _try_bool(val: str | None) -> bool | None:
    if val is None:
        return None
    v = val.strip().lower()
    if v in ("1", "true", "yes", "y"):
        return True
    if v in ("0", "false", "no", "n"):
        return False
    return None


def _compute_scan_tone(
    user_id: Optional[str],
    session_id: Optional[str],
    device_id: Optional[str],
    ip: Optional[str],
) -> str:
    """
    Lightweight fingerprint / 'tone' for *who triggered this scan*.

    This is a deterministic hash we can correlate with other events later.
    It does NOT need to read from EphemeralSessionKeys – it's local to scans.
    """
    raw = "|".join([
        user_id or "",
        session_id or "",
        device_id or "",
        ip or "",
        "sql_scan",  # namespace marker so this is clearly a scan-tone
    ])
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


@router.get(
    "/scan",
    summary="Run a SQL security scan on the sidecar's primary database.",
    tags=["sql-security"],
)
def sql_security_scan(
    request: Request,
    db: Session = Depends(get_db),
    ctx: Any = Depends(get_request_context),  # type: ignore
) -> dict:
    """
    Audits the SQL Server instance this sidecar is connected to AND logs it
    into SQLSecurityScanHistory + ReplayHttpEvents with full attribution.
    """
    started = time.time()

    # 🧠 If this session is high-risk / deceptive, route to honey instead
    if getattr(ctx, "route_to_honey", False):
        # Optional: a fake scan that never touches real SQL
        result = {
            "engine": {
                "driver": "mssql+pyodbc",
                "host": "localhost",
                "port": 1433,
                "database": "CyberSidecar",
            },
            "port_scan": {
                "host": "localhost",
                "port": 1433,
                "reachable": True,
                "error": None,
            },
            "issues": [],
            "generated_at_utc": "HONEYPOT",
        }
    else:
        # Real scan against the customer’s database
        result = run_full_sql_scan(db)

    # 1) Log the SQL scan summary row
    log_sql_scan_history(
        db,
        result,
        user_id=getattr(ctx, "user_id", None),
        session_id=getattr(ctx, "session_id", None),
        device_id=getattr(ctx, "device_id", None),
        origin_ip=getattr(ctx, "origin_ip", None),
        country=getattr(ctx, "geo_country", None),
        region=getattr(ctx, "geo_region", None),
        city=getattr(ctx, "geo_city", None),
        url=str(request.url),
        tone_hash=getattr(ctx, "tone_hash", None),
    )

    # 2) Log a replay-forensics HTTP event
    log_http_event(
        db=db,
        request=request,
        ctx=ctx,
        status_code=200,
        started_at=started,
        extra={
            "engine": "sql_scan",
            "honeypot": bool(getattr(ctx, "route_to_honey", False)),
        },
    )

    return result


@router.post(
    "/scan/test-history",
    summary="Insert a synthetic row into SqlSecurityScanHistory (for dev/testing).",
)
def sql_scan_test_history(db: Session = Depends(get_db)) -> Dict:
    """
    Simple dev-only endpoint to confirm that SqlSecurityScanHistory
    writes correctly with the current schema.
    """
    history = SqlSecurityScanHistory(
        EngineDriver="mssql+pyodbc",
        EngineHost="localhost",
        EnginePort=1433,
        EngineDatabase="CyberSidecar",
        IssueCount=999,
        HighCount=10,
        MediumCount=20,
        LowCount=30,
        IssuesJson='{"test": true, "note": "manual insert"}',

        RiskScore=123.0,
        RiskLevel="high",
        DeceptionUsed=False,
        DeceptionReason=None,
        DriftScore=None,
        BiometricRequired=False,
        ReauthReason=None,
    )
    db.add(history)
    db.commit()
    db.refresh(history)
    return {"status": "ok", "inserted_id": history.Id}
