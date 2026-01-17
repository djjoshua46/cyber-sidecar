# cyber-sidecar/posture_scanner.py

from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional, List, Any, Dict

from sqlalchemy.orm import Session

from .models import Exposure

import socket
def _now() -> datetime:
    return datetime.now(timezone.utc)


def upsert_exposure(
    session: Session,
    *,
    category: str,
    resource: str,
    severity: int,
    opened_by: Optional[str],
    notes: Optional[str] = None,
    environment: Optional[str] = None,
    owner_team: Optional[str] = None,
) -> Exposure:
    """
    Create or update an Exposure row for a given {category, resource} pair.

    - If an open Exposure already exists (ClosedAt is NULL), we bump Severity,
      LastSeenAt, and optionally Notes / Environment / OwnerTeam.
    - If none exists, we create a new Exposure row.
    """
    now = _now()

    existing: Optional[Exposure] = (
        session.query(Exposure)
        .filter(
            Exposure.Category == category,
            Exposure.Resource == resource,
            Exposure.ClosedAt.is_(None),
        )
        .one_or_none()
    )

    if existing:
        # Keep the exposure open, just refresh it
        existing.LastSeenAt = now
        existing.Severity = severity
        if notes:
            # Append note so we don't lose older context
            if existing.Notes:
                existing.Notes = existing.Notes + f"\n[{now.isoformat()}] {notes}"
            else:
                existing.Notes = notes
        if environment:
            existing.Environment = environment
        if owner_team:
            existing.OwnerTeam = owner_team
        exposure = existing
    else:
        exposure = Exposure(
            Category=category,
            Resource=resource,
            Severity=severity,
            OpenedBy=opened_by,
            Notes=notes,
            OpenedAt=now,
            LastSeenAt=now,
            Environment=environment,
            OwnerTeam=owner_team,
        )
        session.add(exposure)

    return exposure


def scan_sql_exposures(session: Session) -> None:
    """
    Placeholder: in v1 we just assert that the SQL port is exposed
    from the sidecar host's point of view.

    Later we can:
      - read from SqlSecurityScanHistory
      - fan out per-database exposures
    """
    upsert_exposure(
        session,
        category="sql_port",
        resource="db-prod-01:1433",
        severity=8,
        opened_by="posture-bot",
        notes="Port 1433 reachable from sidecar host",
        environment="prod",
        owner_team="Data Platform",
    )


def scan_cloud_exposures(session: Session) -> None:
    """
    Placeholder cloud posture checks.

    In a real deployment this will:
      - query AWS/Azure/GCP APIs
      - look for public buckets, open security groups, etc.
    """
    upsert_exposure(
        session,
        category="cloud_bucket",
        resource="s3://customer-exports",
        severity=7,
        opened_by="posture-bot",
        notes="S3 bucket appears public",
        environment="prod",
        owner_team="Data Platform",
    )


def run_posture_scan(session: Session) -> None:
    """
    Run all posture checks and commit once.
    This is what your scheduler / admin API should call.
    """
    scan_sql_exposures(session)
    scan_cloud_exposures(session)
    session.commit()

_COMMON_PORTS: List[int] = [
    22,    # SSH
    80,    # HTTP
    443,   # HTTPS
    445,   # SMB
    1433,  # MSSQL
    3306,  # MySQL
    5432,  # Postgres
    6379,  # Redis
    8085,  # Sidecar (common)
    8099,  # Fake upstream (your harness)
    27017, # Mongo
]

def _is_port_open(host: str, port: int, timeout: float) -> bool:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        return s.connect_ex((host, port)) == 0
    except Exception:
        return False
    finally:
        try:
            s.close()
        except Exception:
            pass

def scan_ports_localhost(*, max_ports: int = 50, host: str = "127.0.0.1", timeout_sec: float = 0.15) -> Dict[str, Any]:
    """
    Fast, non-invasive port posture check for localhost.
    Returns a dict shaped so run_ai.py can use it.
    """
    ports = _COMMON_PORTS[: max_ports] if max_ports else _COMMON_PORTS
    open_ports: List[int] = []
    for p in ports:
        if _is_port_open(host, p, timeout_sec):
            open_ports.append(p)

    return {
        "host": host,
        "checked": ports,
        "open_ports": open_ports,
        "open_count": len(open_ports),
    }