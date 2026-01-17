from __future__ import annotations

import socket
import json
import time
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from sqlalchemy import text, desc
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session

from .models import SqlSecurityScanHistory
from .db import SessionLocal


def quick_sql_healthcheck(*, timeout_sec: float = 2.0) -> Dict[str, Any]:
    """
    Very fast DB check used by run_ai.py.
    - Opens a DB session
    - Runs SELECT 1
    - Returns ok + latency + error (if any)
    """
    started = time.perf_counter()
    db = SessionLocal()
    try:
        # Best-effort: if DB is down/misconfigured, we just report it.
        db.execute(text("SELECT 1"))
        latency_ms = (time.perf_counter() - started) * 1000.0
        return {"ok": True, "latency_ms": latency_ms, "error": None}
    except Exception as exc:
        latency_ms = (time.perf_counter() - started) * 1000.0
        return {"ok": False, "latency_ms": latency_ms, "error": str(exc)}
    finally:
        try:
            db.close()
        except Exception:
            pass
        
@dataclass
class SqlPortScanResult:
    host: str
    port: int
    reachable: bool
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class SqlSecurityIssue:
    severity: str  # "low", "medium", "high"
    code: str      # short machine-readable code
    message: str   # human-readable summary
    details: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def _get_engine_info(engine: Engine) -> Dict[str, Any]:
    """
    Basic metadata about the SQL instance we are connected to.
    """
    url = engine.url
    return {
        "driver": str(url.drivername),
        "host": url.host or "localhost",
        "port": url.port or 1433,
        "database": url.database,
    }


def _scan_db_port(engine: Engine, timeout: float = 1.0) -> SqlPortScanResult:
    """
    Simple TCP connectivity check to the DB host:port from the sidecar host.
    This does NOT tell us whether the port is open from the internet – just
    whether *we* can reach it. It is still useful context.
    """
    info = _get_engine_info(engine)
    host = info["host"]
    port = info["port"]

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((host, port))
        s.close()
        return SqlPortScanResult(host=host, port=port, reachable=True, error=None)
    except Exception as exc:  # noqa: BLE001
        try:
            s.close()
        except Exception:
            pass
        return SqlPortScanResult(
            host=host,
            port=port,
            reachable=False,
            error=str(exc),
        )


def _collect_sql_issues(db: Session) -> List[SqlSecurityIssue]:
    """
    Run a small set of SQL Server–specific checks against the current instance.

    This is v1: we focus on very obvious high-risk problems that are
    almost always bad practice.
    """
    issues: List[SqlSecurityIssue] = []
    engine = db.get_bind()

    # Use a raw connection so we can issue system-view queries.
    with db.connection() as conn:
        # 1) sa login enabled?
        try:
            rows = conn.execute(
                text(
                    """
                    SELECT name, is_disabled
                    FROM sys.sql_logins
                    WHERE name = 'sa'
                    """
                )
            ).fetchall()
            if rows:
                name, is_disabled = rows[0]
                if not is_disabled:
                    issues.append(
                        SqlSecurityIssue(
                            severity="high",
                            code="SA_LOGIN_ENABLED",
                            message="Built-in 'sa' login is enabled. This is extremely risky.",
                            details={"login": name, "is_disabled": bool(is_disabled)},
                        )
                    )
        except Exception as exc:  # noqa: BLE001
            issues.append(
                SqlSecurityIssue(
                    severity="low",
                    code="CHECK_SA_FAILED",
                    message="Failed to check 'sa' login state (non-fatal).",
                    details={"error": str(exc)},
                )
            )

        # 2) SQL logins with sysadmin rights
        try:
            rows = conn.execute(
                text(
                    """
                    SELECT sp.name
                    FROM sys.server_principals sp
                    WHERE sp.type_desc = 'SQL_LOGIN'
                      AND sp.name NOT LIKE '##%%'
                      AND IS_SRVROLEMEMBER('sysadmin', sp.name) = 1
                    """
                )
            ).fetchall()
            if rows:
                issues.append(
                    SqlSecurityIssue(
                        severity="high",
                        code="SYSADMIN_SQL_LOGINS",
                        message=(
                            "One or more SQL logins have sysadmin rights. "
                            "Prefer least-privilege roles and/or Windows/AD groups."
                        ),
                        details={"logins": [r[0] for r in rows]},
                    )
                )
        except Exception as exc:  # noqa: BLE001
            issues.append(
                SqlSecurityIssue(
                    severity="low",
                    code="CHECK_SYSADMIN_FAILED",
                    message="Failed to inspect sysadmin SQL logins (non-fatal).",
                    details={"error": str(exc)},
                )
            )

        # 3) PUBLIC principal with broad permissions in the current database
        try:
            rows = conn.execute(
                text(
                    """
                    SELECT
                        USER_NAME(dp.grantee_principal_id) AS grantee,
                        dp.permission_name,
                        dp.state_desc,
                        OBJECT_NAME(dp.major_id) AS object_name
                    FROM sys.database_permissions dp
                    WHERE USER_NAME(dp.grantee_principal_id) = 'public'
                      AND dp.permission_name IN ('SELECT', 'INSERT', 'UPDATE', 'DELETE', 'CONTROL')
                    """
                )
            ).fetchall()
            if rows:
                issues.append(
                    SqlSecurityIssue(
                        severity="high",
                        code="PUBLIC_DB_PERMISSIONS",
                        message=(
                            "PUBLIC has broad data permissions in the current database. "
                            "This can allow any login to query or modify data."
                        ),
                        details={
                            "samples": [
                                {
                                    "grantee": r[0],
                                    "permission": r[1],
                                    "state": r[2],
                                    "object": r[3],
                                }
                                for r in rows[:50]
                            ],
                            "total_rows": len(rows),
                        },
                    )
                )
        except Exception as exc:  # noqa: BLE001
            issues.append(
                SqlSecurityIssue(
                    severity="low",
                    code="CHECK_PUBLIC_PERMS_FAILED",
                    message="Failed to inspect PUBLIC database permissions (non-fatal).",
                    details={"error": str(exc)},
                )
            )

    return issues


def run_full_sql_scan(db: Session, context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    Runs the full SQL security scan:

    - Basic engine metadata
    - Port reachability check
    - High-risk config checks
    - Persists a history row into SqlSecurityScanHistory, including who/where
      triggered the scan (if context is provided).
    """
    engine = db.get_bind()
    engine_info = _get_engine_info(engine)
    port_scan = _scan_db_port(engine)
    issues = _collect_sql_issues(db)

    # Serialize issues for both API response and history.
    issues_serialized = [issue.to_dict() for issue in issues]

    # Count by severity (case-insensitive, just in case).
    high_count = sum(1 for i in issues if i.severity.lower() == "high")
    medium_count = sum(1 for i in issues if i.severity.lower() == "medium")
    low_count = sum(1 for i in issues if i.severity.lower() == "low")

    result = {
        "engine": engine_info,
        "port_scan": port_scan.to_dict(),
        "issues": issues_serialized,
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
    }

    ctx = context or {}

    # Persist a history row. If this fails for some reason, we still
    # want the API to work, so we catch and log, but don't break.
    try:
        history = SqlSecurityScanHistory(
            engine_driver=engine_info.get("driver") or "",
            engine_host=engine_info.get("host") or "",
            engine_port=engine_info.get("port") or 0,
            engine_database=engine_info.get("database"),
            issue_count=len(issues_serialized),
            high_count=high_count,
            medium_count=medium_count,
            low_count=low_count,
            issues_json=json.dumps(issues_serialized),

            # Attribution fields (all optional / nullable)
            triggered_by_user_id=ctx.get("user_id"),
            triggered_by_session_id=ctx.get("session_id"),
            triggered_by_device_id=ctx.get("device_id"),
            triggered_from_ip=ctx.get("ip"),
            triggered_from_country=ctx.get("country"),
            triggered_from_region=ctx.get("region"),
            triggered_from_city=ctx.get("city"),
            triggered_from_url=ctx.get("url"),
            triggered_tone=ctx.get("tone"),
        )
        db.add(history)
        db.commit()
    except Exception:
        db.rollback()

    return result

def summarize_issues(issues: list[dict[str, Any]]) -> dict[str, int]:
    total = len(issues)
    high = sum(1 for i in issues if i.get("severity") == "high")
    medium = sum(1 for i in issues if i.get("severity") == "medium")
    low = sum(1 for i in issues if i.get("severity") == "low")
    return {
        "total": total,
        "high": high,
        "medium": medium,
        "low": low,
    }


def _compute_risk_from_issues(issues: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Very simple risk engine for SQL scans.
    Later we can swap this out to use your global risk engine.
    """
    high = sum(1 for i in issues if i.get("severity") == "high")
    medium = sum(1 for i in issues if i.get("severity") == "medium")
    low = sum(1 for i in issues if i.get("severity") == "low")

    # Basic heuristic: more high = higher risk
    base = 5.0  # baseline "ok"
    risk_score = base + high * 25.0 + medium * 10.0 + low * 2.0
    risk_score = max(0.0, min(100.0, risk_score))

    if risk_score < 20:
        risk_level = "low"
    elif risk_score < 60:
        risk_level = "medium"
    else:
        risk_level = "high"

    # For now: no deception / drift detected at SQL layer
    return {
        "risk_score": risk_score,
        "risk_level": risk_level,
        "deception_used": False,
        "deception_reason": None,
        "drift_score": 0.0,
        "biometric_required": risk_score >= 80.0,
        "reauth_reason": "sql_scan_high_risk" if risk_score >= 80.0 else None,
    }


def log_sql_scan_history(
    db: Session,
    scan_result: dict,
    user_id: Optional[str] = None,
    session_id: Optional[str] = None,
    device_id: Optional[str] = None,
    origin_ip: Optional[str] = None,
    country: Optional[str] = None,
    region: Optional[str] = None,
    city: Optional[str] = None,
    url: Optional[str] = None,
    tone_hash: Optional[str] = None,
) -> SqlSecurityScanHistory:
    """
    Store a single summary row of a SQL security scan into SQLSecurityScanHistory.

    This version also computes:
      - RiskScore / RiskLevel  (how bad the findings are)
      - DeceptionUsed / DeceptionReason (placeholder for now)
      - DriftScore, BiometricRequired, ReauthReason (placeholders for now)
    """
    engine = scan_result.get("engine") or {}
    issues = scan_result.get("issues") or []

    # --- basic counts ---
    issue_count = len(issues)
    high_count = sum(1 for i in issues if i.get("severity", "").lower() == "high")
    medium_count = sum(1 for i in issues if i.get("severity", "").lower() == "medium")
    low_count = sum(1 for i in issues if i.get("severity", "").lower() == "low")

    # --- naive risk score (you can tune this later) ---
    # high = 10 pts each, medium = 5, low = 1
    risk_score = high_count * 10 + medium_count * 5 + low_count

    if risk_score >= 50 or high_count >= 5:
        risk_level = "high"
    elif risk_score >= 15 or high_count >= 1:
        risk_level = "medium"
    elif risk_score > 0:
        risk_level = "low"
    else:
        risk_level = "none"

    # For now, we are not actually running deception/drift here.
    # We’ll wire those in from separate engines later.
    deception_used = False
    deception_reason = None

    drift_score = None
    biometric_required = False
    reauth_reason = None

    row = SqlSecurityScanHistory(
        # Engine / environment
        EngineDriver=engine.get("driver") or "",
        EngineHost=engine.get("host") or "",
        EnginePort=int(engine.get("port") or 0),
        EngineDatabase=engine.get("database") or "",

        # Issues
        IssueCount=issue_count,
        HighCount=high_count,
        MediumCount=medium_count,
        LowCount=low_count,
        IssuesJson=json.dumps(issues),

        # Attribution
        TriggeredByUserId=user_id,
        TriggeredBySessionId=session_id,
        TriggeredByDeviceId=device_id,
        TriggeredFromIp=origin_ip,
        TriggeredFromCountry=country,
        TriggeredFromRegion=region,
        TriggeredFromCity=city,
        TriggeredFromUrl=url,
        TriggeredTone=tone_hash,

        # Risk / deception / drift
        RiskScore=risk_score,
        RiskLevel=risk_level,
        DeceptionUsed=deception_used,
        DeceptionReason=deception_reason,
        DriftScore=drift_score,
        BiometricRequired=biometric_required,
        ReauthReason=reauth_reason,
    )

    db.add(row)
    db.commit()
    db.refresh(row)
    return row
quick_sql_healthcheck


def compute_drift_and_deception(
    db: Session,
    engine_host: str,
    engine_database: str,
    issue_count: int,
    high_count: int,
    medium_count: int,
    low_count: int,
) -> Tuple[float, bool]:
    """
    Extremely simple drift/deception heuristic for now:

    - Drift = abs(current_issue_count - last_issue_count)
    - Mark as "deception" if:
        * high_count suddenly drops to 0 from a previous non-zero
        * OR issue_count swings very hard in one scan.
    """
    last: Optional[SqlSecurityScanHistory] = (
        db.query(SqlSecurityScanHistory)
        .filter(
            SqlSecurityScanHistory.engine_host == engine_host,
            SqlSecurityScanHistory.engine_database == engine_database,
        )
        .order_by(desc(SqlSecurityScanHistory.created_utc))
        .first()
    )

    if not last:
        # First scan: no drift yet.
        return 0.0, False

    prev_issues = last.issue_count or 0
    drift = float(abs(issue_count - prev_issues))

    # Super basic "something smells off" flags
    deception = False

    # Case 1: issues suddenly vanish
    if prev_issues > 0 and issue_count == 0:
        deception = True

    # Case 2: crazy spike
    if drift > max(prev_issues * 2, 20):
        deception = True

    return drift, deception