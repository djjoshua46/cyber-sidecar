# sidecar/ml/features.py
from __future__ import annotations
from dataclasses import dataclass
from typing import Any, Dict, Optional
from urllib.parse import urlparse

def _safe_int(x: Any, default: int = 0) -> int:
    try:
        return int(x)
    except Exception:
        return default

def _safe_float(x: Any, default: float = 0.0) -> float:
    try:
        return float(x)
    except Exception:
        return default

def _host_path(target_url: str) -> tuple[str, str]:
    try:
        u = urlparse(target_url)
        host = (u.hostname or "").lower()
        path = (u.path or "/").lower()
        return host, path
    except Exception:
        return "", ""

def build_policy_features(
    *,
    tenant_id: str,
    user_id: Optional[str],
    session_id: Optional[str],
    device_id: Optional[str],
    client_ip: Optional[str],
    user_agent: Optional[str],
    method: str,
    target_url: str,
    status_code: int,
    byte_size: int,
    row_count: int,
    behavior_score: float,
    drift_score: float,
    tone_risk: float,
    deception_used: bool,
    session_tainted: bool,
) -> Dict[str, Any]:
    """
    Keep this small + stable for v1.
    IMPORTANT: we do NOT include raw PII. (No full IP, no full UA string.)
    """
    host, path = _host_path(target_url)

    # coarse buckets
    is_export = 1 if ("export" in path or path.endswith(".csv")) else 0
    big_bytes = 1 if byte_size >= 500_000 else 0
    huge_bytes = 1 if byte_size >= 5_000_000 else 0
    big_rows = 1 if row_count >= 800 else 0

    # method as categorical-ish ints
    m = (method or "GET").upper()
    method_get = 1 if m == "GET" else 0
    method_post = 1 if m == "POST" else 0

    # status buckets
    s2xx = 1 if 200 <= status_code < 300 else 0
    s4xx = 1 if 400 <= status_code < 500 else 0
    s5xx = 1 if 500 <= status_code < 600 else 0
    sother = 1 if (status_code and (s2xx + s4xx + s5xx) == 0) else 0

    return {
        # join keys (tenant-safe)
        "tenant_id": tenant_id,
        "user_present": 1 if user_id else 0,
        "session_present": 1 if session_id else 0,
        "device_present": 1 if device_id else 0,

        # request shape
        "method_get": method_get,
        "method_post": method_post,
        "is_export": is_export,
        "host": host,     # categorical
        "path": path,     # categorical (can be high-cardinality; ok for v1 baseline)
        "status_2xx": s2xx,
        "status_4xx": s4xx,
        "status_5xx": s5xx,
        "status_other": sother,

        # magnitude
        "byte_size": _safe_int(byte_size),
        "row_count": _safe_int(row_count),
        "big_bytes": big_bytes,
        "huge_bytes": huge_bytes,
        "big_rows": big_rows,

        # your engines (numerics)
        "behavior_score": _safe_float(behavior_score),
        "drift_score": _safe_float(drift_score),
        "tone_risk": _safe_float(tone_risk),
        "deception_used": 1 if deception_used else 0,
        "session_tainted": 1 if session_tainted else 0,
    }
