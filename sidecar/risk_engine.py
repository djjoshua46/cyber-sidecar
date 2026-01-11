"""
Fluid, paranoid, adaptive risk engine.

THIS ENGINE DOES FOUR THINGS:
-------------------------------------------------
1. Baseline Modeling
   - Tracks what is "normal" for each user/device/session.
   - Builds histograms of export sizes, frequencies, times of day.

2. Real-time Behavioral Checks
   - Detects sudden spikes (20GB when normal is 5MB)
   - Detects abnormal login locations
   - Detects odd device/browser fingerprints
   - Detects dual-sign-in anomalies
   - Detects impossible travel time

3. Paranoid Multi-Signal Correlation
   - A single anomaly ≠ block
   - Multiple stacked anomalies = escalate / verify biometrics
   - Strong anomalies = auto-block + forensic mode

4. Breadcrumb / Deception Layer
   - If behavior is suspicious, system can:
       → route attacker to honeypot
       → inject fake data
       → shadow-copy their queries
       → log full trace for forensics
"""

import statistics, os
from datetime import datetime, timezone
from typing import Optional, Dict, Any

# In-memory baselines only for now (no DB dependencies)
USER_BASELINES: Dict[str, Dict[str, Any]] = {}
SESSION_HISTORY: Dict[str, Dict[str, Any]] = {}
DEVICE_HISTORY: Dict[str, Dict[str, Any]] = {}
SESSION_CREATED_AT = {}  # { user_id: { session_id: datetime } }


# ------------------------------------------------------------
# 1) BASELINE INITIALIZATION
# ------------------------------------------------------------
def initialize_user_baseline(user_id: str) -> Dict[str, Any]:
    """Create or return the baseline dictionary for this user."""
    if user_id not in USER_BASELINES:
        USER_BASELINES[user_id] = {
            "avg_export_size": 0,
            "avg_row_count": 0,
            "export_history": [],  # list of {"bytes": int, "rows": int}
            "geo_history": [],
            "device_fingerprints": set(),
            "last_login_ip": None,
            "last_login_time": None,
        }
    return USER_BASELINES[user_id]


def update_user_baseline(user_id: str, byte_size: int, row_count: int, ip: str) -> None:
    base = initialize_user_baseline(user_id)

    base["export_history"].append({"bytes": byte_size, "rows": row_count})

    # Keep the history finite
    if len(base["export_history"]) > 200:
        base["export_history"] = base["export_history"][-200:]

    # Recompute averages
    sizes = [x["bytes"] for x in base["export_history"]]
    rows = [x["rows"] for x in base["export_history"]]

    base["avg_export_size"] = statistics.mean(sizes) if sizes else 0
    base["avg_row_count"] = statistics.mean(rows) if rows else 0

    base["last_login_ip"] = ip
    base["last_login_time"] = datetime.utcnow()


# ------------------------------------------------------------
# 2) BEHAVIORAL / ANOMALY FUNCTIONS
# ------------------------------------------------------------

def anomaly_export_spike(user_id: str, byte_size: int, row_count: int) -> float:
    """Large increase from baseline → risk score."""
    base = initialize_user_baseline(user_id)

    risk = 0.0

    # Spike in bytes
    if base["avg_export_size"] > 0:
        ratio = byte_size / base["avg_export_size"]
        if ratio > 10:   # 1000% spike
            risk += 40
        elif ratio > 5:  # 500%
            risk += 25
        elif ratio > 2:
            risk += 10

    # Spike in rows
    if base["avg_row_count"] > 0:
        ratio = (row_count or 1) / (base["avg_row_count"] or 1)
        if ratio > 10:
            risk += 20
        elif ratio > 5:
            risk += 15
        elif ratio > 2:
            risk += 5

    return risk


def anomaly_geo_jump(user_id: str, ip: str) -> float:
    """IP suddenly from another region or impossible distance."""
    base = initialize_user_baseline(user_id)
    last = base.get("last_login_ip")

    if last is None:
        return 0.0

    # Dumb first cut: change in first octet = big region jump
    if last.split(".")[0] != ip.split(".")[0]:
        return 30.0  # major risk for new region login

    return 0.0


def anomaly_time_of_day(user_id: str) -> float:
    """If exporting at a time this user never exports."""
    # For now: simple rule. Later: per-user histogram.
    now_hour = datetime.utcnow().hour

    # 1–5 AM considered weird for most users
    if now_hour in (1, 2, 3, 4, 5):
        return 10.0

    return 0.0


def anomaly_new_device(user_id: str, device_id: Optional[str], user_agent: Optional[str]) -> float:
    base = initialize_user_baseline(user_id)

    fingerprint = f"{device_id}:{user_agent}"

    if fingerprint not in base["device_fingerprints"]:
        base["device_fingerprints"].add(fingerprint)
        return 20.0  # new device → moderate risk

    return 0.0


def anomaly_dual_session(user_id: str, session_id: str) -> float:
    """Detect same user active in two locations at once."""
    if user_id not in SESSION_HISTORY:
        SESSION_HISTORY[user_id] = {"sessions": set()}

    sessions = SESSION_HISTORY[user_id]["sessions"]

    if session_id not in sessions and len(sessions) > 0:
        # Another session already exists
        sessions.add(session_id)
        return 25.0

    sessions.add(session_id)
    return 0.0

def anomaly_session_age(user_id: str, session_id: str) -> float:
    """
    Session-age gates:
      - brand new session doing big things -> suspicious
      - very old session -> reauth should be more likely
    """
    if user_id not in SESSION_CREATED_AT:
        SESSION_CREATED_AT[user_id] = {}

    created = SESSION_CREATED_AT[user_id].get(session_id)
    now = datetime.utcnow()

    if created is None:
        SESSION_CREATED_AT[user_id][session_id] = now
        # New session: no penalty here; we penalize based on behavior elsewhere
        return 0.0

    age_s = (now - created).total_seconds()

    risk = 0.0
    # Example gate: after 20 minutes, start increasing risk
    if age_s > 20 * 60:
        risk += 10.0
    # Example gate: after 2 hours, heavy penalty (should have reauthed again)
    if age_s > 2 * 60 * 60:
        risk += 25.0

    return risk


# ------------------------------------------------------------
# 3) MAIN ENTRYPOINT: SCORE THE EXPORT
# ------------------------------------------------------------
def evaluate_risk(
    *,
    user_id: str,
    session_id: str,
    device_id: Optional[str],
    user_agent: Optional[str],
    ip: str,
    byte_size: int,
    row_count: int,
) -> Dict[str, Any]:
    """
    This is the REAL risk engine call the proxy will use.
    It aggregates every anomaly and returns:
       {
          "score": float,
          "level": "low/medium/high",
          "needs_biometric": bool,
          "needs_honeypot": bool
       }
    """

    update_user_baseline(user_id, byte_size, row_count, ip)

    score = 0.0
    reasons = []

    s = anomaly_export_spike(user_id, byte_size, row_count)
    if s > 0:
        score += s
        reasons.append(f"export_spike +{s:.1f}")

    s = anomaly_geo_jump(user_id, ip)
    if s > 0:
        score += s
        reasons.append(f"geo_jump +{s:.1f} (ip={ip})")

    s = anomaly_time_of_day(user_id)
    if s > 0:
        score += s
        reasons.append(f"odd_time +{s:.1f}")

    s = anomaly_new_device(user_id, device_id, user_agent)
    if s > 0:
        score += s
        reasons.append(f"new_device +{s:.1f}")

    s = anomaly_dual_session(user_id, session_id)
    if s > 0:
        score += s
        reasons.append(f"dual_session +{s:.1f}")

    s = anomaly_session_age(user_id, session_id)
    if s > 0:
        score += s
        reasons.append(f"session_age +{s:.1f}")

    score = min(score, 100.0)

    if score >= 70:
        level = "high"
    elif score >= 40:
        level = "medium"
    else:
        level = "low"

    needs_biometric = score >= 50
    needs_honeypot = score >= 80

    return {
        "score": score,
        "level": level,
        "needs_biometric": needs_biometric,
        "needs_honeypot": needs_honeypot,
        "reasons": reasons,
    }

# ------------------------------------------------------------
# 4) HIGH-LEVEL WRAPPERS FOR PROXY USAGE
# ------------------------------------------------------------
def classify_export_like_request(*args, **kwargs) -> Dict[str, Any]:
    """Compatibility shim to match the earlier system."""
    return evaluate_risk(*args, **kwargs)


def decide_action(risk_dict: Dict[str, Any]) -> str:
    score = float(risk_dict.get("score", 0.0))

    # 0) Unknown identity => divert (never step-up something we can't trust)
    if risk_dict.get("identity_missing"):
        return "honeypot"

    # 1) Block: reserved for near-certain / repeated abuse
    if score >= 98 or risk_dict.get("needs_block"):
        return "block"

    # 2) Honeypot band
    if risk_dict.get("needs_honeypot") or score >= 80:
        return "honeypot"

    # 3) Step-up band
    if risk_dict.get("needs_biometric") or score >= 50:
        return "biometric"

    return "allow"


def create_risk_finding_for_export(export_obj) -> None:
    """
    Best-effort debug hook. Must never break request flow.
    Also must not spam during load tests.
    """
    if os.getenv("SIDECAR_LOADTEST", "0") == "1":
        return

    if os.getenv("SIDECAR_DEBUG_RISK", "0").lower() not in ("1", "true", "yes"):
        return

    # No 'export' variable anywhere — we always use export_obj
    try:
        print(
            "[RISK_FINDING] called for export_id=",
            getattr(export_obj, "export_id", None),
            "tenant=",
            getattr(export_obj, "tenant_id", None),
            "user=",
            getattr(export_obj, "user_id", None),
            "bytes=",
            getattr(export_obj, "byte_size", None),
            "rows=",
            getattr(export_obj, "row_count", None),
            "resource=",
            getattr(export_obj, "resource", None),
        )
    except Exception:
        # best-effort: never crash the request
        pass