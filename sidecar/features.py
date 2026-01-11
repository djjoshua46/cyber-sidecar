from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, Optional


def compute_features(ctx: Dict[str, Any]) -> Dict[str, Any]:
    """
    Normalize/derive features used by policy + anomaly.

    ctx keys expected (best-effort):
      - anchors_ok (bool)
      - risk_score (float)
      - risk_level (str)
      - behavior_score (float)
      - behavior_level (str)
      - behavior_action (str)
      - ports_open (int)
      - sql_ok (bool)
      - ip, user_agent, endpoint/resource
    """
    risk_score = float(ctx.get("risk_score", 0.0) or 0.0)
    behavior_score = float(ctx.get("behavior_score", 0.0) or 0.0)

    combined = min(100.0, max(0.0, 0.7 * risk_score + 0.3 * behavior_score))

    ports_open = int(ctx.get("ports_open", 0) or 0)
    sql_ok = bool(ctx.get("sql_ok", True))

    # heuristic anomaly score 0..1 (placeholder until ML model)
    anomaly = 0.0
    if ports_open >= 4:
        anomaly += 0.3
    if ports_open >= 6:
        anomaly += 0.3
    if combined >= 70:
        anomaly += 0.3
    if not sql_ok:
        anomaly += 0.4
    anomaly = min(1.0, anomaly)

    feats = {
        "anchors_ok": bool(ctx.get("anchors_ok", False)),
        "risk_score": risk_score,
        "behavior_score": behavior_score,
        "combined": combined,
        "combined_score": combined,
        "ports_open": ports_open,
        "sql_ok": sql_ok,
        "anomaly": anomaly,
        "behavior_action": (ctx.get("behavior_action") or ctx.get("next_action") or "allow"),
        "risk_level": (ctx.get("risk_level") or "low"),
        "behavior_level": (ctx.get("behavior_level") or "low"),
        "deception_used": bool(ctx.get("deception_used", False)),
        "endpoint": ctx.get("endpoint") or ctx.get("resource") or "",
        "ip": ctx.get("ip") or "",
        "user_agent": ctx.get("user_agent") or "",
    }
    return feats


def build_context(
    *,
    user_id: Optional[str],
    session_id: Optional[str],
    device_id: Optional[str],
    anchors_ok: bool,
    risk_score: float,
    risk_level: str,
    behavior_score: float,
    behavior_level: str,
    behavior_action: str,
    deception_used: bool,
    endpoint: str,
    ip: str,
    user_agent: str,
) -> Dict[str, Any]:
    """
    Standard context builder used by run_ai.
    """
    return {
        "ts": datetime.utcnow().isoformat() + "Z",
        "user_id": user_id or "anonymous",
        "session_id": session_id or "anon-session",
        "device_id": device_id or "anon-device",
        "anchors_ok": bool(anchors_ok),
        "risk_score": float(risk_score or 0.0),
        "risk_level": risk_level or "low",
        "behavior_score": float(behavior_score or 0.0),
        "behavior_level": behavior_level or "low",
        "behavior_action": behavior_action or "allow",
        "deception_used": bool(deception_used),
        "endpoint": endpoint or "",
        "ip": ip or "",
        "user_agent": user_agent or "",
    }
