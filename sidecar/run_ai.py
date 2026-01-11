# run_ai.py
from __future__ import annotations

from datetime import datetime
from sqlalchemy import desc

from sidecar.db import SessionLocal
from sidecar.models import Event, Export

from sidecar.features import build_context, compute_features
from sidecar.posture_scanner import scan_ports_localhost
from sidecar.sql_scanner import quick_sql_healthcheck
from sidecar.policy_agent import PolicyAgent

from sidecar.job import run_ai_loop
import json

_agent = PolicyAgent()

def get_latest_context():
    db = SessionLocal()
    try:
        evt = None
        candidates = (
            db.query(Event)
            .filter(Event.event_type == "export_completed")
            .order_by(desc(Event.id))
            .limit(25)
            .all()
        )

        for c in candidates:
            try:
                d = json.loads(c.details or "{}")
            except Exception:
                d = {}
            if ("risk_score" in d) and ("behavior_score" in d) and ("next_action" in d):
                evt = c
                break

        # fallback: just use the newest if none are rich
        if evt is None and candidates:
            evt = candidates[0]

        if evt is None:
            evt = (
                db.query(Event)
                .filter(Event.event_type == "identity_incomplete")
                .order_by(desc(Event.id))
                .first()
            )

        if evt is None:
            evt = db.query(Event).order_by(desc(Event.id)).first()

        # parse details early (used for fallbacks)
        details = {}
        try:
            raw = getattr(evt, "details", None)
            if raw:
                details = json.loads(raw)
        except Exception:
            details = {}

        # identity anchors (define session_id BEFORE any Export query)
        user_id = getattr(evt, "user_id", None) or "unknown"
        session_id = getattr(evt, "session_id", None) or "unknown"
        device_id = getattr(evt, "device_id", None) or "unknown"

        anchors_ok = user_id != "unknown" and session_id != "unknown" and device_id != "unknown"

        # --- get matching Export for this session (optional) ---
        exp = None
        if session_id != "unknown":
            exp = (
                db.query(Export)
                .filter(Export.session_id == session_id)
                .order_by(desc(Export.id))
                .first()
            )
        if exp is None:
            exp = db.query(Export).order_by(desc(Export.id)).first()

        # --- endpoint / request shape ---
        endpoint = (getattr(evt, "resource", None) or getattr(exp, "resource", None) or "unknown")
        ip = (getattr(evt, "ip", None) or "0.0.0.0")
        ua = (getattr(evt, "user_agent", None) or details.get("user_agent") or "unknown")

        # --- risk-ish signals ---
        # Export model DOES NOT have risk_score/risk_level, so rely on Event.details for now
        risk_score = float(details.get("risk_score") or 0.0)
        risk_level = str(details.get("risk_level") or "low")

        behavior_score = float(details.get("behavior_score") or 0.0)
        behavior_level = str(details.get("behavior_level") or "low")
        behavior_action = str(details.get("next_action") or "allow")

        deception_used = bool(details.get("deception_used") or False)

        # --- cheap posture signals ---
        open_ports = scan_ports_localhost(host="127.0.0.1")
        ports_open = len(open_ports)
        sql_ok = quick_sql_healthcheck(timeout_sec=2.0)

        ctx = build_context(
            user_id=user_id,
            session_id=session_id,
            device_id=device_id,
            anchors_ok=anchors_ok,
            risk_score=risk_score,
            risk_level=risk_level,
            behavior_score=behavior_score,
            behavior_level=behavior_level,
            behavior_action=behavior_action,
            deception_used=deception_used,
            endpoint=str(endpoint),
            ip=str(ip),
            user_agent=str(ua),
        )

        ctx["ports_open"] = ports_open
        ctx["open_ports"] = open_ports
        ctx["sql_ok"] = bool(sql_ok.get("ok", True))
        ctx["sql_latency_ms"] = float(sql_ok.get("latency_ms", 0.0) or 0.0)
        return ctx
    finally:
        db.close()

def get_latest_context_with_ai():
    ctx = get_latest_context()

    # compute features (combined, anchors_ok, etc.)
    feats = compute_features(ctx)

    combined = feats.get("combined")
    if combined is None:
        combined = feats.get("combined_score")
    feats["combined"] = float(combined or 0.0)

    # policy agent decision (support multiple PolicyAgent shapes)
    if hasattr(_agent, "recommend"):
        decision = _agent.recommend(ctx, feats)
    elif hasattr(_agent, "decide"):
        decision = _agent.decide(ctx, feats)
    elif callable(_agent):
        decision = _agent(ctx, feats)
    else:
        raise RuntimeError("PolicyAgent has no recommend()/decide() and is not callable")

    # normalize for responders compatibility
    recommended = (
        decision.get("recommended_action")
        or decision.get("action")
        or decision.get("recommended")
        or "allow"
    )
    policy_rec = {
        "recommended_action": recommended,
        "confidence": float(decision.get("confidence", 0.7) or 0.7),
        "reason": str(decision.get("reason") or "policy_agent"),
    }

    # write ai_decision event for debugging / training
    db = SessionLocal()
    try:
        from sidecar.routes.proxy import _log_event

        _log_event(
            db,
            tenant_id=ctx.get("tenant_id") or "demo",   # REQUIRED
            user_id=ctx.get("user_id"),
            device_id=ctx.get("device_id"),
            session_id=ctx.get("session_id"),
            source="ai_loop",
            event_type="ai_decision",
            resource=ctx.get("endpoint"),
            ip=ctx.get("ip"),
            geo=None,
            client_ip=ctx.get("client_ip"),
            user_agent=ctx.get("user_agent"),
            details={
                "combined": feats.get("combined"),
                "action": policy_rec.get("recommended_action"),
                "confidence": policy_rec.get("confidence"),
                "reason": policy_rec.get("reason"),
                "risk_score": ctx.get("risk_score"),
                "risk_level": ctx.get("risk_level"),
                "behavior_score": ctx.get("behavior_score"),
                "behavior_level": ctx.get("behavior_level"),
                "behavior_action": ctx.get("behavior_action"),
                "ports_open": ctx.get("ports_open"),
                "sql_ok": ctx.get("sql_ok"),
            },
        )
        db.commit()

    except Exception as e:
        db.rollback()
        print("[AI] failed to write ai_decision:", repr(e))
    finally:
        db.close()

    # print like before but using decision action
    rec = policy_rec.get("recommended_action") or policy_rec.get("action")
    print(
        f"[AI] user={ctx.get('user_id')} session={ctx.get('session_id')} "
        f"combined={float(feats.get('combined',0.0)):.1f} "
        f"action={policy_rec.get('action') or policy_rec.get('recommended_action')} "
        f"anomaly={float(feats.get('anomaly', 0.0) or 0.0):.2f} "
        f"ports_open={ctx.get('ports_open')}"
    )

    return {
        "ctx": ctx,
        "feats": feats,
        "policy_rec": policy_rec,
    }


def main():
    run_ai_loop(get_latest_context=get_latest_context_with_ai, interval_s=3.0)



if __name__ == "__main__":
    main()
