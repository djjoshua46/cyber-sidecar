import asyncio
import json
import os
from datetime import datetime
from sidecar.infra.redis_client import get_redis_async
from sidecar.db import SessionLocal
from sidecar.models import RiskFinding

def _risk_level(score: float) -> str:
    if score >= 85:
        return "high"
    if score >= 70:
        return "medium"
    if score >= 50:
        return "low"
    return "low"

def _dedupe_key(tenant_id: str, finding_type: str, correlation_id: str, risk_level: str) -> str:
    return f"dedupe:{tenant_id}:{finding_type}:{correlation_id}:{risk_level}"

async def main():
    tenant = os.getenv("TENANT_ID", "demo-tenant")
    chan = f"events:{tenant}"

    redis = await get_redis_async()
    pubsub = redis.pubsub()
    await pubsub.subscribe(chan)
    print("subscribed", chan)

    DEDUPE_TTL_S = int(os.getenv("SIDECAR_FINDING_DEDUPE_TTL_S", "180"))  # 3 minutes
    AI_FLOOR = float(os.getenv("SIDECAR_AI_FINDING_FLOOR", "85"))

    while True:
        msg = await pubsub.get_message(ignore_subscribe_messages=True, timeout=1.0)
        if not msg:
            await asyncio.sleep(0.05)
            continue

        try:
            payload = json.loads(msg["data"])
        except Exception:
            continue

        tenant_id = payload.get("tenant_id") or tenant
        session_id = payload.get("session_id") or ""
        user_id = payload.get("user_id")
        export_id = payload.get("export_id")
        resource = payload.get("resource")
        score = float(payload.get("risk_score") or 0.0)

        # V1 "AI" gate
        if score < AI_FLOOR or not session_id:
            continue

        level = _risk_level(score)
        finding_type = "ai"
        correlation_id = session_id

        # Dedupe (Redis fast path)
        dk = _dedupe_key(tenant_id, finding_type, correlation_id, level)
        try:
            ok = await redis.setnx(dk, "1")
            if not ok:
                continue
            await redis.expire(dk, DEDUPE_TTL_S)
        except Exception:
            # If Redis hiccups, still proceed (DB write is acceptable)
            pass

        db = SessionLocal()
        try:
            rf = RiskFinding(
                tenant_id=tenant_id,
                user_id=user_id,
                session_id=session_id,
                export_id=export_id,
                resource=resource,
                risk_score=int(score),
                risk_level=level,
                reason=json.dumps(["ai_escalation", f"score>={AI_FLOOR}"]),
                finding_type=finding_type,
                correlation_id=str(correlation_id),
                created_at_utc=datetime.utcnow(),
                is_acknowledged=False,
            )
            db.add(rf)
            db.commit()
            print("wrote RiskFinding", tenant_id, finding_type, correlation_id, level, int(score))
        finally:
            db.close()

if __name__ == "__main__":
    asyncio.run(main())
