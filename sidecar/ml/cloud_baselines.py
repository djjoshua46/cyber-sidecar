from __future__ import annotations
from typing import Dict, Any

def _key(*parts: str) -> str:
    return "sc:" + ":".join(p.replace(":", "_") for p in parts if p)

async def update_cloud_baselines(
    redis_client,
    tenant_id: str,
    user_id: str,
    device_id: str,
    session_id: str,
    cloud: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Returns baseline-derived features:
      - first_seen_service
      - service_switch_rate (coarse)
      - enum_burst_score (coarse counter over 60s)
    """
    if not redis_client or not cloud or cloud.get("cloud_is_cloud") != 1:
        return {
            "cloud_first_seen_service": 0,
            "cloud_enum_burst_score": 0.0,
            "cloud_service_switches_60s": 0,
        }

    service = str(cloud.get("cloud_service", "unknown"))
    fam = str(cloud.get("cloud_action_family", "unknown"))

    # First seen: principal -> service
    fs_key = _key("fs", tenant_id, user_id, device_id, service)
    first_seen = 0
    if not await redis_client.exists(fs_key):
        # Mark first-seen for 30 days
        await redis_client.setex(fs_key, 30 * 24 * 3600, "1")
        first_seen = 1

    # Enumeration burst: count enum-ish in last 60s
    # (Simple counter w/ TTL; good enough for v1)
    enum_key = _key("enum60", tenant_id, user_id, session_id)
    enum_burst = 0.0
    if fam == "enumeration":
        v = await redis_client.incr(enum_key)
        await redis_client.expire(enum_key, 60)
        # normalize into 0..1-ish range
        enum_burst = min(1.0, float(v) / 50.0)
    else:
        # read without increment
        try:
            v = await redis_client.get(enum_key)
            enum_burst = min(1.0, float(v or 0) / 50.0)
        except Exception:
            enum_burst = 0.0

    # Service switches in 60s (very coarse)
    lastsvc_key = _key("lastsvc", tenant_id, user_id, session_id)
    switch_key = _key("sw60", tenant_id, user_id, session_id)

    try:
        last = await redis_client.get(lastsvc_key)
        last = (last.decode("utf-8") if isinstance(last, (bytes, bytearray)) else str(last or ""))
        if last and last != service:
            sw = await redis_client.incr(switch_key)
            await redis_client.expire(switch_key, 60)
        else:
            sw = await redis_client.get(switch_key)
        await redis_client.setex(lastsvc_key, 60, service)
        sw = int(sw or 0)
    except Exception:
        sw = 0

    return {
        "cloud_first_seen_service": int(first_seen),
        "cloud_enum_burst_score": float(enum_burst),
        "cloud_service_switches_60s": int(sw),
    }
