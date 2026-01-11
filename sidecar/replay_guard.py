# sidecar/replay_guard.py
async def assert_not_replay(redis_client, *, tenant_id: str, user_id: str, device_id: str, nonce: str) -> None:
    key = f"nonce:{tenant_id}:{user_id}:{device_id}:{nonce}"
    ok = await redis_client.setnx(key, "1")
    if not ok:
        raise ValueError("replay_detected")
    await redis_client.expire(key, 30)
