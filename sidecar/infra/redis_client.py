import os
import redis.asyncio as redis

_redis = None

async def get_redis_async():
    global _redis
    if _redis is not None:
        return _redis

    url = os.getenv("REDIS_URL") or os.getenv("SIDECAR_REDIS_URL") or "redis://redis:6379/0"
    _redis = redis.from_url(url, decode_responses=True)
    return _redis
