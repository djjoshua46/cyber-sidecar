from __future__ import annotations
import os, json, asyncio
from fastapi import APIRouter, Request, Header
from starlette.responses import StreamingResponse

router = APIRouter()

@router.get("/events/stream")
async def events_stream(
    request: Request,
    x_org_id: str | None = Header(None, alias="X-Org-Id"),
):
    tenant_id = x_org_id or os.getenv("TENANT_ID", "demo-tenant")
    redis_client = getattr(request.app.state, "redis", None)
    if redis_client is None:
        # SSE without redis makes no sense; return empty stream
        async def _empty():
            yield "event: error\ndata: {\"error\":\"redis_not_configured\"}\n\n"
        return StreamingResponse(_empty(), media_type="text/event-stream")

    pubsub = redis_client.pubsub()
    channel = f"events:{tenant_id}"
    await pubsub.subscribe(channel)

    async def gen():
        try:
            # Tell browser the stream is alive
            yield "event: hello\ndata: {}\n\n"

            while True:
                if await request.is_disconnected():
                    break

                msg = await pubsub.get_message(ignore_subscribe_messages=True, timeout=1.0)
                if msg and msg.get("type") == "message":
                    data = msg.get("data")
                    if isinstance(data, (bytes, bytearray)):
                        data = data.decode("utf-8", errors="replace")
                    yield f"event: event\ndata: {data}\n\n"
                else:
                    # keepalive
                    yield "event: ping\ndata: {}\n\n"

                await asyncio.sleep(0.05)
        finally:
            try:
                await pubsub.unsubscribe(channel)
                await pubsub.close()
            except Exception:
                pass

    return StreamingResponse(gen(), media_type="text/event-stream")
