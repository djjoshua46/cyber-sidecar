from fastapi import APIRouter
from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

router = APIRouter()


@router.get("/")
def health():
    return {"status": "ok"}

@router.get("/redis")
async def health_redis(request: Request):
    r = getattr(request.app.state, "redis", None)
    if r is None:
        return JSONResponse(status_code=503, content={"ok": False, "error": "no_redis_on_app_state"})

    try:
        pong = await r.ping()
        return {"ok": True, "ping": bool(pong)}
    except Exception as e:
        return JSONResponse(status_code=503, content={"ok": False, "error": "redis_ping_failed", "detail": repr(e)})