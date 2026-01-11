from dotenv import load_dotenv
load_dotenv()
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
import redis.asyncio as redis

from .routes import health, events, proxy, alerts, decisions, ui, sql_scan, tone, console, routes_devices, auth, stream
from .routes_posture import router as posture_router
from .routes_commander_admin import router as commander_admin_router
from .routes import proxy as proxy_routes
import httpx, os

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
# app = FastAPI(title="Cyber Sidecar")

@asynccontextmanager
async def lifespan(app: FastAPI):
    app.state.redis = redis.from_url(
        REDIS_URL,
        encoding="utf-8",
        decode_responses=False,
    )

    # ✅ IMPORTANT: expose redis to proxy module global used by the gate
    proxy_routes.redis_client = app.state.redis

    # Shared upstream HTTP client (per-worker)
    timeout_s = float(os.getenv("UPSTREAM_TIMEOUT_SECONDS", "3"))
    app.state.upstream_client = httpx.AsyncClient(
        timeout=httpx.Timeout(timeout_s),
        follow_redirects=True,
        limits=httpx.Limits(
            max_connections=200,
            max_keepalive_connections=50,
            keepalive_expiry=30.0,
        ),
    )

    try:
        yield
    finally:
        # Close upstream client first
        try:
            await app.state.upstream_client.aclose()
        except Exception:
            pass

        # Then close Redis
        try:
            await app.state.redis.close()
        except Exception:
            pass

        # ✅ IMPORTANT: clear module global
        proxy_routes.redis_client = None


app = FastAPI(lifespan=lifespan)

@app.on_event("startup")
async def _startup():
    # one pooled client per worker process
    proxy_routes.HTTPX_CLIENT = httpx.AsyncClient(
        follow_redirects=True,
        timeout=proxy_routes.UPSTREAM_TIMEOUT_SECONDS,
        limits=httpx.Limits(max_keepalive_connections=200, max_connections=500),
    )

@app.on_event("shutdown")
async def _shutdown():
    client = getattr(proxy_routes, "HTTPX_CLIENT", None)
    if client:
        await client.aclose()
        proxy_routes.HTTPX_CLIENT = None

origins = [
    "http://localhost:5173",
    "http://localhost:4173",  # if you ever use preview
]

# CORS – open for now while we develop the sidecar UI
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,      # tighten later
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Routers
app.include_router(health.router,    prefix="/health",    tags=["health"])
app.include_router(events.router,    prefix="/events",    tags=["events"])
app.include_router(proxy.router,                          tags=["proxy"])
app.include_router(alerts.router,    prefix="/alerts",    tags=["alerts"])
app.include_router(decisions.router, prefix="/decisions", tags=["decisions"])
app.include_router(ui.router,        prefix="/ui",        tags=["ui"])
app.include_router(sql_scan.router,  prefix="/admin/sql", tags=["sql-security"])
app.include_router(tone.router)
app.include_router(console.router)
app.include_router(posture_router)
app.include_router(commander_admin_router)
app.include_router(routes_devices.router)
app.include_router(auth.router, tags=["auth"])
app.include_router(stream.router, prefix="/api")