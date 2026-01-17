import os
from contextlib import asynccontextmanager

import httpx
import redis.asyncio as redis
from dotenv import load_dotenv
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .middleware.security_headers import SecurityHeadersMiddleware

from .routes import (
    alerts,
    auth,
    console,
    decisions,
    events,
    health,
    proxy,
    routes_devices,
    sql_scan,
    stream,
    tone,
    ui,
)
from .routes_commander_admin import router as commander_admin_router
from .routes_posture import router as posture_router
from .routes import proxy as proxy_routes

load_dotenv()

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
UPSTREAM_TIMEOUT_SECONDS = float(os.getenv("UPSTREAM_TIMEOUT_SECONDS", "3"))


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Redis
    app.state.redis = redis.from_url(
        REDIS_URL,
        encoding="utf-8",
        decode_responses=False,
    )
    proxy_routes.redis_client = app.state.redis

    # Shared HTTPX client
    app.state.upstream_client = httpx.AsyncClient(
        timeout=httpx.Timeout(UPSTREAM_TIMEOUT_SECONDS),
        follow_redirects=True,
        limits=httpx.Limits(
            max_connections=200,
            max_keepalive_connections=50,
            keepalive_expiry=30.0,
        ),
    )
    proxy_routes.HTTPX_CLIENT = app.state.upstream_client

    try:
        yield
    finally:
        # Cleanup
        try:
            await app.state.upstream_client.aclose()
        except Exception:
            pass

        try:
            await app.state.redis.close()
        except Exception:
            pass

        proxy_routes.redis_client = None
        proxy_routes.HTTPX_CLIENT = None


app = FastAPI(lifespan=lifespan)


@app.get("/")
async def root():
    return {"ok": True, "service": "cyber-sidecar"}


# CORS – open for now while developing UI
origins = [
    "http://localhost:5173",
    "http://localhost:4173",
]
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Security headers (fixes ZAP warnings for X-Content-Type-Options, cacheable content, Spectre/site isolation)
# NOTE: if Swagger UI ever breaks, we can scope COEP/COOP/CORP only to non-/docs paths.
app.add_middleware(SecurityHeadersMiddleware)

# Routers
app.include_router(health.router, prefix="/health", tags=["health"])
app.include_router(events.router, prefix="/events", tags=["events"])
app.include_router(proxy.router, tags=["proxy"])
app.include_router(alerts.router, prefix="/alerts", tags=["alerts"])
app.include_router(decisions.router, prefix="/decisions", tags=["decisions"])
app.include_router(ui.router, prefix="/ui", tags=["ui"])
app.include_router(sql_scan.router, prefix="/admin/sql", tags=["sql-security"])
app.include_router(tone.router)
app.include_router(console.router)
app.include_router(posture_router)
app.include_router(commander_admin_router)
app.include_router(routes_devices.router)
app.include_router(auth.router, tags=["auth"])
app.include_router(stream.router, prefix="/api")
