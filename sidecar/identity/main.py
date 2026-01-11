from fastapi import FastAPI
from .routers import auth, webauthn

app = FastAPI(title="Cyber Sidecar Identity Service")

app.include_router(auth.router, prefix="/auth", tags=["auth"])
app.include_router(webauthn.router, prefix="/webauthn", tags=["webauthn"])
