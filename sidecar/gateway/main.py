from fastapi import FastAPI
from .routes import router as main_router

app = FastAPI(title="Cyber Sidecar Gateway")

app.include_router(main_router)

# Can add startup/shutdown hooks to init HTTP clients, config, etc.
