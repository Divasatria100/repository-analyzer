"""RepoLens backend application entry point (foundation skeleton).

No business logic lives here yet. The app exposes only a health
endpoint so the skeleton can boot and be verified.
"""

from fastapi import FastAPI

from app.api.health import router as health_router
from app.core.config import settings

app = FastAPI(title=settings.app_name)
app.include_router(health_router)


@app.get("/")
def root() -> dict[str, str]:
    return {"name": settings.app_name}
