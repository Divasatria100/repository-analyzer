"""RepoLens backend application entry point.

Foundation only: exposes the health endpoint so the skeleton can boot
and be verified. No business logic, no network calls at startup —
importing this module only builds configuration and the FastAPI app.

Run locally::

    uvicorn app.main:app --reload --port 8000
"""

from fastapi import FastAPI

from app.api.health import router as health_router
from app.core.config import Settings, get_settings
from app.core.logging import configure_logging

API_PREFIX = "/api"


def create_app(settings: Settings | None = None) -> FastAPI:
    """Application factory. Raises ValidationError on invalid configuration."""
    active = settings or get_settings()
    configure_logging(active.resolved_log_level)

    application = FastAPI(title=active.application.name, version=active.application.version)
    application.state.settings = active
    application.include_router(health_router, prefix=API_PREFIX)

    @application.get("/")
    def root() -> dict[str, str]:
        return {"name": active.application.name}

    return application


app = create_app()
