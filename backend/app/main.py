"""RepoLens backend application entry point.

Foundation only: exposes the health endpoint so the skeleton can boot
and be verified. No business logic, no network calls at startup —
importing this module only builds configuration and the FastAPI app.

Run locally::

    uvicorn app.main:app --reload --port 8000
"""

import logging

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import ValidationError

from app.api.analyses import router as analyses_router
from app.api.errors import install_error_handlers
from app.api.health import router as health_router
from app.api.repositories import router as repositories_router
from app.core.config import Settings, format_validation_error, get_settings
from app.core.logging import (
    configure_logging,
    get_logger,
    log_event,
    summarize_settings_for_logging,
)

API_PREFIX = "/api"


def create_app(settings: Settings | None = None) -> FastAPI:
    """Application factory. Raises ValidationError on invalid configuration."""
    active = settings or get_settings()
    configure_logging(active.resolved_log_level)
    logger = get_logger("startup")
    log_event(
        logger,
        logging.INFO,
        "configuration.loaded",
        "Operator configuration loaded",
        environment=active.environment,
    )
    log_event(
        logger,
        logging.INFO,
        "application.started",
        "Application initialized",
        app=active.application.name,
        version=active.application.version,
    )
    logger.debug("Effective configuration: %s", summarize_settings_for_logging(active))

    application = FastAPI(title=active.application.name, version=active.application.version)
    application.state.settings = active
    install_error_handlers(application)
    # Browser CORS for the local frontend. Explicit origin allow-list, no
    # credentials, and only the methods/headers the API actually uses; the
    # allow-list defaults live in ``CorsSettings`` (never a wildcard).
    application.add_middleware(
        CORSMiddleware,
        allow_origins=active.cors.allow_origins,
        allow_methods=["GET", "POST"],
        allow_headers=["content-type"],
        allow_credentials=False,
    )
    application.include_router(health_router, prefix=API_PREFIX)
    application.include_router(analyses_router, prefix=API_PREFIX)
    application.include_router(repositories_router, prefix=API_PREFIX)

    @application.get("/")
    def root() -> dict[str, str]:
        return {"name": active.application.name}

    return application


def build_app() -> FastAPI:
    """Build the module-level app, failing closed with a sanitized report."""
    try:
        return create_app()
    except ValidationError as exc:
        # Fail closed with section/field/reason only — never raw
        # environment values (they may carry credentials).
        raise SystemExit(format_validation_error(exc)) from None


app = build_app()
