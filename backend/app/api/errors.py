"""Standardized API error envelope (TASK-169/170, docs/17 §3.4).

Every error uses one structure::

    {"error": {"code": "...", "message": "...", "details": ...}}

``details`` is an object or null, never a stack trace, SQL text, path, or
secret. Expected domain failures map through their frozen contract codes;
unexpected failures become ``INTERNAL_ERROR`` (500) with a user-safe
message while diagnostics stay in server logs.
"""

from __future__ import annotations

import logging

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.core.logging import get_logger, log_event
from app.repository.errors import IngestionError

_logger = get_logger("api.errors")

#: Frozen contract codes with their HTTP statuses (docs/17 §3.4).
ERROR_STATUS: dict[str, int] = {
    "INVALID_URL": 422,
    "REPOSITORY_NOT_ACCESSIBLE": 422,
    "INVALID_BRANCH": 422,
    "INVALID_COMMIT": 422,
    "ANALYSIS_NOT_FOUND": 404,
    "REPOSITORY_NOT_FOUND": 404,
    "ANALYSIS_FAILED": 422,
    "ANALYSIS_NOT_COMPLETED": 409,
    "REPORT_UNAVAILABLE": 404,
    "VALIDATION_ERROR": 400,
    "RATE_LIMITED": 429,
    "INTERNAL_ERROR": 500,
}


class ApiError(Exception):
    """An expected API failure with a frozen contract code."""

    def __init__(
        self,
        code: str,
        message: str,
        details: dict[str, object] | None = None,
        http_status: int | None = None,
    ) -> None:
        if code not in ERROR_STATUS:
            raise ValueError(f"Unknown API error code: {code!r}.")
        super().__init__(message)
        self.code = code
        self.message = message
        self.details = details
        self.http_status = http_status if http_status is not None else ERROR_STATUS[code]


def error_body(
    code: str, message: str, details: dict[str, object] | None = None
) -> dict[str, object]:
    """Build the envelope payload (no internals, ever)."""
    return {"error": {"code": code, "message": message, "details": details}}


def _respond(request: Request, error: ApiError) -> JSONResponse:
    log_event(
        _logger,
        logging.WARNING if error.http_status < 500 else logging.ERROR,
        "api.request.failed",
        "Request failed with a contract error",
        path=request.url.path,
        code=error.code,
        status=error.http_status,
    )
    return JSONResponse(
        status_code=error.http_status,
        content=error_body(error.code, error.message, error.details),
    )


async def _api_error_handler(request: Request, exc: ApiError) -> JSONResponse:
    return _respond(request, exc)


async def _ingestion_error_handler(request: Request, exc: IngestionError) -> JSONResponse:
    code = exc.contract_code if exc.contract_code in ERROR_STATUS else "INTERNAL_ERROR"
    return _respond(request, ApiError(code, exc.user_message))


async def _validation_error_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
    details: dict[str, object] = {
        "errors": [
            {"field": ".".join(str(part) for part in error["loc"]), "reason": error["msg"]}
            for error in exc.errors()
        ]
    }
    return _respond(
        request, ApiError("VALIDATION_ERROR", "The request could not be validated.", details)
    )


async def _http_error_handler(request: Request, exc: StarletteHTTPException) -> JSONResponse:
    # Unmatched routes/methods are client errors with no narrower contract
    # code; they share the generic client-error code and envelope.
    code = "VALIDATION_ERROR" if exc.status_code < 500 else "INTERNAL_ERROR"
    message = "Not found." if exc.status_code == 404 else "The request could not be completed."
    response = _respond(request, ApiError(code, message, http_status=exc.status_code))
    return response


async def _unexpected_error_handler(request: Request, exc: Exception) -> JSONResponse:
    log_event(
        _logger,
        logging.ERROR,
        "api.request.unexpected",
        "Unexpected request failure",
        path=request.url.path,
        error_type=type(exc).__name__,
    )
    return _respond(request, ApiError("INTERNAL_ERROR", "An unexpected error occurred."))


def install_error_handlers(application: FastAPI) -> None:
    """Register the single error-mapping mechanism for the application."""
    application.add_exception_handler(ApiError, _api_error_handler)  # type: ignore[arg-type]
    application.add_exception_handler(IngestionError, _ingestion_error_handler)  # type: ignore[arg-type]
    application.add_exception_handler(RequestValidationError, _validation_error_handler)  # type: ignore[arg-type]
    application.add_exception_handler(StarletteHTTPException, _http_error_handler)  # type: ignore[arg-type]
    application.add_exception_handler(Exception, _unexpected_error_handler)
