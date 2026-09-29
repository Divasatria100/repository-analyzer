"""Structured logging foundation (safe by default).

Guarantees for this foundation (see docs/15 §13):

* no secret is logged in full — values attached to sensitive keys
  (``password``, ``token``, ``secret``, …) are replaced with ``***``;
* no raw credentials are emitted — record arguments are filtered before
  formatting, and ``Authorization``-style headers must never be logged;
* URLs are scrubbed of userinfo passwords and sensitive query parameters;
* log level resolves per environment (``test`` quiets to ``WARNING``).

Structured events (``log_event``) carry stable event names plus optional
context (``request_id``, ``analysis_id``, component, …). Only metadata is
logged — never repository source, never secret values.

This foundation does not implement the analyzer redaction pipeline;
it only ensures RepoLens's own diagnostics cannot leak secrets.
"""

import contextvars
import logging
import re
from collections.abc import Mapping
from typing import Any
from urllib.parse import urlsplit, urlunsplit

SENSITIVE_KEYS = frozenset(
    {
        "password",
        "passwd",
        "pwd",
        "secret",
        "client_secret",
        "token",
        "access_token",
        "refresh_token",
        "api_key",
        "apikey",
        "x-api-key",
        "authorization",
        "proxy-authorization",
        "proxy_authorization",
        "cookie",
        "set-cookie",
        "set_cookie",
        "credential",
        "credentials",
        "private_key",
        "database_url",
    }
)

# HTTP headers that must never be logged in plaintext (case-insensitive).
SENSITIVE_HEADERS = frozenset(
    {
        "authorization",
        "proxy-authorization",
        "cookie",
        "set-cookie",
    }
)

REDACTED = "***"

_CREDENTIAL_PATTERN = re.compile(
    r"(?i)\b(password|passwd|secret|client_secret|private_key|database_url|"
    r"(?:access_|refresh_)?token|api[_-]?key|authorization)\b\s*[:=]\s*"
    r"(?P<value>[^\s,}]+)"
)

_URL_USERINFO_PATTERN = re.compile(r"(?i)([a-zA-Z][a-zA-Z0-9+.-]*://[^/\s]*?):[^@/\s]*?@")

_URL_FINDER_PATTERN = re.compile(r"https?://[^\s,}]+")


def redact_value(key: str, value: Any) -> Any:
    """Return ``REDACTED`` when ``key`` names a sensitive field."""
    if key.lower() in SENSITIVE_KEYS:
        return REDACTED
    return value


def redact_text(message: str) -> str:
    """Mask credential fragments and sensitive URL parts inside free text."""
    redacted = _CREDENTIAL_PATTERN.sub(
        lambda match: match.group(0).replace(match.group("value"), REDACTED), message
    )
    redacted = _URL_USERINFO_PATTERN.sub(lambda match: f"{match.group(1)}:{REDACTED}@", redacted)
    return _URL_FINDER_PATTERN.sub(lambda match: redact_url(match.group(0)), redacted)


def redact_url(url: str) -> str:
    """Scrub userinfo passwords and sensitive query parameters from a URL."""
    try:
        parts = urlsplit(url)
    except ValueError:
        return redact_text(url) if "://" not in url else url
    if not parts.scheme or not parts.netloc:
        return url
    netloc = parts.netloc
    if "@" in netloc:
        userinfo, _, host = netloc.rpartition("@")
        user, _, _ = userinfo.partition(":")
        netloc = f"{user}:{REDACTED}@{host}" if ":" in userinfo else netloc
    query = "&".join(_redact_query_pair(pair) for pair in parts.query.split("&") if pair != "")
    return urlunsplit((parts.scheme, netloc, parts.path, query, parts.fragment))


def _redact_query_pair(pair: str) -> str:
    """Redact one raw ``key=value`` query fragment, preserving encoding."""
    key, separator, value = pair.partition("=")
    if separator and key.lower() in SENSITIVE_KEYS:
        return f"{key}={REDACTED}"
    return pair


def redact_headers(headers: Mapping[str, Any]) -> dict[str, Any]:
    """Redact sensitive HTTP headers (case-insensitive); never plaintext."""
    return {
        key: REDACTED
        if key.lower() in SENSITIVE_HEADERS or key.lower() in SENSITIVE_KEYS
        else value
        for key, value in headers.items()
    }


def redact_sensitive_data(data: Any) -> Any:
    """Recursively redact sensitive values in nested dicts/lists/tuples/strings."""
    if isinstance(data, Mapping):
        return {
            key: REDACTED
            if isinstance(key, str) and key.lower() in SENSITIVE_KEYS
            else redact_sensitive_data(value)
            for key, value in data.items()
        }
    if isinstance(data, (list, tuple)):
        redacted = [redact_sensitive_data(item) for item in data]
        return type(data)(redacted)
    if isinstance(data, str):
        return redact_text(data)
    return data


def redact_args(args: Any) -> Any:
    """Recursively redact sensitive values inside logging record arguments."""
    if isinstance(args, dict):
        return {
            key: REDACTED if key.lower() in SENSITIVE_KEYS else redact_args(value)
            for key, value in args.items()
        }
    if isinstance(args, (list, tuple)):
        redacted = [redact_args(item) for item in args]
        return type(args)(redacted)
    if isinstance(args, str):
        return redact_text(args)
    return args


class RedactingFilter(logging.Filter):
    """Logging filter that redacts secrets before a record is emitted."""

    def filter(self, record: logging.LogRecord) -> bool:
        if record.args:
            # Redact the fully rendered message instead of the template so
            # %-style formatting is never broken by redaction.
            record.msg = redact_text(record.getMessage())
            record.args = None
        elif isinstance(record.msg, str):
            record.msg = redact_text(record.msg)
        return True


# --- Structured events and correlation context ---

# Correlation/request identifiers. Set per request/analysis where available;
# never manufactured — absent context renders as "-".
request_id_ctx: contextvars.ContextVar[str] = contextvars.ContextVar("request_id", default="-")
analysis_id_ctx: contextvars.ContextVar[str] = contextvars.ContextVar("analysis_id", default="-")


def set_request_context(request_id: str = "-", analysis_id: str = "-") -> None:
    """Bind correlation identifiers for the current context (request/analysis)."""
    request_id_ctx.set(request_id)
    analysis_id_ctx.set(analysis_id)


def clear_request_context() -> None:
    """Reset correlation identifiers to absent."""
    request_id_ctx.set("-")
    analysis_id_ctx.set("-")


class ContextFilter(logging.Filter):
    """Attach correlation identifiers to every emitted record."""

    def filter(self, record: logging.LogRecord) -> bool:
        record.request_id = request_id_ctx.get()
        record.analysis_id = analysis_id_ctx.get()
        return True


class EventFormatter(logging.Formatter):
    """Render event name, correlation context, and redacted tracebacks."""

    def format(self, record: logging.LogRecord) -> str:
        if not hasattr(record, "repolens_event"):
            record.repolens_event = "-"  # type: ignore[attr-defined]
        if not hasattr(record, "repolens_detail"):
            record.repolens_detail = ""  # type: ignore[attr-defined]
        return super().format(record)

    def formatException(self, ei: Any) -> str:  # noqa: N802 (stdlib override)
        return redact_text(super().formatException(ei))


_EVENT_FORMAT = (
    "%(asctime)s %(levelname)s %(name)s "
    "event=%(repolens_event)s request_id=%(request_id)s analysis_id=%(analysis_id)s "
    "%(message)s%(repolens_detail)s"
)


def log_event(
    logger: logging.Logger,
    level: int,
    event: str,
    message: str,
    **fields: Any,
) -> None:
    """Emit a structured event log with stable name and redacted context fields.

    Only metadata belongs in ``fields`` (identifiers, paths, rule IDs, line
    numbers, durations, statuses) — never source content or secret values.
    """
    safe_fields = redact_sensitive_data(fields)
    detail = "".join(f" {key}={value}" for key, value in sorted(safe_fields.items()))
    logger.log(
        level,
        redact_text(message),
        extra={"repolens_event": event, "repolens_detail": detail},
    )


def log_exception(
    logger: logging.Logger,
    event: str,
    exc: BaseException,
    message: str,
    **fields: Any,
) -> None:
    """Emit an ERROR event for an exception with the error value redacted."""
    fields = {
        **fields,
        "error_type": type(exc).__name__,
        "error": redact_text(str(exc)),
    }
    log_event(logger, logging.ERROR, event, message, **fields)


def configure_logging(level: str) -> logging.Logger:
    """Configure the ``repolens`` root logger once and return it."""
    logger = logging.getLogger("repolens")
    logger.setLevel(level)
    if not any(isinstance(handler, logging.StreamHandler) for handler in logger.handlers):
        handler = logging.StreamHandler()
        handler.setFormatter(EventFormatter(_EVENT_FORMAT))
        # Handler-level filters apply to records from every child logger;
        # logger-level filters alone would miss propagated records.
        handler.addFilter(RedactingFilter())
        handler.addFilter(ContextFilter())
        logger.addHandler(handler)
    if not any(isinstance(filter_, RedactingFilter) for filter_ in logger.filters):
        logger.addFilter(RedactingFilter())
    logger.propagate = False
    return logger


def get_logger(name: str) -> logging.Logger:
    """Return a child logger of the ``repolens`` root logger."""
    return logging.getLogger(f"repolens.{name}")


def summarize_settings_for_logging(settings: Any) -> dict[str, Any]:
    """Return an operator-safe settings summary: structure without secrets.

    Safe to emit at startup (``configuration.loaded``): database URLs and
    any other sensitive values are replaced, never logged in plaintext.
    """
    summary = settings.model_dump() if hasattr(settings, "model_dump") else dict(settings)
    summary = redact_sensitive_data(summary)
    database = summary.get("database")
    if isinstance(database, dict) and "url" in database:
        database["url"] = REDACTED
    return summary
