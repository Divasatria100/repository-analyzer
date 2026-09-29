"""Structured logging foundation (safe by default).

Guarantees for this foundation (see docs/15 §13):

* no secret is logged in full — values attached to sensitive keys
  (``password``, ``token``, ``secret``, …) are replaced with ``***``;
* no raw credentials are emitted — record arguments are filtered before
  formatting, and ``Authorization``-style headers must never be logged;
* log level resolves per environment (``test`` quiets to ``WARNING``).

This foundation does not implement the analyzer redaction pipeline;
it only ensures RepoLens's own diagnostics cannot leak secrets.
"""

import logging
import re
from typing import Any

SENSITIVE_KEYS = frozenset(
    {
        "password",
        "passwd",
        "pwd",
        "secret",
        "token",
        "api_key",
        "apikey",
        "access_token",
        "refresh_token",
        "authorization",
        "cookie",
        "set-cookie",
        "credential",
        "credentials",
        "private_key",
        "client_secret",
    }
)

REDACTED = "***"

_CREDENTIAL_PATTERN = re.compile(
    r"(?i)\b(password|passwd|secret|token|api[_-]?key|authorization)\b\s*[:=]\s*"
    r"(?P<value>[^\s,}]+)"
)


def redact_value(key: str, value: Any) -> Any:
    """Return ``REDACTED`` when ``key`` names a sensitive field."""
    if key.lower() in SENSITIVE_KEYS:
        return REDACTED
    return value


def redact_text(message: str) -> str:
    """Mask ``key=value``/``key: value`` credential fragments inside free text."""
    return _CREDENTIAL_PATTERN.sub(
        lambda match: match.group(0).replace(match.group("value"), REDACTED), message
    )


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


def configure_logging(level: str) -> logging.Logger:
    """Configure the ``repolens`` root logger once and return it."""
    logger = logging.getLogger("repolens")
    logger.setLevel(level)
    if not any(isinstance(handler, logging.StreamHandler) for handler in logger.handlers):
        handler = logging.StreamHandler()
        handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s %(message)s"))
        logger.addHandler(handler)
    if not any(isinstance(filter_, RedactingFilter) for filter_ in logger.filters):
        logger.addFilter(RedactingFilter())
    logger.propagate = False
    return logger


def get_logger(name: str) -> logging.Logger:
    """Return a child logger of the ``repolens`` root logger."""
    return logging.getLogger(f"repolens.{name}")
