"""Bounded pagination contract (TASK-171, docs/17 §3.5).

``page`` is 1-based (default 1, minimum 1); ``page_size`` defaults to the
frozen configured default with a frozen maximum enforced server-side.
Any non-integer, out-of-range, or otherwise invalid value is a
``VALIDATION_ERROR`` (400) — never a silent cap or an unbounded result.
"""

from __future__ import annotations

from app.api.errors import ApiError
from app.core.config import Settings


def parse_pagination(
    settings: Settings,
    page_raw: str | None,
    page_size_raw: str | None,
) -> tuple[int, int]:
    """Validate raw pagination params against the frozen contract."""
    page = 1 if page_raw is None else _parse_int(page_raw)
    page_size = (
        settings.operational.api_page_size_default
        if page_size_raw is None
        else _parse_int(page_size_raw)
    )
    if page is None or page < 1:
        raise ApiError(
            "VALIDATION_ERROR", "Invalid pagination: page must be an integer of at least 1."
        )
    if page_size is None or page_size < 1 or page_size > settings.operational.api_page_size_max:
        raise ApiError(
            "VALIDATION_ERROR",
            "Invalid pagination: page_size must be an integer between 1 and "
            f"{settings.operational.api_page_size_max}.",
        )
    return page, page_size


def _parse_int(raw: str) -> int | None:
    """Strict integer parsing: booleans, floats, and text are invalid."""
    text = raw.strip()
    if not text or text[0] in "+-" and len(text) == 1:
        return None
    if text[0] == "+":
        text = text[1:]
    if not text.isdigit():
        return None
    try:
        return int(text)
    except ValueError:
        return None


def paginate(
    items: list[dict[str, object]], total: int, page: int, page_size: int
) -> dict[str, object]:
    """Slice an ordered collection into the contract page envelope."""
    start = (page - 1) * page_size
    return {
        "page": page,
        "page_size": page_size,
        "total": total,
        "items": items[start : start + page_size],
    }
