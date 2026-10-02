"""Bounded security evidence (TASK-096).

Findings carry a redacted source excerpt around the sink location built
from the same bounded lines the rules inspected — never a whole file.
The window follows the frozen ``OperationalSettings`` values (cited,
never redefined here):

* 10 lines before the finding (``evidence.context_lines_each_side``),
* 40 lines after the finding (``evidence.max_excerpt_lines``).

A single-line finding therefore yields at most 51 lines
(10 + 1 + 40); the absolute cap binds only multi-line focus spans, and
the finding lines are always preserved (over-cap windows trim with
``truncated=True``).

Every line passes through :func:`app.analyzers.redaction.mask_secrets`;
excerpts containing masked values set ``redacted=True``. When source is
unavailable the builder returns ``None`` so the caller records an
explicit limitation instead of failing or fabricating context.
"""

from __future__ import annotations

from app.analyzers.findings import Evidence
from app.analyzers.redaction import mask_secrets

#: Frozen window: lines of context before the focus span.
EVIDENCE_LINES_BEFORE = 10

#: Frozen window: lines of context after the focus span.
EVIDENCE_LINES_AFTER = 40

#: Absolute cap: 10 + 1 + 40. Binds only multi-line focus spans; a
#: single-line finding always keeps its full 10-before/40-after window.
EVIDENCE_MAX_EXCERPT_LINES = EVIDENCE_LINES_BEFORE + 1 + EVIDENCE_LINES_AFTER


def build_security_evidence(
    *,
    path: str,
    focus_start_line: int,
    focus_end_line: int,
    lines: tuple[str, ...] | list[str] | None,
) -> Evidence | None:
    """Build a bounded, redacted excerpt, or ``None`` when unavailable."""
    if lines is None or not lines:
        return None
    if focus_start_line < 1 or focus_end_line < focus_start_line:
        return None
    if focus_end_line > len(lines):
        return None
    start = max(1, focus_start_line - EVIDENCE_LINES_BEFORE)
    end = min(len(lines), focus_end_line + EVIDENCE_LINES_AFTER)
    window = list(lines[start - 1 : end])
    truncated = False
    if len(window) > EVIDENCE_MAX_EXCERPT_LINES:
        window, truncated = _truncate_to_cap(window, focus_start_line, focus_end_line, start)
    redacted_lines: list[str] = []
    redacted = False
    for line in window:
        masked, had_secret = mask_secrets(line)
        redacted_lines.append(masked)
        redacted = redacted or had_secret
    return Evidence(
        path=path,
        start_line=start,
        end_line=start + len(window) - 1,
        lines=tuple(redacted_lines),
        truncated=truncated,
        redacted=redacted,
    )


def _truncate_to_cap(
    window: list[str],
    focus_start: int,
    focus_end: int,
    window_start: int,
) -> tuple[list[str], bool]:
    """Trim an over-cap window, always preserving the finding lines."""
    focus_from = focus_start - window_start
    focus_to = focus_end - window_start
    before = window[:focus_from]
    focus = window[focus_from : focus_to + 1]
    after = window[focus_to + 1 :]
    remaining = max(0, EVIDENCE_MAX_EXCERPT_LINES - len(focus))
    keep_after_count = min(len(after), remaining // 2)
    keep_before_count = min(len(before), remaining - keep_after_count)
    trimmed = before[len(before) - keep_before_count :] + focus + after[:keep_after_count]
    return trimmed, True
