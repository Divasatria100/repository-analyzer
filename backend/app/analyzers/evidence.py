"""Bounded evidence builder (TASK-089).

Findings stay evidence-first without letting unbounded repository content
into findings, logs, or reports. Window: the finding's lines plus up to
``context_each_side`` surrounding lines each side (frozen default 10);
the whole excerpt is capped at ``max_excerpt_lines`` (frozen default 40),
finding lines always preserved. Values come from centralized
``OperationalSettings`` — never literals here.
"""

from __future__ import annotations

import os
import stat
from pathlib import Path

from app.analyzers.errors import EvidenceUnavailableError
from app.analyzers.findings import Evidence
from app.analyzers.redaction import mask_secrets
from app.repository.workspace import WorkspaceManager


def build_evidence(
    *,
    workspaces: WorkspaceManager,
    workspace: Path,
    relpath: str,
    focus_start_line: int,
    focus_end_line: int,
    context_each_side: int,
    max_excerpt_lines: int,
) -> Evidence:
    """Build a bounded, redacted excerpt around 1-based finding lines.

    Reads the workspace file as data (never executed, never imported).
    Raises :class:`EvidenceUnavailableError` when evidence cannot be
    obtained safely — callers record a limitation instead of crashing.
    """
    if focus_start_line < 1 or focus_end_line < focus_start_line:
        raise EvidenceUnavailableError("Invalid finding line range.")
    try:
        resolved = workspaces.resolve(workspace, relpath)
    except Exception as exc:
        raise EvidenceUnavailableError("Evidence path escapes the workspace.") from exc
    try:
        # lstat (never follows): symlinks and non-regular files are rejected
        # here even when their targets resolve inside the workspace.
        entry_stat = os.lstat(workspace / relpath)
    except OSError as exc:
        raise EvidenceUnavailableError("Evidence target is not accessible.") from exc
    if stat.S_ISLNK(entry_stat.st_mode) or not stat.S_ISREG(entry_stat.st_mode):
        raise EvidenceUnavailableError("Evidence target is not a regular file.")
    try:
        if resolved.is_symlink() or not resolved.is_file():
            raise EvidenceUnavailableError("Evidence target is not a regular file.")
        text = resolved.read_text(encoding="utf-8", errors="strict")
    except (OSError, ValueError, UnicodeDecodeError) as exc:
        raise EvidenceUnavailableError("Evidence file could not be read safely.") from exc
    lines = text.splitlines()
    if not lines:
        raise EvidenceUnavailableError("Evidence file is empty.")
    if focus_end_line > len(lines):
        raise EvidenceUnavailableError("Finding lines exceed file length.")
    start = max(1, focus_start_line - context_each_side)
    end = min(len(lines), focus_end_line + context_each_side)
    window = lines[start - 1 : end]
    truncated = False
    if len(window) > max_excerpt_lines:
        window, truncated = _truncate_to_cap(
            window, focus_start_line, focus_end_line, start, max_excerpt_lines
        )
    redacted_lines: list[str] = []
    redacted = False
    for line in window:
        masked, had_secret = mask_secrets(line)
        redacted_lines.append(masked)
        redacted = redacted or had_secret
    return Evidence(
        path=relpath,
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
    cap: int,
) -> tuple[list[str], bool]:
    """Trim an over-cap window, always preserving the finding lines."""
    focus_from = focus_start - window_start
    focus_to = focus_end - window_start
    before = window[:focus_from]
    focus = window[focus_from : focus_to + 1]
    after = window[focus_to + 1 :]
    remaining = max(0, cap - len(focus))
    keep_after_count = min(len(after), remaining // 2)
    keep_before_count = min(len(before), remaining - keep_after_count)
    trimmed = before[len(before) - keep_before_count :] + focus + after[:keep_after_count]
    return trimmed, True
