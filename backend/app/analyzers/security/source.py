"""Bounded source access for security rules (TASK-096 support).

Security rules consume NCM plus approved analyzer-layer data. NCM
deliberately records call shapes (``callee_text`` + ``argument_count``)
and assignment targets (names only) without argument expressions or
values, so confirming what reaches a sink requires looking at the
already-located source lines. This module provides that narrow,
read-as-data access:

* :class:`SourceProvider` — protocol returning source lines for a
  repository-relative path (``None`` when unavailable).
* :class:`DictSourceProvider` — in-memory provider (tests, deterministic).
* :class:`WorkspaceSourceProvider` — workspace-backed provider (bounded,
  symlink-aware, read as data; never executed, never imported).

Text utilities (string masking, comment stripping, parenthesis-balanced
extraction) operate on plain strings with the stdlib ``re`` module only.
No ``ast``, no tree-sitter, no ``app.parsers`` imports — there is no
second code representation here, only bounded string inspection around
NCM-located sinks.
"""

from __future__ import annotations

import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

#: Hard cap on bytes read for one source file (mirrors the frozen
#: ``file.max_size_bytes`` default; cited, never silently raised).
MAX_SOURCE_BYTES = 1024 * 1024

#: Maximum lines accumulated while balancing one multi-line construct.
MAX_SPAN_LINES = 30

#: Maximum lines scanned backwards for local assignments.
MAX_SCOPE_LINES = 200

_STRING_RE = re.compile(r"'''(?:[^\\]|\\.)*?'''|\"\"\"(?:[^\\]|\\.)*?\"\"\"|'[^'\n]*'|\"[^\"\n]*\"")


@dataclass(frozen=True)
class SourceFile:
    """Bounded source lines for one repository-relative path (data only)."""

    path: str
    lines: tuple[str, ...]

    def __len__(self) -> int:
        return len(self.lines)


class SourceProvider(Protocol):
    """Narrow source access: lines for a path, or ``None`` when unavailable."""

    def read(self, path: str) -> SourceFile | None:
        """Return bounded source lines, or ``None`` (recorded, never clean)."""
        raise NotImplementedError


class DictSourceProvider:
    """In-memory provider over ``{path: text}`` (tests and integration)."""

    def __init__(self, files: dict[str, str]) -> None:
        self._files = dict(files)

    def read(self, path: str) -> SourceFile | None:
        """Return lines for ``path`` (bounded), or ``None`` when unknown."""
        text = self._files.get(path)
        if text is None:
            return None
        lines = text.splitlines()[: MAX_SOURCE_BYTES // 40]
        return SourceFile(path=path, lines=tuple(lines))


class WorkspaceSourceProvider:
    """Workspace-backed provider: bounded read-as-data through the manager."""

    def __init__(self, workspaces: object, workspace: Path) -> None:
        self._workspaces = workspaces
        self._workspace = workspace

    def read(self, path: str) -> SourceFile | None:
        """Read bounded lines as data (symlinks/non-regular files rejected)."""
        resolve = getattr(self._workspaces, "resolve", None)
        if resolve is None:
            return None
        try:
            resolved = resolve(self._workspace, path)
        except Exception:
            return None
        try:
            entry_stat = os.lstat(self._workspace / path)
        except OSError:
            return None
        if stat.S_ISLNK(entry_stat.st_mode) or not stat.S_ISREG(entry_stat.st_mode):
            return None
        try:
            if resolved.is_symlink() or not resolved.is_file():
                return None
            if resolved.stat().st_size > MAX_SOURCE_BYTES:
                return None
            text = resolved.read_text(encoding="utf-8", errors="strict")
        except (OSError, ValueError, UnicodeDecodeError):
            return None
        return SourceFile(path=path, lines=tuple(text.splitlines()))


def mask_strings(text: str) -> str:
    """Replace string literal contents with a placeholder (shape preserved)."""

    def _placeholder(match: re.Match[str]) -> str:
        token = match.group(0)
        if len(token) >= 6 and token[:3] in ("'''", '"""'):
            return token[:3] + token[-3:]
        quote = token[0]
        prefix = ""
        body = token[1:]
        if body[:1].lower() in ("r", "u", "b", "f"):
            prefix = body[0]
            body = body[1:]
            if body[:1].lower() in ("r", "b", "u"):
                prefix += body[0]
                body = body[1:]
        if prefix.lower().startswith("f") or "f" in prefix.lower():
            return prefix + quote + quote
        return prefix + quote + quote

    return _STRING_RE.sub(_placeholder, text)


def strip_comment(line: str) -> str:
    """Remove a trailing ``#`` comment (naive; applied after masking)."""
    masked = mask_strings(line)
    index = masked.find("#")
    if index == -1:
        return line
    return line[:index]


def structure_mask(text: str) -> str:
    """Replace string literals with equal-length blanks (offsets preserved).

    Unlike :func:`mask_strings`, the output length always equals the input
    length, so index-based structural scanning (parenthesis balance,
    argument splitting) stays aligned with the original text. Quotes are
    blanked too, so a ``#`` in the masked text always starts a comment.
    """
    return _STRING_RE.sub(lambda match: " " * len(match.group(0)), text)


def strip_structural_comment(line: str) -> str:
    """Cut a trailing comment using string-aware (length-preserving) masking."""
    masked = structure_mask(line)
    index = masked.find("#")
    return line[:index] if index != -1 else line


def balanced_span(lines: list[str], start_line: int, start_column: int) -> str:
    """Accumulate text from a 1-based position until parens balance (bounded).

    Strings and comments are excluded from balancing via
    :func:`structure_mask`, and the span is cut exactly at the closing
    delimiter. Stops after :data:`MAX_SPAN_LINES` lines.
    """
    collected: list[str] = []
    depth = 0
    started = False
    for offset in range(MAX_SPAN_LINES):
        index = start_line - 1 + offset
        if index < 0 or index >= len(lines):
            break
        raw = lines[index] if offset else lines[index][start_column:]
        masked = structure_mask(strip_structural_comment(raw))
        cut = len(raw)
        for position, char in enumerate(masked):
            if char in "([":
                depth += 1
                started = True
            elif char in ")]":
                depth -= 1
                if started and depth <= 0:
                    cut = position + 1
                    break
        collected.append(raw[:cut])
        if started and depth <= 0:
            break
    return "\n".join(collected)


def scope_lines(lines: list[str], focus_line: int, limit: int = MAX_SCOPE_LINES) -> list[str]:
    """Return up to ``limit`` lines preceding a 1-based focus line (bounded)."""
    start = max(0, focus_line - 1 - limit)
    return lines[start : focus_line - 1]
