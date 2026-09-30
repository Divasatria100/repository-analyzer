"""Parse phase orchestration: eligible files in, NCM + states persisted.

Consumes Phase 4 File rows (eligibility + language + support already
decided — never rediscovered here). Each file resolves inside the
workspace, re-verifies size/containment/regular-file, parses in an
isolated worker, and records ``parse_result`` + structured diagnostics.
One file's failure never stops the rest; unexpected per-file errors are
recorded as failed with the error classification (never silently
swallowed, never internals).
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from pathlib import Path

from sqlalchemy.orm import Session

from app.core.config import Settings
from app.core.logging import get_logger, log_event, log_exception
from app.models.indexing import File
from app.parsers.ncm import NormalizedModule
from app.parsers.registry import get_adapter
from app.parsers.result import ParseResult, ParseState
from app.parsers.runner import run_adapter
from app.repositories import indexing as gateway
from app.repository.workspace import WorkspaceManager

_logger = get_logger("parsing")


@dataclass
class ParsePhaseResult:
    """Aggregate outcome plus in-memory NCM for future analyzers."""

    total: int = 0
    parsed: int = 0
    parsed_with_diagnostics: int = 0
    failed: int = 0
    unsupported: int = 0
    duration_ms: float = 0.0
    modules: dict[str, NormalizedModule] = field(default_factory=dict)


def _adapter_name_for(language: str | None) -> str | None:
    adapter = get_adapter(language) if language else None
    return adapter.name if adapter else None


def run_parse_phase(
    *,
    session: Session,
    analysis_id: str,
    workspace: Path,
    workspaces: WorkspaceManager,
    settings: Settings,
) -> ParsePhaseResult:
    """Parse every eligible supported file; persist states + diagnostics."""
    started = time.perf_counter()
    log_event(_logger, logging.INFO, "parsing.started", "Parsing started", analysis_id=analysis_id)
    operational = settings.operational
    max_bytes = operational.file_max_size_bytes
    timeout_s = operational.parse_file_timeout_s
    result = ParsePhaseResult()
    try:
        files = gateway.get_files(session, analysis_id)
    except Exception as exc:
        log_exception(_logger, "parsing.failed", exc, "Parsing failed loading file index")
        raise
    for row in files:
        parsed = _parse_one(
            session=session,
            row=row,
            workspace=workspace,
            workspaces=workspaces,
            max_bytes=max_bytes,
            timeout_s=timeout_s,
        )
        result.total += 1
        if parsed.state == ParseState.PARSED:
            result.parsed += 1
        elif parsed.state == ParseState.PARSED_WITH_DIAGNOSTICS:
            result.parsed_with_diagnostics += 1
        elif parsed.state == ParseState.FAILED:
            result.failed += 1
        else:
            result.unsupported += 1
        if parsed.ncm is not None:
            result.modules[row.id] = parsed.ncm
    # Second pass over persisted rows is unnecessary: modules were collected
    # from worker results held in memory during this run.
    result.duration_ms = (time.perf_counter() - started) * 1000.0
    log_event(
        _logger,
        logging.INFO,
        "parsing.completed",
        "Parsing completed",
        analysis_id=analysis_id,
        total=result.total,
        parsed=result.parsed,
        failed=result.failed,
        unsupported=result.unsupported,
    )
    return result


def _synthetic(adapter_name: str, state: ParseState, message: str, code: str) -> ParseResult:
    from app.parsers.ncm import Diagnostic

    return ParseResult(
        state=state,
        ncm=None,
        diagnostics=[
            Diagnostic(
                severity="error" if state == ParseState.FAILED else "info",
                message=message,
                location=None,
                parser=adapter_name,
                code=code,
            )
        ],
        parser_name=adapter_name,
    )


def _parse_one(
    *,
    session: Session,
    row: File,
    workspace: Path,
    workspaces: WorkspaceManager,
    max_bytes: int,
    timeout_s: float,
) -> ParseResult:
    """Parse a single File row with full input-boundary enforcement."""
    relative_path = row.path
    language = row.language
    adapter_name = _adapter_name_for(language) or "none"
    if (
        row.eligibility != "eligible"
        or row.support_status != "supported"
        or _adapter_name_for(language) is None
    ):
        # Unsupported/unrecognized/binary/ineligible: recorded state, not failure.
        return _synthetic(
            adapter_name, ParseState.UNSUPPORTED, "No parser for this file.", "unsupported"
        )
    try:
        resolved = workspaces.resolve(workspace, relative_path)
    except Exception as exc:
        parsed = _synthetic(
            adapter_name,
            ParseState.FAILED,
            "File path could not be resolved inside the workspace.",
            "unresolvable-path",
        )
        gateway.update_parse_result(
            session, row.id, parsed.state, [d.to_dict() for d in parsed.diagnostics]
        )
        log_exception(_logger, "parsing.failed", exc, "File path unresolvable", file_id=row.id)
        return parsed
    try:
        if resolved.is_symlink() or not resolved.is_file():
            raise ValueError("not-a-regular-file")
        size = resolved.stat().st_size
        if size > max_bytes:
            raise ValueError("over-limit")
        source = resolved.read_bytes()
    except (OSError, ValueError) as exc:
        parsed = _synthetic(
            adapter_name, ParseState.FAILED, "File could not be read for parsing.", "unreadable"
        )
        gateway.update_parse_result(
            session, row.id, parsed.state, [d.to_dict() for d in parsed.diagnostics]
        )
        log_exception(_logger, "parsing.failed", exc, "File unreadable", file_id=row.id)
        return parsed
    try:
        parsed = run_adapter(adapter_name, language or "", relative_path, source, timeout_s)
    except Exception as exc:
        # Runner contract says no raises, but a file must never take the phase.
        parsed = _synthetic(
            adapter_name,
            ParseState.FAILED,
            f"Parser infrastructure failed ({type(exc).__name__}).",
            "infrastructure",
        )
        gateway.update_parse_result(
            session, row.id, parsed.state, [d.to_dict() for d in parsed.diagnostics]
        )
        log_exception(
            _logger, "parsing.failed", exc, "Parser infrastructure failed", file_id=row.id
        )
        return parsed
    gateway.update_parse_result(
        session,
        row.id,
        parsed.state,
        [d.to_dict() for d in parsed.diagnostics],
    )
    return parsed
