"""Persistence gateway for the file index (docs/12 §4.3, §4.9).

Saves File + Limitation rows atomically: callers commit (or roll back on
failure) via their own transaction scope. Vocabulary is validated here so
invalid states fail fast instead of persisting silently.
"""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.indexing import (
    ELIGIBILITY_VALUES,
    FILE_TYPES,
    SUPPORT_STATUSES,
    File,
    Limitation,
)
from app.parsers.result import ParseState
from app.repository.index_types import IndexedFile, LimitationRecord


def save_index(
    session: Session,
    analysis_id: str,
    files: list[IndexedFile],
    limitations: list[LimitationRecord],
) -> None:
    """Persist one complete index pass (all rows or none on failure)."""
    for item in files:
        if item.file_type not in FILE_TYPES:
            raise ValueError(f"Unknown file type: {item.file_type}")
        if item.support_status not in SUPPORT_STATUSES:
            raise ValueError(f"Unknown support status: {item.support_status}")
        if item.eligibility not in ELIGIBILITY_VALUES:
            raise ValueError(f"Unknown eligibility: {item.eligibility}")
        session.add(
            File(
                analysis_id=analysis_id,
                path=item.relative_path,
                file_type=item.file_type,
                extension=item.extension,
                size=item.size,
                language=item.language,
                support_status=item.support_status,
                is_binary=item.is_binary,
                is_generated=item.is_generated,
                excluded=item.excluded,
                exclusion_reason=item.exclusion_reason,
                eligibility=item.eligibility,
                eligibility_reason=item.eligibility_reason,
                parse_result=None,
                indexing_limitation=item.indexing_limitation,
            )
        )
    for limitation in limitations:
        session.add(
            Limitation(
                analysis_id=analysis_id,
                scope_kind=limitation.scope_kind,
                file_path=limitation.file_path,
                reason=limitation.reason,
            )
        )
    session.flush()


def get_files(session: Session, analysis_id: str) -> list[File]:
    """Load an analysis' file rows in stable path order (deterministic)."""
    return list(
        session.scalars(
            select(File).where(File.analysis_id == analysis_id).order_by(File.path)
        ).all()
    )


def get_limitations(session: Session, analysis_id: str) -> list[Limitation]:
    """Load an analysis' limitation rows in stable order (deterministic)."""
    return list(
        session.scalars(
            select(Limitation)
            .where(Limitation.analysis_id == analysis_id)
            .order_by(Limitation.scope_kind, Limitation.file_path)
        ).all()
    )


PARSE_RESULT_VALUES = frozenset(
    {
        ParseState.PARSED.value,
        ParseState.PARSED_WITH_DIAGNOSTICS.value,
        ParseState.FAILED.value,
    }
)


def update_parse_result(
    session: Session,
    file_id: str,
    state: ParseState,
    diagnostics: list[dict[str, object]],
) -> None:
    """Record one file's parse outcome + structured diagnostics.

    ``unsupported`` is never a ``parse_result`` value: files without an
    adapter keep ``parse_result`` NULL with their support status intact.
    Diagnostics are bounded structured data (severity/message/location),
    never source text.
    """
    if state not in (
        ParseState.PARSED,
        ParseState.PARSED_WITH_DIAGNOSTICS,
        ParseState.FAILED,
    ):
        raise ValueError(f"Not a persistable parse state: {state}")
    row = session.get(File, file_id)
    if row is None:
        raise ValueError(f"Unknown file id: {file_id}")
    row.parse_result = state.value
    row.diagnostics = diagnostics
    session.flush()
