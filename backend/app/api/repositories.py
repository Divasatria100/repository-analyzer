"""Repository endpoint (TASK-166; docs/17 §4.5).

Read-only repository identity plus analysis history. No ingestion, no
analysis, and no workspace access happens here as a side effect.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.common import get_repository_or_404, history_entry
from app.api.deps import get_db
from app.models.repository import Analysis

router = APIRouter()

#: Module-level dependency singleton (ruff B008: no calls in defaults).
_db = Depends(get_db)


@router.get("/repositories/{repository_id}")
def get_repository(repository_id: str, session: Session = _db) -> dict[str, object]:
    """Repository metadata with most-recent-first history (§4.5)."""
    repository = get_repository_or_404(session, repository_id)
    analyses = list(
        session.scalars(
            select(Analysis)
            .where(Analysis.repository_id == repository.id)
            .order_by(Analysis.created_at.desc(), Analysis.id.desc())
        ).all()
    )
    return {
        "repository_id": repository.id,
        "url": repository.normalized_url,
        "owner": repository.owner,
        "name": repository.name,
        "analyses": [history_entry(analysis) for analysis in analyses],
    }
