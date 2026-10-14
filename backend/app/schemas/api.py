"""Public API request schemas (TASK-168, docs/17 §4.1).

Schemas validate shape only; domain validation (URL form, branch/commit
resolution, accessibility) happens in endpoints through the existing
repository services so contract error codes stay exact.
"""

from __future__ import annotations

from pydantic import BaseModel


class AnalysisCreateRequest(BaseModel):
    """Submit a public repository for analysis (docs/17 §4.1)."""

    url: str
    branch: str | None = None
    commit: str | None = None
