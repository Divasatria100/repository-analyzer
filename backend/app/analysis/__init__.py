"""Production analysis pipeline package (VS-003 → VS-004).

Exposes the single post-ingestion orchestrator that drives parsing, the
Normalized Code Model, the four analyzer domains, aggregation, persistence,
and snapshot sealing.
"""

from __future__ import annotations

from app.analysis.pipeline import run_analysis_pipeline

__all__ = ["run_analysis_pipeline"]
