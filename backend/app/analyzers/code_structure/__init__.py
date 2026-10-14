"""Code-structure analysis domain (Phase 10, TASK-135–144).

Static code-structure analysis over the Normalized Code Model: McCabe
complexity, nesting depth, parameter counts, duplicate candidates, four
registered rules, and review-ordered hotspots without scoring. NCM in,
results out — no second parser, no execution, no network.
"""

from app.analyzers.code_structure.analyzer import (
    CodeStructureAnalyzer,
    build_code_structure_rules,
)

__all__ = [
    "CodeStructureAnalyzer",
    "build_code_structure_rules",
]
