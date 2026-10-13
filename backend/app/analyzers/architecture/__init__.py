"""Architecture analysis domain (Phase 9, TASK-123–133).

Static architecture analysis over the Normalized Code Model: module
extraction, directed dependency graph, metrics (fan-in/out, coupling-def-1,
sizes, cycles, layers, responsibility signals), nine registered rules, and
deterministic serialization. NCM in, results out — no parsers, no
execution, no network.
"""

from app.analyzers.architecture.analyzer import (
    ArchitectureAnalyzer,
    build_architecture_rules,
)

__all__ = [
    "ArchitectureAnalyzer",
    "build_architecture_rules",
]
