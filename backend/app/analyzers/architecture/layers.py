"""Layer inference and layer-violation detection (TASK-129).

RepoLens never forces a repository into a predefined layered architecture
(ARCH-REQ-065/069). Layers are inferred only from directory and module-name
keywords using the documented mapping below, with deterministic precedence:
the deepest path component carrying a keyword wins (the filename stem counts
as the deepest component); directory evidence outranks nothing — it simply
participates by depth. No keyword anywhere means ``unknown``.

Permitted dependency direction (documented convention for V1.0, from the
docs/08 §6.8 illustration): presentation → application → domain →
infrastructure (downward or same-layer edges are consistent). An edge
running upward is a *possible* layer violation — an evidence-based
observation, never a verdict (ARCH-REQ-070). Findings are per violating
relationship (ARCH-REQ-071), confidence never High on naming evidence
(ARCH-REQ-068), and the rule is not evaluated (with an explicit limitation,
never clean) when fewer than two distinct layers are identifiable
(ARCH-REQ-066).
"""

from __future__ import annotations

from dataclasses import dataclass

from app.analyzers.architecture.models import ArchGraph

PRESENTATION = "presentation"
APPLICATION = "application"
DOMAIN = "domain"
INFRASTRUCTURE = "infrastructure"
UNKNOWN = "unknown"

#: Rank order: dependencies may flow downward (increasing rank) or stay level.
LAYER_RANK = {PRESENTATION: 0, APPLICATION: 1, DOMAIN: 2, INFRASTRUCTURE: 3}

#: Directory/filename keywords per layer (disjoint sets, deterministic).
LAYER_KEYWORDS: dict[str, frozenset[str]] = {
    PRESENTATION: frozenset(
        {"presentation", "ui", "view", "views", "web", "frontend", "templates", "static"}
    ),
    APPLICATION: frozenset(
        {
            "application",
            "app",
            "service",
            "services",
            "usecase",
            "usecases",
            "controller",
            "controllers",
            "handler",
            "handlers",
            "routes",
            "api",
        }
    ),
    DOMAIN: frozenset({"domain", "model", "models", "entity", "entities", "core", "business"}),
    INFRASTRUCTURE: frozenset(
        {
            "infrastructure",
            "infra",
            "repository",
            "repositories",
            "db",
            "database",
            "persistence",
            "dao",
            "storage",
            "external",
            "adapters",
            "migrations",
        }
    ),
}

_KEYWORD_TO_LAYER = {
    keyword: layer for layer, keywords in LAYER_KEYWORDS.items() for keyword in keywords
}


@dataclass(frozen=True)
class LayerAssignment:
    """One module's inferred layer plus the evidence that produced it."""

    module: str
    layer: str  # one of the four layers or "unknown"
    evidence: str  # e.g. "directory 'services'" or "no layer keyword found"
    from_filename: bool = False


def infer_layer(path: str) -> LayerAssignment:
    """Infer a layer from path components (deepest keyword wins)."""
    parts = [part for part in path.replace("\\", "/").split("/") if part not in ("", ".")]
    stem = parts[-1] if parts else ""
    if "." in stem:
        stem = stem.rsplit(".", 1)[0]
    components = parts[:-1] + [stem]
    for depth in range(len(components) - 1, -1, -1):
        component = components[depth].lower()
        tokens = {component} | set(component.replace("-", "_").split("_"))
        for token in sorted(tokens):
            layer = _KEYWORD_TO_LAYER.get(token)
            if layer is not None:
                if depth == len(components) - 1:
                    return LayerAssignment(
                        module=path,
                        layer=layer,
                        evidence=f"module name {components[depth]!r}",
                        from_filename=True,
                    )
                return LayerAssignment(
                    module=path,
                    layer=layer,
                    evidence=f"directory {components[depth]!r}",
                )
    return LayerAssignment(module=path, layer=UNKNOWN, evidence="no layer keyword found")


def infer_layers(paths: list[str]) -> dict[str, LayerAssignment]:
    """Infer layers for every module path (deterministic input order)."""
    return {path: infer_layer(path) for path in sorted(paths)}


@dataclass(frozen=True)
class LayerViolation:
    """One upward dependency relationship with layer evidence."""

    source: str
    target: str
    source_layer: str
    target_layer: str
    source_evidence: str
    target_evidence: str


def find_violations(
    graph: ArchGraph, assignments: dict[str, LayerAssignment]
) -> tuple[list[LayerViolation], bool]:
    """Find upward edges between known layers.

    Returns (violations, layers_identifiable): the flag is False when fewer
    than two distinct known layers exist, in which case the rule must be
    recorded as not evaluated rather than clean (ARCH-REQ-066).
    """
    known = {path for path, item in assignments.items() if item.layer != UNKNOWN}
    distinct = {assignments[path].layer for path in known}
    if len(distinct) < 2:
        return [], False
    violations: list[LayerViolation] = []
    for edge in graph.sorted_edges():
        source_item = assignments.get(edge.source)
        target_item = assignments.get(edge.target)
        if source_item is None or target_item is None:
            continue
        if source_item.layer == UNKNOWN or target_item.layer == UNKNOWN:
            continue
        if LAYER_RANK[source_item.layer] > LAYER_RANK[target_item.layer]:
            violations.append(
                LayerViolation(
                    source=edge.source,
                    target=edge.target,
                    source_layer=source_item.layer,
                    target_layer=target_item.layer,
                    source_evidence=source_item.evidence,
                    target_evidence=target_item.evidence,
                )
            )
    return violations, True
