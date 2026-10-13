"""Direct/transitive classification over static evidence (TASK-115).

A dependency explicitly declared in a manifest is direct for that context.
A lockfile entry that is not declared in any manifest of the same project
context is transitive only when the lockfile records relationships that
support the conclusion. Guesses are never made: without supporting data
the classification stays unknown and the provenance is preserved.
"""

from __future__ import annotations

from app.analyzers.dependency.identity import identity_key
from app.analyzers.dependency.models import (
    DependencyClass,
    DependencyOccurrence,
    ManifestOutcome,
)


def classify_occurrences(outcomes: list[ManifestOutcome]) -> list[DependencyOccurrence]:
    """Resolve UNKNOWN lockfile classes against manifest declarations.

    Rules (evidence-based, deterministic):
    * manifest declarations are always direct;
    * a lockfile entry whose identity is declared direct in the same
      project context is direct for that context (kept as its own
      occurrence; the lockfile occurrence is marked direct);
    * a lockfile entry that appears as a recorded child in the same
      project context's relationships is transitive;
    * anything else stays unknown with its provenance preserved.
    """
    direct_keys: dict[str, set[str]] = {}
    child_keys: dict[str, set[str]] = {}
    for outcome in outcomes:
        context = outcome.ref.project_context
        ecosystem = outcome.ref.ecosystem
        if outcome.ref.kind == "manifest":
            direct_keys.setdefault(context, set()).update(
                identity_key(ecosystem, occ.original_name) for occ in outcome.occurrences
            )
        for relation in outcome.relationships:
            child_keys.setdefault(context, set()).add(identity_key(ecosystem, relation.child))
    classified: list[DependencyOccurrence] = []
    for outcome in outcomes:
        for occ in outcome.occurrences:
            if outcome.ref.kind == "manifest":
                classified.append(_replace_class(occ, DependencyClass.DIRECT))
                continue
            key = identity_key(occ.ecosystem, occ.original_name)
            context = occ.project_context
            if key in direct_keys.get(context, set()):
                classified.append(_replace_class(occ, DependencyClass.DIRECT))
            elif key in child_keys.get(context, set()):
                classified.append(_replace_class(occ, DependencyClass.TRANSITIVE))
            elif _is_top_level_lockfile_node(outcome, occ.original_name):
                # A lockfile node with no recorded parent in a context that
                # has no relationships at all: unknown, never fabricated.
                classified.append(_replace_class(occ, DependencyClass.UNKNOWN))
            else:
                classified.append(occ)
    return classified


def _is_top_level_lockfile_node(outcome: ManifestOutcome, name: str) -> bool:
    if not outcome.relationships:
        return True
    key = identity_key(outcome.ref.ecosystem, name)
    children = {
        identity_key(outcome.ref.ecosystem, relation.child) for relation in outcome.relationships
    }
    return key not in children


def _replace_class(
    occ: DependencyOccurrence, dependency_class: DependencyClass
) -> DependencyOccurrence:
    return DependencyOccurrence(
        ecosystem=occ.ecosystem,
        canonical_name=occ.canonical_name,
        original_name=occ.original_name,
        constraint=occ.constraint,
        resolved_version=occ.resolved_version,
        source_file=occ.source_file,
        project_context=occ.project_context,
        section=occ.section,
        dependency_class=dependency_class,
        runtime_context=occ.runtime_context,
        source_line=occ.source_line,
        support_state=occ.support_state,
        kind=occ.kind,
    )
