"""OSV advisory integration for dependency analysis (TASK-119/120).

Analyzer-facing surface over the infrastructure gateway
(:mod:`app.services.osv_gateway`, which owns the HTTP contract, timeouts,
and retries). This module holds only the pure, network-free pieces used by
the analyzer: the OSV ecosystem mapping, exact-version query building, and
re-exports of the gateway types. No ``httpx`` import lives in this package
(analyzer network boundary); advisory matching itself runs through the
injected gateway client.
"""

from __future__ import annotations

from collections.abc import Sequence

from app.analyzers.dependency.models import Advisory
from app.services.osv_gateway import (
    MAX_BATCH_QUERIES,
    OSV_BASE_URL,
    OSV_ECOSYSTEMS,
    OsvClient,
    OsvOutcome,
    OsvQuery,
    osv_client_from_network_settings,
    parse_advisory,
)


def build_queries(
    occurrences: Sequence[object],
) -> tuple[list[OsvQuery], dict[int, str]]:
    """Build deduplicated exact-version queries; report skipped occurrences.

    Returns ``(queries, skipped)`` where ``skipped`` maps occurrence index
    to the reason it was not queried (unknown version, unsupported
    ecosystem, empty version). Query order is deterministic.
    """
    queries: list[OsvQuery] = []
    skipped: dict[int, str] = {}
    seen: set[tuple[str, str, str]] = set()
    for index, occ in enumerate(occurrences):
        ecosystem = getattr(occ, "ecosystem", "")
        version = getattr(occ, "resolved_version", None)
        name = getattr(occ, "canonical_name", "") or ""
        if ecosystem not in OSV_ECOSYSTEMS:
            skipped[index] = f"unsupported ecosystem {ecosystem!r}; not queried"
            continue
        if not version or not str(version).strip():
            skipped[index] = "no exact resolved version; range is never sent as exact"
            continue
        triple = (ecosystem, name, str(version).strip())
        if triple in seen:
            continue
        seen.add(triple)
        queries.append(
            OsvQuery(ecosystem=ecosystem, package_name=name, version=str(version).strip())
        )
    queries.sort(key=lambda q: (q.ecosystem, q.package_name, q.version))
    return queries, skipped


def advisory_status(outcome: OsvOutcome, query_count: int) -> str | None:
    """Derive the advisory-data consultation status from a raw OSV outcome.

    Returns the persisted vocabulary validated by ``ADVISORY_STATUSES``
    (docs/13 §4.3, docs/12 §4): ``succeeded`` when every eligible query was
    assessed,     ``partly succeeded`` when only some could be (including truncated
    hydrations that still yielded associations), and
    ``unavailable`` when the advisory service could not provide anything.
    ``None`` means OSV was never consulted (no eligible query), which is
    the only case that maps to ``advisory_data: null`` — never a false
    clean result (PIPE-REQ-042).
    """
    if query_count <= 0:
        return None
    failed = sum(1 for position in outcome.failed_indexes if 0 <= position < query_count)
    if failed == 0:
        return "succeeded"
    obtained = any(outcome.advisories.get(position) for position in range(query_count))
    if failed >= query_count and not obtained:
        return "unavailable"
    return "partly succeeded"


__all__ = [
    "Advisory",
    "MAX_BATCH_QUERIES",
    "OSV_BASE_URL",
    "OSV_ECOSYSTEMS",
    "OsvClient",
    "OsvOutcome",
    "OsvQuery",
    "advisory_status",
    "build_queries",
    "osv_client_from_network_settings",
    "parse_advisory",
]
