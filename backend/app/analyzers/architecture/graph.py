"""Architecture graph construction from NCM (TASK-124).

Direction (ARCH-REQ-013/019, frozen): an edge runs from the dependent unit
to the unit it depends on — importing module → imported module. The same
convention drives fan-out (successors), fan-in (predecessors), coupling,
cycles, layer violations, and serialization.

Semantics:

* Internal edges only between parsed modules (ARCH-REQ-014). Parser-marked
  ``external`` references are counted as external diagnostics, never edges.
  Anything that cannot be mapped to a parsed module is recorded unresolved
  (ARCH-REQ-015) — never converted, never silently discarded.
* One directed edge per ordered pair (ARCH-REQ-016); every establishing
  import site is preserved on the edge as evidence (ARCH-REQ-092).
* Self-loops are preserved as edges with explicit effects defined in
  metrics.py (excluded from neighbor sets) and cycles.py (single-node
  cycle findings).
* Node/edge budgets come from the frozen operational configuration; the
  defaults below mirror ``OperationalSettings`` and are asserted equal to
  it in tests. Breaching a budget truncates deterministically (path order)
  and records incompleteness (PIPE-REQ-089) — never a silent complete graph.
"""

from __future__ import annotations

import logging

from app.analyzers.architecture.models import (
    ArchEdge,
    ArchGraph,
    ExtractionReport,
    UnresolvedImport,
)
from app.analyzers.architecture.modules import extract_modules
from app.analyzers.architecture.resolve import resolve_import
from app.core.logging import get_logger, log_event
from app.ncm import ImportRef, NcmRepository

_logger = get_logger("analyzers.architecture.graph")

#: Frozen graph budgets, mirroring ``OperationalSettings`` (single source of
#: truth there; equality is asserted in tests, never redefined here lightly).
GRAPH_MAX_NODES = 10000
GRAPH_MAX_EDGES = 50000


def _import_level(target: str, ref: ImportRef) -> int:
    if ref.is_relative:
        dots = 0
        for char in target:
            if char != ".":
                break
            dots += 1
        return max(dots, 1)
    return 0


def build_graph(
    ncm: NcmRepository,
    *,
    max_nodes: int = GRAPH_MAX_NODES,
    max_edges: int = GRAPH_MAX_EDGES,
) -> ExtractionReport:
    """Build the directed architecture graph from an NCM snapshot."""
    modules, diagnostics = extract_modules(ncm)
    known = set(modules)
    by_path = {entry.path: entry.module for entry in ncm.files if entry.module is not None}
    graph = ArchGraph(nodes=dict(modules))
    unresolved: list[UnresolvedImport] = []
    external_count = 0
    limited = False
    limitation_reasons: list[str] = list(diagnostics.reasons())

    if len(graph.nodes) > max_nodes:
        limited = True
        limitation_reasons.append(
            f"graph node budget ({max_nodes}) exceeded; modules beyond the budget "
            "are not analyzed and are not treated as clean"
        )
        kept = sorted(graph.nodes)[:max_nodes]
        graph.nodes = {key: graph.nodes[key] for key in kept}
        graph.truncated = True
        graph.truncation_reason = f"node budget {max_nodes} exceeded"
        known = set(graph.nodes)

    edge_count = 0
    for path in sorted(known):
        module = by_path.get(path)
        if module is None:
            continue
        imports = sorted(
            module.imports, key=lambda ref: (ref.location.start_line, ref.location.start_column)
        )
        for ref in imports:
            if ref.resolution == "external":
                external_count += 1
                continue
            target_path = resolve_import(
                ref.target_text,
                is_relative=ref.is_relative,
                level=_import_level(ref.target_text, ref),
                importer_path=path,
                known=known,
            )
            if target_path is None:
                reason = "unresolved" if ref.resolution != "internal" else "unmapped-internal"
                unresolved.append(
                    UnresolvedImport(
                        path=path,
                        target_text=ref.target_text,
                        reason=reason,
                        line=ref.location.start_line,
                        column=ref.location.start_column,
                    )
                )
                continue
            key = (path, target_path)
            existing = graph.edges.get(key)
            site = (path, ref.location.start_line, ref.location.start_column)
            if existing is None:
                if edge_count >= max_edges:
                    limited = True
                    limitation_reasons.append(
                        f"graph edge budget ({max_edges}) exceeded; further relationships "
                        "are not analyzed and are not treated as clean"
                    )
                    graph.truncated = True
                    graph.truncation_reason = f"edge budget {max_edges} exceeded"
                    break
                graph.edges[key] = ArchEdge(
                    source=path,
                    target=target_path,
                    locations=(site,),
                    conditional=ref.is_conditional,
                    deferred=ref.is_deferred,
                )
                edge_count += 1
            else:
                locations = tuple(sorted(set(existing.locations) | {site}))
                graph.edges[key] = ArchEdge(
                    source=existing.source,
                    target=existing.target,
                    locations=locations,
                    conditional=existing.conditional or ref.is_conditional,
                    deferred=existing.deferred or ref.is_deferred,
                )
        if graph.truncated and edge_count >= max_edges:
            break

    graph.freeze_index()
    unresolved.sort(key=lambda item: (item.path, item.line, item.column, item.target_text))
    if unresolved:
        limitation_reasons.append(
            f"{len(unresolved)} import reference(s) could not be resolved to internal "
            "modules; metrics that depend on them are potentially incomplete"
        )
    if diagnostics.incomplete:
        limited = True
    log_event(
        _logger,
        logging.INFO,
        "architecture.graph.built",
        "Architecture graph built",
        modules=len(graph.nodes),
        edges=len(graph.edges),
        unresolved=len(unresolved),
    )
    return ExtractionReport(
        graph=graph,
        unresolved=tuple(unresolved),
        external_count=external_count,
        skipped_files=tuple(diagnostics.skipped_files),
        partial_modules=tuple(diagnostics.partial_modules),
        failed_files=tuple(diagnostics.failed_files),
        unsupported_files=tuple(diagnostics.unsupported_files),
        limited=limited or graph.truncated,
        limitation_reasons=tuple(limitation_reasons),
    )
