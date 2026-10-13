"""Deterministic architecture graph serialization (TASK-133).

JSON-compatible, sorted, bounded output for reporting and UI consumption
(PIPE-REQ-051): stable node/edge records, explicit metric fields with
availability states, and completeness records. Unknown metrics serialize as
``"unknown"``/``null`` with reasons — never as zero. No source content, no
secrets: only paths, identifiers, counts, and structural references.
"""

from __future__ import annotations

import json

from app.analyzers.architecture.cycles import CycleGroup
from app.analyzers.architecture.models import ArchGraph, ExtractionReport, MetricValue

#: Report-size guard for serialized graphs (bounded text, never truncated silently
#: without the completeness record below stating it).
SERIALIZATION_MAX_CHARS = 1024 * 1024


def serialize_metrics(values: list[MetricValue]) -> list[dict[str, object]]:
    """Serialize metrics in stable (name, subject) order with availability."""
    ordered = sorted(values, key=lambda item: (item.name, item.subject))
    records: list[dict[str, object]] = []
    for item in ordered:
        record: dict[str, object] = {
            "metric": item.name,
            "subject": item.subject,
            "value": item.value if item.value is not None else None,
            "availability": "available" if item.value is not None else "unknown",
            "potentially_incomplete": item.potentially_incomplete,
            "basis": item.basis,
        }
        records.append(record)
    return records


def serialize_graph(graph: ArchGraph) -> dict[str, object]:
    """Serialize nodes and edges in stable sorted order (no duplicates)."""
    return {
        "nodes": [
            {
                "id": node.id,
                "path": node.path,
                "language": node.language,
                "partially_represented": node.partially_represented,
            }
            for node in graph.sorted_nodes()
        ],
        "edges": [
            {
                "source": edge.source,
                "target": edge.target,
                "locations": [
                    {"path": path, "line": line, "column": column}
                    for path, line, column in edge.locations
                ],
                "conditional": edge.conditional,
                "deferred": edge.deferred,
            }
            for edge in graph.sorted_edges()
        ],
        "truncated": graph.truncated,
        "truncation_reason": graph.truncation_reason,
    }


def serialize_cycles(groups: list[CycleGroup]) -> list[dict[str, object]]:
    """Serialize cycle groups (unit counted: groups, per ARCH-REQ-033)."""
    ordered = sorted(groups, key=lambda group: (group.members, group.path))
    return [
        {
            "unit": "group",
            "members": list(group.members),
            "path": list(group.path),
            "self_loop": group.self_loop,
            "edge_count": group.edge_count,
        }
        for group in ordered
    ]


def serialize_report(
    report: ExtractionReport,
    *,
    metrics: list[MetricValue] | None = None,
    cycles: list[CycleGroup] | None = None,
    rule_set_version: str = "",
) -> dict[str, object]:
    """Serialize one extraction outcome with completeness records."""
    return {
        "graph": serialize_graph(report.graph),
        "metrics": serialize_metrics(metrics or []),
        "cycles": serialize_cycles(cycles or []),
        "cycle_count": {"unit": "group", "value": len(cycles or [])},
        "module_count": len(report.graph.nodes),
        "dependency_count": len(report.graph.edges),
        "unresolved": [
            {
                "path": item.path,
                "target": item.target_text,
                "reason": item.reason,
                "line": item.line,
            }
            for item in report.unresolved
        ],
        "external_reference_count": report.external_count,
        "failed_files": list(report.failed_files),
        "unsupported_files": list(report.unsupported_files),
        "partial_modules": list(report.partial_modules),
        "limited": report.limited,
        "limitation_reasons": list(report.limitation_reasons),
        "rule_set_version": rule_set_version,
    }


def dumps_canonical(payload: dict[str, object]) -> str:
    """Canonical JSON bytes-stable form (sorted keys, compact separators)."""
    text = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    if len(text) > SERIALIZATION_MAX_CHARS:
        raise ValueError("Serialized architecture graph exceeds the size guard.")
    return text
