"""Deterministic code-structure serialization (TASK-144 support).

JSON-compatible, sorted, bounded output: measurements with explicit
availability, duplicate groups with member locations, and hotspot records.
Unknown values serialize as ``null`` with reasons — never as zero. No
source content, no secrets: paths, identifiers, counts, and structural
references only.
"""

from __future__ import annotations

import json

from app.analyzers.code_structure.hotspots import serialize_hotspots
from app.analyzers.code_structure.models import (
    DuplicateGroup,
    FunctionMeasurement,
    Hotspot,
)

#: Report-size guard for serialized code-structure output.
SERIALIZATION_MAX_CHARS = 1024 * 1024


def serialize_measurements(values: list[FunctionMeasurement]) -> list[dict[str, object]]:
    """Serialize measurements in stable (name, path, symbol) order."""
    ordered = sorted(values, key=lambda item: (item.name, item.path, item.qualified_name))
    return [
        {
            "metric": item.name,
            "path": item.path,
            "symbol": item.qualified_name,
            "value": item.value,
            "availability": "available" if item.value is not None else "unknown",
            "potentially_incomplete": item.potentially_incomplete,
            "basis": item.basis,
        }
        for item in ordered
    ]


def serialize_duplicates(groups: list[DuplicateGroup]) -> list[dict[str, object]]:
    """Serialize candidate groups with member locations (primary first)."""
    ordered = sorted(
        groups, key=lambda group: [(item.path, item.start_line) for item in group.members]
    )
    return [
        {
            "members": [
                {
                    "path": item.path,
                    "symbol": item.qualified_name,
                    "start_line": item.start_line,
                    "end_line": item.end_line,
                    "matched_tokens": item.matched_tokens,
                    "primary": position == 0,
                }
                for position, item in enumerate(group.members)
            ],
            "matched_tokens": group.matched_tokens,
            "exact": group.exact,
        }
        for group in ordered
    ]


def serialize_code_report(
    *,
    metrics: list[dict[str, object]] | None = None,
    duplicates: list[dict[str, object]] | None = None,
    hotspots: list[Hotspot] | None = None,
    limited: bool = False,
    limitation_reasons: list[str] | None = None,
    rule_set_version: str = "",
) -> dict[str, object]:
    """Assemble the code-structure report section (hotspots carry no scores)."""
    return {
        "metrics": metrics or [],
        "duplicates": duplicates or [],
        "hotspots": serialize_hotspots(hotspots or []),
        "limited": limited,
        "limitation_reasons": limitation_reasons or [],
        "rule_set_version": rule_set_version,
    }


def dumps_canonical(payload: dict[str, object]) -> str:
    """Canonical JSON bytes-stable form (sorted keys, compact separators)."""
    text = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    if len(text) > SERIALIZATION_MAX_CHARS:
        raise ValueError("Serialized code-structure output exceeds the size guard.")
    return text
