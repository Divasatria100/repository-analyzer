"""Code hotspots without aggregate scoring (TASK-144).

A hotspot groups the measurements that flag one symbol, so reviewers can
see *where several structural measurements are notable at once* (docs/14
§12.3, FR-064). Notable means flagged by a rule-set threshold. Each
measurement is shown separately with its own value and threshold; the
presentation order (signal count, then path, then symbol) is a review
ordering, never a score, rank, weight, or grade (FR-065). Hotspots are
presentation data built from findings plus their measurements — never
findings themselves, so no new rule is introduced (CODE-REQ-006) and no
finding is duplicated.
"""

from __future__ import annotations

from dataclasses import dataclass

from app.analyzers.code_structure.models import Hotspot
from app.analyzers.findings import Finding


@dataclass(frozen=True)
class HotspotInput:
    """One flagged measurement with its finding, for hotspot grouping."""

    finding: Finding
    path: str
    symbol: str
    kind: str  # function | method
    metric: str  # complexity | nesting_depth | parameter_count
    value: int | None
    thresholds: dict[str, object]


def build_hotspots(inputs: list[HotspotInput]) -> list[Hotspot]:
    """Group flagged measurements by symbol for review ordering."""
    grouped: dict[tuple[str, str], list[HotspotInput]] = {}
    for item in inputs:
        grouped.setdefault((item.path, item.symbol), []).append(item)
    hotspots: list[Hotspot] = []
    for (path, symbol), items in grouped.items():
        ordered = sorted(items, key=lambda item: (item.metric, item.finding.rule_id))
        kind = ordered[0].kind
        measurements: tuple[dict[str, object], ...] = tuple(
            {
                "rule_id": item.finding.rule_id,
                "metric": item.metric,
                "value": item.value,
                "thresholds": dict(sorted(item.thresholds.items())),
                "severity": item.finding.severity.value,
                "confidence": item.finding.confidence.value,
                "finding_id": item.finding.finding_id or item.finding.identity_key,
            }
            for item in ordered
        )
        hotspots.append(
            Hotspot(
                path=path,
                symbol=symbol,
                kind=kind,
                signal_count=len(ordered),
                measurements=measurements,
                finding_ids=tuple(
                    item.finding.finding_id or item.finding.identity_key for item in ordered
                ),
            )
        )
    hotspots.sort(key=lambda item: (-item.signal_count, item.path, item.symbol))
    return hotspots


def serialize_hotspots(hotspots: list[Hotspot]) -> list[dict[str, object]]:
    """JSON-compatible hotspot records (measurements side by side, no scores)."""
    return [
        {
            "path": item.path,
            "symbol": item.symbol,
            "kind": item.kind,
            "signal_count": item.signal_count,
            "measurements": [dict(measurement) for measurement in item.measurements],
            "finding_ids": list(item.finding_ids),
        }
        for item in hotspots
    ]
