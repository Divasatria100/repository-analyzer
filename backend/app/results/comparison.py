"""Snapshot comparison: New / Resolved / Unchanged (TASK-160).

Findings are matched by stable identity key only — never message text,
array position, database keys, or fuzzy similarity (docs/13 §15). Both
snapshots must belong to the same repository and have completed outcomes;
anything else yields a structured not-comparable result instead of a
misleading clean comparison. Version skew and incomplete scopes qualify
labels (NFR-038, docs/13 §15.2) but never block comparison.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class SnapshotView:
    """Minimal sealed-snapshot data required for comparison (plain data)."""

    analysis_id: str
    repository_id: str
    commit_sha: str | None
    timestamp: str | None
    analyzer_version: str
    rule_set_version: str
    configuration: dict[str, object]
    advisory_source: str | None
    advisory_status: str | None
    findings: tuple[tuple[str, str, str, str], ...] = ()
    domain_states: tuple[tuple[str, str | None], ...] = ()
    rule_states: tuple[tuple[str, str, str], ...] = ()


@dataclass(frozen=True)
class ComparisonEntry:
    """One classified finding with provenance identifiers."""

    identity_key: str
    rule_id: str
    category: str
    base_finding_id: str | None = None
    target_finding_id: str | None = None
    qualified: bool = False


@dataclass
class ComparisonResult:
    """Deterministic comparison outcome (derived, never persisted)."""

    comparable: bool
    reason: str = ""
    base_analysis_id: str = ""
    target_analysis_id: str = ""
    base_commit_sha: str | None = None
    target_commit_sha: str | None = None
    base_context: dict[str, object] = field(default_factory=dict)
    target_context: dict[str, object] = field(default_factory=dict)
    context_differences: dict[str, bool] = field(default_factory=dict)
    qualifications: list[dict[str, object]] = field(default_factory=list)
    new: tuple[ComparisonEntry, ...] = ()
    resolved: tuple[ComparisonEntry, ...] = ()
    unchanged: tuple[ComparisonEntry, ...] = ()


def _snapshot_context(view: SnapshotView) -> dict[str, object]:
    """Comparison context of one snapshot (docs/13 §15)."""
    return {
        "commit_sha": view.commit_sha,
        "timestamp": view.timestamp,
        "analyzer_version": view.analyzer_version,
        "rule_set_version": view.rule_set_version,
    }


def compare_snapshots(base: SnapshotView, target: SnapshotView) -> ComparisonResult:
    """Classify findings across two sealed snapshots of one repository."""
    if base.repository_id != target.repository_id:
        return ComparisonResult(
            comparable=False,
            reason="Analyses belong to different repositories.",
            base_analysis_id=base.analysis_id,
            target_analysis_id=target.analysis_id,
        )
    if base.analysis_id == target.analysis_id:
        return ComparisonResult(
            comparable=False,
            reason="Baseline and target are the same analysis.",
            base_analysis_id=base.analysis_id,
            target_analysis_id=target.analysis_id,
        )
    context_differences = {
        "analyzer_version": base.analyzer_version != target.analyzer_version,
        "rule_set_version": base.rule_set_version != target.rule_set_version,
        "configuration": dict(base.configuration) != dict(target.configuration),
        "advisory_data": (base.advisory_source, base.advisory_status)
        != (target.advisory_source, target.advisory_status),
    }
    base_index = {
        identity: (rule, category, finding_id)
        for identity, rule, category, finding_id in base.findings
    }
    target_index = {
        identity: (rule, category, finding_id)
        for identity, rule, category, finding_id in target.findings
    }
    new_entries: list[ComparisonEntry] = []
    resolved_entries: list[ComparisonEntry] = []
    unchanged_entries: list[ComparisonEntry] = []
    for identity in sorted(set(base_index) | set(target_index)):
        in_base = identity in base_index
        in_target = identity in target_index
        if in_target and not in_base:
            rule, category, finding_id = target_index[identity]
            new_entries.append(
                ComparisonEntry(
                    identity_key=identity,
                    rule_id=rule,
                    category=category,
                    target_finding_id=finding_id,
                )
            )
        elif in_base and not in_target:
            rule, category, finding_id = base_index[identity]
            resolved_entries.append(
                ComparisonEntry(
                    identity_key=identity,
                    rule_id=rule,
                    category=category,
                    base_finding_id=finding_id,
                )
            )
        else:
            rule, category, base_finding_id = base_index[identity]
            _target_rule, _target_category, target_finding_id = target_index[identity]
            unchanged_entries.append(
                ComparisonEntry(
                    identity_key=identity,
                    rule_id=rule,
                    category=category,
                    base_finding_id=base_finding_id,
                    target_finding_id=target_finding_id,
                )
            )
    qualifications: list[dict[str, object]] = []
    qualified_scopes: set[tuple[str, str]] = set()
    target_area_state = {area: state for area, state in target.domain_states}
    target_rule_state = {(area, rule): state for area, rule, state in target.rule_states}
    for area, state in sorted(target_area_state.items()):
        if state not in ("No findings detected", None):
            qualifications.append(
                {
                    "scope": "area",
                    "area": area,
                    "base_state": _lookup_state(base.domain_states, area),
                    "target_state": state,
                    "effect": "Resolved findings here may reflect unevaluated scope, not fixes.",
                }
            )
            qualified_scopes.add(("area", area))
    for (area, rule), state in sorted(target_rule_state.items()):
        if state != "Evaluated":
            qualifications.append(
                {
                    "scope": "rule",
                    "rule_id": rule,
                    "area": area,
                    "base_state": _lookup_rule_state(base.rule_states, area, rule),
                    "target_state": state,
                    "effect": "Resolved findings of this rule may reflect unevaluated scope.",
                }
            )
            qualified_scopes.add(("rule", rule))
    qualified_resolved: list[ComparisonEntry] = []
    for entry in resolved_entries:
        qualified = ("area", _area_of(entry, target_index, base_index)) in qualified_scopes or (
            "rule",
            entry.rule_id,
        ) in qualified_scopes
        qualified_resolved.append(
            ComparisonEntry(
                identity_key=entry.identity_key,
                rule_id=entry.rule_id,
                category=entry.category,
                base_finding_id=entry.base_finding_id,
                target_finding_id=entry.target_finding_id,
                qualified=qualified,
            )
        )
    return ComparisonResult(
        comparable=True,
        base_analysis_id=base.analysis_id,
        target_analysis_id=target.analysis_id,
        base_commit_sha=base.commit_sha,
        target_commit_sha=target.commit_sha,
        base_context=_snapshot_context(base),
        target_context=_snapshot_context(target),
        context_differences=context_differences,
        qualifications=qualifications,
        new=tuple(new_entries),
        resolved=tuple(qualified_resolved),
        unchanged=tuple(unchanged_entries),
    )


def _lookup_state(states: tuple[tuple[str, str | None], ...], area: str) -> str | None:
    for scope_area, state in states:
        if scope_area == area:
            return state
    return None


def _lookup_rule_state(
    states: tuple[tuple[str, str, str], ...], area: str, rule_id: str
) -> str | None:
    for scope_area, scope_rule, state in states:
        if scope_area == area and scope_rule == rule_id:
            return state
    return None


def _area_of(
    entry: ComparisonEntry,
    target_index: dict[str, tuple[str, str, str]],
    base_index: dict[str, tuple[str, str, str]],
) -> str:
    if entry.identity_key in target_index:
        _rule, category, _finding = target_index[entry.identity_key]
        return category
    _rule, category, _finding = base_index[entry.identity_key]
    return category
