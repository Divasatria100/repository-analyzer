"""Canonical analysis result serialization (TASK-159/161, docs/13).

Builds the JSON-compatible canonical result from persisted snapshot rows
(``SnapshotData``, loaded by the results gateway). Pure function of its
input: deterministic for equivalent rows, no database access, no network,
no analyzer execution. Sections unavailable for the analysis state are
``null``, never empty objects or arrays (docs/13 §3.3).

Conventions owned by this module (documented, deterministic):

- Analyzer ``subject_key`` strings are this repository's own analyzer
  outputs (version-pinned); strict ``prefix:path[:qualified]`` parsing
  with skip-on-mismatch. Parsed subjects only ever add optional members
  (module/dependency associations, measurements); locations, thresholds,
  and factors always come from stored columns.
- Stored lowercase operational values map to canonical capitalized
  vocabulary: branch/commit origin ``requested``/``defaulted`` →
  ``Requested``/``Defaulted``; advisory ``succeeded``/``partly
  succeeded``/``unavailable`` → ``Succeeded``/``Partly succeeded``/
  ``Unavailable`` (anything else → ``Unavailable``, never silent).
- Metric definitions (description, interpretation, unit) are stated here
  as the defining-analyzer account: fan-in/out count distinct internal
  modules per direction, coupling is coupling-def-1
  (``|In(M) ∪ Out(M)|`` over internal edges only), size/complexity
  metrics count their subject's units. Map is closed; unknown metric
  names raise instead of being described vaguely.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from os.path import basename

from app.models.indexing import File, Limitation
from app.models.repository import Analysis, Repository
from app.models.results import (
    AnalysisSnapshot,
    ArchitectureMetric,
    Dependency,
    DomainState,
    FileCoverage,
    Finding,
    Module,
    ModuleDependency,
    RuleEvaluation,
)
from app.results.comparison import ComparisonEntry, ComparisonResult, SnapshotView

#: Canonical areas in stable presentation order (docs/13 §3.4).
AREAS = ("security", "architecture", "dependency", "code_structure")

#: Result section per area (docs/13 §3.4; ``dependencies`` is plural).
AREA_SECTIONS = {
    "security": "security",
    "architecture": "architecture",
    "dependency": "dependencies",
    "code_structure": "code_structure",
}

#: Severity keys always present in area summary counts (docs/13 §7.2).
SEVERITIES = ("Critical", "High", "Medium", "Low", "Info")

#: Confidence keys always present in area summary counts (docs/13 §7.2).
CONFIDENCES = ("High", "Medium", "Low")

#: Stored file-type values to canonical labels (docs/13 §13 table).
FILE_TYPES = {"source": "source", "manifest": "dependency manifest", "unknown": "other"}

#: Stored support values to canonical labels (docs/13 §13 table).
SUPPORT_LABELS = {
    "supported": "Primary Support",
    "unsupported": "Not Supported",
    "unrecognized": "Unrecognized",
    "binary": "Not Supported",
}

#: Stored eligibility values to canonical labels (docs/13 §13 example).
ELIGIBILITY_LABELS = {
    "eligible": "Eligible",
    "not_eligible": "Not eligible",
    "not_scanned": "Not eligible",
}

#: Stored parse results to canonical labels (docs/13 §13 table).
PARSE_LABELS = {
    "parsed": "Parsed",
    "parsed_with_diagnostics": "Parsed with diagnostics",
    "failed": "Failed",
}

#: Parse-result keys always present in the files summary (docs/13 §7.1).
PARSE_SUMMARY_KEYS = ("Parsed", "Parsed with diagnostics", "Failed", "Not parsed")

#: Stored language codes to display names (V1.0 supports Python only).
LANGUAGE_DISPLAY = {"python": "Python"}

#: Threshold name to (metric name, subject kind) for evidence measurements.
#: Subject kinds: ``module`` matches a module path; ``qualified`` matches a
#: class/function qualified name parsed from the finding subject; ``none``
#: means the threshold has no metric counterpart (docs/13 §8.5).
THRESHOLD_METRICS: dict[str, tuple[str, str]] = {
    "fan_out": ("fan_out", "module"),
    "fan_in": ("fan_in", "module"),
    "coupling": ("coupling", "module"),
    "module_lines": ("lines_of_code", "module"),
    "module_declarations": ("declaration_count", "module"),
    "class_lines": ("lines_of_code", "qualified"),
    "class_methods": ("method_count", "qualified"),
    "function_lines": ("lines_of_code", "qualified"),
    "function_complexity": ("complexity", "qualified"),
    "complexity": ("complexity", "qualified"),
    "nesting": ("nesting_depth", "qualified"),
    "parameters": ("parameter_count", "qualified"),
    "dependencies": ("", "none"),
    "duplicate_tokens": ("", "none"),
}

#: Subject prefixes carrying a qualified class/function name after the path.
QUALIFIED_SUBJECT_PREFIXES = frozenset(
    {"large-class", "large-function", "complexity", "nesting", "parameters"}
)

#: Metric definitions stated as the defining-analyzer account.
METRIC_DEFINITIONS: dict[str, dict[str, str]] = {
    "fan_out": {
        "description": "Number of distinct internal modules imported by the module.",
        "interpretation": "Lower is better; high values suggest broad responsibility.",
        "unit": "count",
    },
    "fan_in": {
        "description": "Number of distinct internal modules importing the module.",
        "interpretation": "Higher values indicate wider reuse and higher change impact.",
        "unit": "count",
    },
    "coupling": {
        "description": "coupling-def-1: |In(M) union Out(M)| over internal edges only.",
        "interpretation": "Higher values indicate stronger two-sided structural ties.",
        "unit": "count",
    },
    "lines_of_code": {
        "description": "Lines of code of the subject.",
        "interpretation": "Higher values indicate larger size.",
        "unit": "count",
    },
    "declaration_count": {
        "description": "Number of declarations in the subject.",
        "interpretation": "Higher values indicate a larger interface or body.",
        "unit": "count",
    },
    "method_count": {
        "description": "Number of methods in the class.",
        "interpretation": "Higher values indicate a larger class.",
        "unit": "count",
    },
    "complexity": {
        "description": "Cyclomatic complexity of the function.",
        "interpretation": "Higher values indicate more decision paths to exercise.",
        "unit": "score",
    },
    "nesting_depth": {
        "description": "Maximum nesting depth of the function.",
        "interpretation": "Higher values indicate harder-to-follow control flow.",
        "unit": "levels",
    },
    "parameter_count": {
        "description": "Number of parameters of the function.",
        "interpretation": "Higher values indicate a wider calling contract.",
        "unit": "count",
    },
}

#: Fixed layering-direction account for layer-violation structure.
LAYERING_DESCRIPTION = (
    "Dependencies are expected to flow downward: presentation depends on "
    "application, application on domain, and domain on infrastructure; "
    "upward or lateral dependencies across layers are violations."
)


@dataclass
class SnapshotData:
    """All persisted rows of one sealed snapshot (loaded by the gateway)."""

    analysis: Analysis
    repository: Repository
    snapshot: AnalysisSnapshot
    rules: dict[str, str] = field(default_factory=dict)
    findings: list[Finding] = field(default_factory=list)
    rule_evaluations: list[RuleEvaluation] = field(default_factory=list)
    metrics: list[ArchitectureMetric] = field(default_factory=list)
    modules: list[Module] = field(default_factory=list)
    module_dependencies: list[ModuleDependency] = field(default_factory=list)
    dependencies: list[Dependency] = field(default_factory=list)
    files: list[File] = field(default_factory=list)
    file_coverages: list[FileCoverage] = field(default_factory=list)
    domain_states: list[DomainState] = field(default_factory=list)
    limitations: list[Limitation] = field(default_factory=list)
    comparison: dict[str, object] | None = None


def _iso(value: datetime | None) -> str | None:
    """Render a timestamp in UTC ISO-8601, or None when absent."""
    if value is None:
        return None
    moment = value if value.tzinfo is not None else value.replace(tzinfo=UTC)
    return moment.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _origin(value: str | None) -> str | None:
    """Map a stored branch/commit origin to canonical vocabulary."""
    if value is None:
        return None
    normalized = value.strip().lower()
    if normalized == "requested":
        return "Requested"
    if normalized == "defaulted":
        return "Defaulted"
    raise ValueError(f"Unknown origin: {value!r}")


def _advisory_outcome(value: str | None) -> str:
    """Map a stored advisory status to the docs/13 §4.3 outcome vocabulary."""
    normalized = (value or "").strip().lower()
    if normalized == "succeeded":
        return "Succeeded"
    if normalized == "partly succeeded":
        return "Partly succeeded"
    return "Unavailable"


def _sorted_findings(findings: list[Finding]) -> list[Finding]:
    """Deterministic finding order: rule, path, line, finding id."""
    return sorted(
        findings,
        key=lambda item: (item.rule_id, item.location_path, item.start_line, item.finding_id),
    )


def _location_entry(
    path: str, start_line: int, end_line: int, start_column: int, end_column: int
) -> dict[str, object]:
    """One canonical source location."""
    return {
        "path": path,
        "start_line": start_line,
        "end_line": end_line,
        "start_column": start_column,
        "end_column": end_column,
    }


def _finding_subject(finding: Finding) -> dict[str, object]:
    """Canonical subject with locations, module node ids, dependency ids.

    Location rows include the primary location (flagged); it sorts first.
    """
    locations = [
        _location_entry(
            location.path,
            location.start_line,
            location.end_line,
            location.start_column,
            location.end_column,
        )
        for location in sorted(
            finding.locations,
            key=lambda item: (not item.primary, item.path, item.start_line, item.start_column),
        )
    ]
    if not locations:
        raise ValueError(f"Finding {finding.finding_id!r} has no subject locations.")
    return {
        "locations": locations,
        "modules": sorted({link.module_node_id for link in finding.modules}),
        "dependencies": sorted({link.dependency_id for link in finding.dependencies}),
    }


def _qualified_subject_name(rule_id: str, finding: Finding) -> str | None:
    """Extract a class/function qualified name from the finding subject.

    Only ``prefix:path:qualified`` shapes whose prefix belongs to the
    qualified-subject rule families and whose path equals the primary
    location path are accepted; anything else yields None.
    """
    subject = finding.subject_key or ""
    parts = subject.split(":", 2)
    if len(parts) != 3:
        return None
    prefix, path, qualified = parts
    if prefix not in QUALIFIED_SUBJECT_PREFIXES or path != finding.location_path:
        return None
    if not qualified.strip():
        return None
    void_prefixes = {
        "ARCH-LARGE-CLASS": "large-class",
        "ARCH-LARGE-FUNCTION": "large-function",
        "CODE-HIGH-COMPLEXITY": "complexity",
        "CODE-DEEP-NESTING": "nesting",
        "CODE-HIGH-PARAMETER-COUNT": "parameters",
    }
    if void_prefixes.get(rule_id) != prefix:
        return None
    return qualified


def _metric_index(metrics: list[ArchitectureMetric]) -> dict[tuple[str, str, str, str], int]:
    """Index available metric values by (area, name, path, subject name)."""
    index: dict[tuple[str, str, str, str], int] = {}
    for metric in metrics:
        if metric.value is None:
            continue
        index[(metric.area, metric.metric_name, metric.subject_path, metric.subject_name or "")] = (
            metric.value
        )
    return index


def _applied_thresholds(finding: Finding) -> list[dict[str, object]]:
    """Canonical applied-threshold entries sorted by threshold name."""
    pairs = finding.applied_thresholds or []
    entries = [
        {"threshold": str(pair[0]), "value": pair[1]}
        for pair in pairs
        if isinstance(pair, (list, tuple)) and len(pair) == 2
    ]
    return sorted(entries, key=lambda item: str(item["threshold"]))


def _measurements(
    finding: Finding,
    area: str,
    index: dict[tuple[str, str, str, str], int],
) -> list[dict[str, object]]:
    """Evidence measurements resolved through stored metric rows.

    Each applied threshold with a metric counterpart resolves to the
    persisted metric value for the finding subject; unresolvable
    thresholds are omitted (never synthesized).
    """
    qualified: str | None | bool = None
    records: list[dict[str, object]] = []
    for entry in _applied_thresholds(finding):
        mapping = THRESHOLD_METRICS.get(str(entry["threshold"]))
        if mapping is None:
            continue
        metric_name, kind = mapping
        if kind == "none":
            continue
        if kind == "qualified":
            if qualified is None:
                qualified = _qualified_subject_name(finding.rule_id, finding)
            subject_name = qualified if isinstance(qualified, str) else None
            if subject_name is None:
                continue
        else:
            subject_name = ""
        value = index.get((area, metric_name, finding.location_path, subject_name))
        if value is None:
            continue
        record: dict[str, object] = {"metric": metric_name, "value": value}
        threshold_value = entry["value"]
        if isinstance(threshold_value, (int, float)) and isinstance(value, (int, float)):
            record["exceeded"] = value > threshold_value
        records.append(record)
    return sorted(records, key=lambda item: str(item["metric"]))


def _source_context(finding: Finding) -> tuple[bool, dict[str, object] | None]:
    """Canonical source context from the stored evidence payload."""
    evidence = finding.evidence if isinstance(finding.evidence, dict) else None
    redacted = bool(finding.redacted) or bool(evidence and evidence.get("redacted", False))
    if evidence is None:
        return redacted, None
    lines = evidence.get("lines", [])
    text = "\n".join(str(line) for line in lines) if isinstance(lines, list) else None
    start = evidence.get("start_line")
    end = evidence.get("end_line")
    context: dict[str, object] = {
        "text": text,
        "start_line": start if isinstance(start, int) else None,
        "end_line": end if isinstance(end, int) else None,
    }
    if bool(evidence.get("truncated", False)):
        context["truncated"] = True
    return redacted, context


def _finding_structure(
    finding: Finding,
    area: str,
    modules_by_id: dict[str, str],
    edges: dict[tuple[str, str], dict[str, object]],
) -> dict[str, object] | None:
    """Canonical structure evidence for architecture findings, else None."""
    if area != "architecture":
        return None
    rule_id = finding.rule_id
    members = sorted({link.module_node_id for link in finding.modules})
    if rule_id == "ARCH-CIRCULAR-DEPENDENCY":
        return {
            "participants": members,
            "paths_limited": True,
            "relationships": _incident_edges(members, members, edges),
        }
    if rule_id in ("ARCH-HIGH-FAN-OUT", "ARCH-HIGH-FAN-IN", "ARCH-HIGH-COUPLING"):
        return {"participants": members, "relationships": _incident_edges(members, members, edges)}
    if rule_id == "ARCH-LAYER-VIOLATION":
        layers = {
            link.module_node_id: link.module_layer for link in finding.modules if link.module_layer
        }
        structure: dict[str, object] = {
            "participants": members,
            "layers": [
                {
                    "module_id": node_id,
                    "layer": layers[node_id],
                    "assignment_basis": "directory or module naming",
                }
                for node_id in members
                if node_id in layers
            ],
            "layering_direction": {"description": LAYERING_DESCRIPTION},
        }
        consistency = next(
            (factor for factor in (finding.severity_factors or []) if "consistent" in factor),
            None,
        )
        if consistency is not None:
            layering = structure["layering_direction"]
            assert isinstance(layering, dict)
            layering["consistency_evidence"] = consistency
        structure["relationships"] = _incident_edges(members, members, edges)
        return structure
    if members:
        return {"participants": members}
    return None


def _incident_edges(
    sources: list[str],
    targets: list[str],
    edges: dict[tuple[str, str], dict[str, object]],
) -> list[dict[str, str]]:
    """Edge references incident to the given members, in sorted order."""
    source_set = set(sources)
    target_set = set(targets)
    return [
        {"source": source, "target": target}
        for source, target in sorted(edges)
        if source in source_set and target in target_set
    ]


def _finding_advisories(finding: Finding, area: str) -> list[dict[str, object]] | None:
    """Canonical advisory evidence for known-vulnerability findings."""
    if area != "dependency" or finding.rule_id != "DEP-KNOWN-VULNERABILITY":
        return None
    evidence = finding.evidence if isinstance(finding.evidence, dict) else None
    candidates: list[dict[str, object]] = []
    advisories = evidence.get("advisories") if evidence is not None else None
    if isinstance(advisories, list):
        candidates = [item for item in advisories if isinstance(item, dict)]
    records: list[dict[str, object]] = [
        {"advisory_id": str(item.get("advisory_id", "")), "source": str(item.get("source", ""))}
        for item in candidates
        if item.get("advisory_id")
    ]
    return sorted(records, key=lambda item: (str(item["source"]), str(item["advisory_id"])))


def _finding_entry(
    finding: Finding,
    rules: dict[str, str],
    area: str,
    index: dict[tuple[str, str, str, str], int],
    modules_by_id: dict[str, str],
    edges: dict[tuple[str, str], dict[str, object]],
) -> dict[str, object]:
    """One canonical finding (docs/13 §8)."""
    if finding.rule_id not in rules:
        raise ValueError(f"Unknown rule for finding {finding.finding_id!r}: {finding.rule_id!r}.")
    entry: dict[str, object] = {
        "finding_id": finding.finding_id,
        "identity_key": finding.identity_key,
        "rule_id": finding.rule_id,
        "rule_name": rules[finding.rule_id],
        "category": finding.category,
        "severity": finding.severity,
        "confidence": finding.confidence,
        "subject": _finding_subject(finding),
    }
    redacted, context = _source_context(finding)
    measurements = _measurements(finding, area, index)
    advisories = _finding_advisories(finding, area)
    structure = _finding_structure(finding, area, modules_by_id, edges)
    has_evidence = (
        context is not None or bool(measurements) or advisories is not None or structure is not None
    )
    if area in ("security", "architecture") or has_evidence:
        evidence_entry: dict[str, object] = {"redacted": redacted, "source_context": context}
        if measurements:
            evidence_entry["measurements"] = measurements
        if advisories is not None:
            evidence_entry["advisories"] = advisories
        if structure is not None:
            evidence_entry["structure"] = structure
        entry["evidence"] = evidence_entry
    entry["explanation"] = finding.description
    if finding.impact is not None or area == "security":
        entry["impact"] = finding.impact
    entry["recommendation"] = finding.recommendation
    thresholds = _applied_thresholds(finding)
    if thresholds:
        entry["applied_thresholds"] = thresholds
    if finding.partial_info:
        entry["partial_information"] = True
    severity_factors = list(finding.severity_factors or [])
    confidence_factors = list(finding.confidence_factors or [])
    if area == "architecture" or severity_factors:
        entry["severity_factors"] = severity_factors
    if area == "architecture" or confidence_factors:
        entry["confidence_factors"] = confidence_factors
    return entry


def _rule_evaluation_entries(evaluations: list[RuleEvaluation]) -> list[dict[str, object]]:
    """Canonical rule evaluations sorted by rule id (docs/13 §6.4)."""
    entries: list[dict[str, object]] = []
    for evaluation in sorted(evaluations, key=lambda item: item.rule_id):
        record: dict[str, object] = {"rule_id": evaluation.rule_id, "state": evaluation.state}
        if evaluation.state != "Evaluated" or evaluation.reason:
            record["reason"] = evaluation.reason
        entries.append(record)
    return entries


def _graph_edges(
    modules: list[Module], module_dependencies: list[ModuleDependency]
) -> tuple[dict[str, str], dict[tuple[str, str], dict[str, object]], list[dict[str, object]]]:
    """Resolve node ids, merge same-pair edges, collect unresolved references.

    Multiple references for one ordered pair are one edge with combined
    locations (docs/13 §14.2). Only references resolving to an internal
    source unit are edges; the rest are diagnostic records (§14.3).
    """
    surrogate_to_node = {module.id: module.module_id for module in modules}
    merged: dict[tuple[str, str], dict[str, object]] = {}
    diagnostics: list[dict[str, object]] = []
    for dependency in sorted(
        module_dependencies, key=lambda item: (item.source_id, item.target_text, item.line or 0)
    ):
        source = surrogate_to_node.get(dependency.source_id)
        if source is None:
            raise ValueError(f"Module dependency {dependency.id!r} has an unknown source module.")
        if dependency.resolution == "internal" and dependency.target_id is not None:
            target = surrogate_to_node.get(dependency.target_id)
            if target is None:
                raise ValueError(
                    f"Module dependency {dependency.id!r} has an unknown target module."
                )
            edge = merged.setdefault(
                (source, target),
                {
                    "source": source,
                    "target": target,
                    "relationship_type": "import",
                    "qualifiers": {},
                    "locations": [],
                },
            )
            qualifiers = edge["qualifiers"]
            assert isinstance(qualifiers, dict)
            if dependency.conditional:
                qualifiers["conditional"] = True
            if dependency.deferred:
                qualifiers["deferred"] = True
            locations = edge["locations"]
            assert isinstance(locations, list)
            for site in dependency.locations or []:
                if isinstance(site, (list, tuple)) and len(site) == 3:
                    locations.append({"path": site[0], "line": site[1], "column": site[2]})
                else:
                    locations.append(
                        {"path": source, "line": dependency.line, "column": dependency.column}
                    )
            continue
        if dependency.resolution not in ("external", "unresolved"):
            raise ValueError(f"Unknown module dependency resolution: {dependency.resolution!r}.")
        diagnostics.append(
            {
                "source": source,
                "resolution": dependency.resolution,
                "target_reference": dependency.target_text,
                "locations": [
                    {"path": source, "line": dependency.line, "column": dependency.column}
                ],
            }
        )
    ordered_edges = dict(sorted(merged.items()))
    for edge in ordered_edges.values():
        locations = edge["locations"]
        assert isinstance(locations, list)
        locations.sort(key=lambda item: (str(item["path"]), item["line"] or 0, item["column"] or 0))
        if not edge["qualifiers"]:
            del edge["qualifiers"]
    diagnostics.sort(key=lambda item: (str(item["source"]), str(item["target_reference"])))
    return surrogate_to_node, ordered_edges, diagnostics


def _metric_record(metric: ArchitectureMetric) -> dict[str, object]:
    """One canonical metric record (docs/13 §10.1)."""
    record: dict[str, object] = {
        "metric": metric.metric_name,
        "subject_path": metric.subject_path,
        "subject_name": metric.subject_name or None,
        "availability": metric.availability,
    }
    if metric.value is not None:
        record["value"] = metric.value
    if metric.potentially_incomplete:
        record["potentially_incomplete"] = True
    if metric.basis:
        record["basis"] = metric.basis
    return record


def _metric_definitions(names: set[str]) -> dict[str, object]:
    """Canonical metric definitions for the metrics present (docs/13 §10)."""
    definitions: dict[str, object] = {}
    for name in sorted(names):
        if name not in METRIC_DEFINITIONS:
            raise ValueError(f"Unknown metric {name!r}: no canonical definition.")
        definition = METRIC_DEFINITIONS[name]
        definitions[name] = {
            "description": definition["description"],
            "interpretation": definition["interpretation"],
            "unit": definition["unit"],
            "aggregation": "individual",
        }
    return definitions


def _area_findings_block(findings: list[dict[str, object]]) -> dict[str, object]:
    """Canonical findings summary block (docs/13 §7.2)."""
    by_severity = {severity: 0 for severity in SEVERITIES}
    by_confidence = {confidence: 0 for confidence in CONFIDENCES}
    by_rule: dict[str, int] = {}
    for finding in findings:
        severity = str(finding["severity"])
        confidence = str(finding["confidence"])
        if severity not in by_severity:
            raise ValueError(f"Unknown severity in summary: {severity!r}.")
        if confidence not in by_confidence:
            raise ValueError(f"Unknown confidence in summary: {confidence!r}.")
        by_severity[severity] += 1
        by_confidence[confidence] += 1
        rule_id = str(finding["rule_id"])
        by_rule[rule_id] = by_rule.get(rule_id, 0) + 1
    return {
        "total": len(findings),
        "by_severity": by_severity,
        "by_confidence": by_confidence,
        "by_rule": dict(sorted(by_rule.items())),
    }


def _file_entry(
    record: File,
    coverages: list[FileCoverage],
    finding_count: int,
) -> dict[str, object]:
    """One canonical file record (docs/13 §13)."""
    if record.file_type not in FILE_TYPES:
        raise ValueError(f"Unknown file type for {record.path!r}: {record.file_type!r}.")
    if record.support_status not in SUPPORT_LABELS:
        raise ValueError(f"Unknown support status for {record.path!r}: {record.support_status!r}.")
    if record.eligibility not in ELIGIBILITY_LABELS:
        raise ValueError(f"Unknown eligibility for {record.path!r}: {record.eligibility!r}.")
    parse_result = PARSE_LABELS.get(record.parse_result or "")
    if record.parse_result is not None and parse_result is None:
        raise ValueError(f"Unknown parse result for {record.path!r}: {record.parse_result!r}.")
    diagnostics: list[dict[str, object]] = []
    for diagnostic in record.diagnostics or []:
        if not isinstance(diagnostic, dict):
            raise ValueError(f"Invalid diagnostic for {record.path!r}.")
        diagnostics.append(
            {
                "code": diagnostic.get("code"),
                "message": diagnostic.get("message"),
                "line": diagnostic.get("line"),
                "column": diagnostic.get("column"),
            }
        )
    coverage_entries: list[dict[str, object]] = []
    for coverage in sorted(coverages, key=lambda item: (item.scope_kind, item.scope_value)):
        entry: dict[str, object] = {
            "scope": {"kind": coverage.scope_kind, "value": coverage.scope_value},
            "state": coverage.state,
        }
        if coverage.state != "Fully analyzed" or coverage.reason:
            entry["reason"] = coverage.reason
        coverage_entries.append(entry)
    language = record.language
    return {
        "path": record.path,
        "file_type": FILE_TYPES[record.file_type],
        "language": LANGUAGE_DISPLAY.get(language or "", language),
        "support": SUPPORT_LABELS[record.support_status],
        "size": record.size,
        "binary": record.is_binary,
        "generated": record.is_generated,
        "exclusion": (
            {"status": "Excluded", "reason": record.exclusion_reason} if record.excluded else None
        ),
        "eligibility": {
            "classification": ELIGIBILITY_LABELS[record.eligibility],
            "reason": record.eligibility_reason,
        },
        "parse_result": parse_result,
        "diagnostics": diagnostics,
        "indexing_limitation": record.indexing_limitation,
        "coverage": coverage_entries,
        "finding_count": finding_count,
    }


def build_canonical_result(data: SnapshotData) -> dict[str, object]:
    """Build the canonical JSON-compatible result for one snapshot.

    Requires a completed outcome (``Completed`` or ``Completed with
    limitations``); anything else raises, because sections for other
    states are outside the persistence contract (docs/13 §3.3).
    """
    analysis = data.analysis
    if analysis.outcome not in ("Completed", "Completed with limitations"):
        raise ValueError(
            f"Canonical result requires a completed outcome, got {analysis.outcome!r}."
        )
    if not isinstance(analysis.analysis_config, dict):
        raise ValueError("Canonical result requires the persisted configuration snapshot.")
    advisory_entries = (
        {
            "source": analysis.advisory_source,
            "consulted_at": _iso(analysis.advisory_consulted_at),
            "outcome": _advisory_outcome(analysis.advisory_status),
        }
        if analysis.advisory_source
        else None
    )
    result: dict[str, object] = {
        "analysis": {
            "analysis_id": analysis.id,
            "repository_id": analysis.repository_id,
            "timestamp": _iso(analysis.created_at),
            "analyzer_version": analysis.analyzer_version,
            "rule_set_version": analysis.rule_set_version,
            "configuration": analysis.analysis_config,
            "advisory_data": advisory_entries,
        },
        "repository": {
            "repository_id": data.repository.id,
            "url": data.repository.normalized_url,
            "owner": data.repository.owner,
            "name": data.repository.name,
            "analyzed_state": {
                "branch": (
                    {"name": analysis.resolved_branch, "origin": _origin(analysis.branch_origin)}
                    if analysis.resolved_branch
                    else None
                ),
                "commit": (
                    {"sha": analysis.resolved_commit_sha, "origin": _origin(analysis.commit_origin)}
                    if analysis.resolved_commit_sha
                    else None
                ),
            },
        },
    }
    domain_by_area = {domain.area: domain for domain in data.domain_states}
    for area in AREAS:
        if area not in domain_by_area:
            raise ValueError(f"Missing domain state for area {area!r}.")
    limitations = [_limitation_entry(limitation) for limitation in data.limitations]
    limitations.sort(
        key=lambda item: (
            str(item["scope_kind"]),
            str(item.get("area") or ""),
            str(item.get("rule_id") or ""),
            str(item.get("path") or ""),
            str(item["reason"]),
        )
    )
    result["status"] = {
        # Exactly one of stage/outcome is non-null (docs/13 §6.1): the
        # stored stage keeps the last pipeline stage for operations while
        # the canonical view reports null for a terminal analysis.
        "stage": None if analysis.outcome is not None else analysis.stage,
        "outcome": analysis.outcome,
        "completed_at": _iso(analysis.completed_at),
        "explanation": analysis.explanation,
        "snapshot": {"sealed_at": _iso(data.snapshot.sealed_at)},
        "domains": [
            {
                "area": area,
                "state": domain_by_area[area].state,
                "reason": domain_by_area[area].reason,
            }
            for area in AREAS
        ],
        "limitations": limitations,
    }

    findings_by_area: dict[str, list[Finding]] = {area: [] for area in AREAS}
    for finding in _sorted_findings(data.findings):
        if finding.category not in findings_by_area:
            raise ValueError(f"Unknown finding category: {finding.category!r}.")
        findings_by_area[finding.category].append(finding)
    evaluations_by_area: dict[str, list[RuleEvaluation]] = {area: [] for area in AREAS}
    for evaluation in data.rule_evaluations:
        area = _area_of_rule(evaluation.rule_id)
        evaluations_by_area[area].append(evaluation)
    metrics_by_area: dict[str, list[ArchitectureMetric]] = {area: [] for area in AREAS}
    for metric in data.metrics:
        if metric.area not in metrics_by_area:
            raise ValueError(f"Unknown metric area: {metric.area!r}.")
        metrics_by_area[metric.area].append(metric)
    metric_index = _metric_index(data.metrics)
    _, graph_edges, graph_diagnostics = _graph_edges(data.modules, data.module_dependencies)
    modules_by_id = {module.module_id: module.module_id for module in data.modules}

    area_states = {area: domain_by_area[area].state for area in AREAS}
    sections: dict[str, dict[str, object] | None] = {}
    finding_entries: dict[str, list[dict[str, object]]] = {}
    for area in AREAS:
        state = area_states[area]
        if state in ("Analysis not performed", "Analysis failed", "Analysis unavailable"):
            sections[area] = None
            finding_entries[area] = []
            continue
        entries = [
            _finding_entry(finding, data.rules, area, metric_index, modules_by_id, graph_edges)
            for finding in findings_by_area[area]
        ]
        finding_entries[area] = entries
        section: dict[str, object] = {
            "rule_evaluations": _rule_evaluation_entries(evaluations_by_area[area]),
            "findings": entries,
        }
        if area in ("architecture", "code_structure"):
            area_metrics = sorted(
                metrics_by_area[area],
                key=lambda item: (item.metric_name, item.subject_path, item.subject_name or ""),
            )
            section["metric_definitions"] = _metric_definitions(
                {item.metric_name for item in area_metrics}
            )
            section["metrics"] = [_metric_record(item) for item in area_metrics]
        if area == "security":
            section["metric_definitions"] = {}
            section["metrics"] = []
        if area == "architecture":
            section["graph"] = _graph_section(data, graph_edges, graph_diagnostics)
            section["cycles"] = _cycle_section(finding_entries[area])
        if area == "dependency":
            section["items"] = _dependency_items(data)
        sections[area] = section

    result["security"] = sections["security"]
    result["architecture"] = sections["architecture"]
    result["dependencies"] = sections["dependency"]
    result["code_structure"] = sections["code_structure"]
    result["summary"] = _summary_section(data, area_states, finding_entries, sections, graph_edges)
    file_counts: dict[str, int] = {}
    for finding in data.findings:
        for location in {item.path for item in finding.locations}:
            file_counts[location] = file_counts.get(location, 0) + 1
    coverages_by_file: dict[str, list[FileCoverage]] = {}
    files_by_id = {record.id: record for record in data.files}
    for coverage in data.file_coverages:
        owner = files_by_id.get(coverage.file_id)
        if owner is None:
            raise ValueError(f"File coverage {coverage.id!r} has an unknown file.")
        coverages_by_file.setdefault(owner.path, []).append(coverage)
    result["files"] = [
        _file_entry(record, coverages_by_file.get(record.path, []), file_counts.get(record.path, 0))
        for record in sorted(data.files, key=lambda item: item.path)
    ]
    result["comparison"] = data.comparison
    return result


def _limitation_entry(limitation: Limitation) -> dict[str, object]:
    """One canonical limitation (docs/13 §6.5)."""
    entry: dict[str, object] = {"scope_kind": limitation.scope_kind, "reason": limitation.reason}
    if limitation.area is not None:
        entry["area"] = limitation.area
    if limitation.rule_id is not None:
        entry["rule_id"] = limitation.rule_id
    if limitation.file_path is not None:
        entry["path"] = limitation.file_path
    return entry


def _area_of_rule(rule_id: str) -> str:
    """Map a rule id prefix to its analysis area."""
    if rule_id.startswith("SEC-"):
        return "security"
    if rule_id.startswith("ARCH-"):
        return "architecture"
    if rule_id.startswith("DEP-"):
        return "dependency"
    if rule_id.startswith("CODE-"):
        return "code_structure"
    raise ValueError(f"Unknown rule area for {rule_id!r}.")


def _graph_section(
    data: SnapshotData,
    edges: dict[tuple[str, str], dict[str, object]],
    diagnostics: list[dict[str, object]],
) -> dict[str, object]:
    """Canonical architecture graph (docs/13 §14)."""
    finding_nodes: dict[str, list[str]] = {}
    for finding in data.findings:
        if finding.category != "architecture":
            continue
        for link in finding.modules:
            finding_nodes.setdefault(link.module_node_id, []).append(finding.finding_id)
    nodes: list[dict[str, object]] = []
    for module in sorted(data.modules, key=lambda item: item.module_id):
        node: dict[str, object] = {
            "node_id": module.module_id,
            "name": basename(module.module_id),
            "paths": [module.module_id],
            "partially_represented": module.partially_represented,
            "finding_ids": sorted(set(finding_nodes.get(module.module_id, []))),
        }
        if module.layer is not None:
            node["layer"] = module.layer
        nodes.append(node)
    incomplete = any(module.partially_represented for module in data.modules) or bool(diagnostics)
    return {
        "granularity": "Source file",
        "potentially_incomplete": incomplete,
        "nodes": nodes,
        "edges": list(edges.values()),
        "external_and_unresolved_references": diagnostics,
    }


def _cycle_section(findings: list[dict[str, object]]) -> list[dict[str, object]]:
    """Canonical cycle records, one per circular-dependency finding (§10.3)."""
    cycles: list[dict[str, object]] = []
    for finding in findings:
        if str(finding["rule_id"]) != "ARCH-CIRCULAR-DEPENDENCY":
            continue
        subject = finding["subject"]
        assert isinstance(subject, dict)
        modules = subject.get("modules", [])
        assert isinstance(modules, list)
        cycles.append(
            {"finding_id": finding["finding_id"], "node_ids": sorted(str(item) for item in modules)}
        )
    return cycles


def _dependency_items(data: SnapshotData) -> list[dict[str, object]]:
    """Canonical dependency items (docs/13 §11)."""
    finding_occurrences: dict[str, list[str]] = {}
    for finding in data.findings:
        if finding.category != "dependency":
            continue
        for link in finding.dependencies:
            finding_occurrences.setdefault(link.dependency_id, []).append(finding.finding_id)
    introduced: dict[str, list[str]] = {}
    for dependency in data.dependencies:
        for relationship in dependency.relationships:
            introduced.setdefault(relationship.child_id, []).append(dependency.id)
    items: list[dict[str, object]] = []
    for dependency in sorted(
        data.dependencies,
        key=lambda item: (
            item.ecosystem,
            item.canonical_name,
            item.resolved_version or "",
            item.source_manifest,
            item.source_line or 0,
        ),
    ):
        items.append(
            {
                "dependency_id": dependency.id,
                "name": dependency.canonical_name,
                "version": dependency.resolved_version,
                "ecosystem": dependency.ecosystem,
                "classification": dependency.dependency_class,
                "source_manifest": dependency.source_manifest,
                "introduced_by": sorted(introduced.get(dependency.id, [])),
                "advisories": sorted(
                    (
                        {"advisory_id": advisory.advisory_id, "source": advisory.source}
                        for advisory in dependency.advisories
                    ),
                    key=lambda item: (str(item["source"]), str(item["advisory_id"])),
                ),
                "finding_ids": sorted(set(finding_occurrences.get(dependency.id, []))),
            }
        )
    return items


def _summary_section(
    data: SnapshotData,
    area_states: dict[str, str | None],
    finding_entries: dict[str, list[dict[str, object]]],
    sections: dict[str, dict[str, object] | None],
    edges: dict[tuple[str, str], dict[str, object]],
) -> dict[str, object]:
    """Canonical result summary with counts derived from sections (§7.4)."""
    files = sorted(data.files, key=lambda item: item.path)
    for record in files:
        if record.file_type not in FILE_TYPES:
            raise ValueError(f"Unknown file type for {record.path!r}: {record.file_type!r}.")
        if record.support_status not in SUPPORT_LABELS:
            raise ValueError(
                f"Unknown support status for {record.path!r}: {record.support_status!r}."
            )
        if record.eligibility not in ELIGIBILITY_LABELS:
            raise ValueError(f"Unknown eligibility for {record.path!r}: {record.eligibility!r}.")
        if record.parse_result is not None and record.parse_result not in PARSE_LABELS:
            raise ValueError(f"Unknown parse result for {record.path!r}: {record.parse_result!r}.")
    languages: dict[tuple[str | None, str], int] = {}
    for record in files:
        display = LANGUAGE_DISPLAY.get(record.language or "", record.language)
        languages[(display, SUPPORT_LABELS[record.support_status])] = (
            languages.get((display, SUPPORT_LABELS[record.support_status]), 0) + 1
        )
    parse_counts = {key: 0 for key in PARSE_SUMMARY_KEYS}
    for record in files:
        parse_counts[PARSE_LABELS.get(record.parse_result or "", "Not parsed")] += 1
    summary: dict[str, object] = {
        "languages": [
            {"language": language, "support": support, "file_count": count}
            for (language, support), count in sorted(
                languages.items(), key=lambda item: (str(item[0][0]), item[0][1])
            )
            if language is not None
        ],
        "files": {"indexed": len(files), "parse_results": parse_counts},
    }
    for area in AREAS:
        state = area_states[area]
        area_summary: dict[str, object] = {"state": state}
        if sections[area] is None:
            area_summary["findings"] = None
        else:
            area_summary["findings"] = _area_findings_block(finding_entries[area])
        summary[AREA_SECTIONS[area]] = area_summary
    architecture = summary["architecture"]
    assert isinstance(architecture, dict)
    if sections["architecture"] is not None:
        fan_in = [
            (m.value or 0, m.subject_path)
            for m in data.metrics
            if m.area == "architecture" and m.metric_name == "fan_in" and m.value is not None
        ]
        fan_out = [
            (m.value or 0, m.subject_path)
            for m in data.metrics
            if m.area == "architecture" and m.metric_name == "fan_out" and m.value is not None
        ]
        cycles = _cycle_section(finding_entries["architecture"])
        architecture.update(
            {
                "module_count": len(data.modules),
                "module_dependency_count": len(edges),
                "cycle_count": {"value": len(cycles), "unit": "cycles"},
                "fan_in": _fan_summary(fan_in),
                "fan_out": _fan_summary(fan_out),
            }
        )
    dependencies = summary["dependencies"]
    assert isinstance(dependencies, dict)
    if sections["dependency"] is not None:
        classes = [dependency.dependency_class for dependency in data.dependencies]
        with_advisories = sum(1 for dependency in data.dependencies if dependency.advisories)
        duplicates = sum(
            1
            for finding in data.findings
            if finding.category == "dependency" and finding.rule_id == "DEP-DUPLICATE-VERSION"
        )
        dependencies.update(
            {
                "dependency_count": {
                    "total": len(data.dependencies),
                    "direct": sum(1 for item in classes if item == "direct"),
                    "transitive": sum(1 for item in classes if item == "transitive"),
                },
                "vulnerable_count": with_advisories,
                "duplicate_version_package_count": duplicates,
            }
        )
    return summary


def _fan_summary(values: list[tuple[int, str]]) -> dict[str, object] | None:
    """Maximum fan descriptor with the modules attaining it, else None."""
    if not values:
        return None
    peak = max(value for value, _path in values)
    return {
        "max": peak,
        "module_ids": sorted(path for value, path in values if value == peak),
    }


def snapshot_view_from_data(data: SnapshotData) -> SnapshotView:
    """Build the comparison view of one sealed snapshot (docs/13 §15)."""
    analysis = data.analysis
    configuration = analysis.analysis_config
    if not isinstance(configuration, dict):
        raise ValueError("Snapshot comparison requires the persisted configuration snapshot.")
    return SnapshotView(
        analysis_id=analysis.id,
        repository_id=analysis.repository_id,
        commit_sha=analysis.resolved_commit_sha,
        timestamp=_iso(analysis.created_at),
        analyzer_version=analysis.analyzer_version,
        rule_set_version=analysis.rule_set_version,
        configuration=dict(configuration),
        advisory_source=analysis.advisory_source,
        advisory_status=analysis.advisory_status,
        findings=tuple(
            sorted(
                (finding.identity_key, finding.rule_id, finding.category, finding.finding_id)
                for finding in data.findings
            )
        ),
        domain_states=tuple(sorted((domain.area, domain.state) for domain in data.domain_states)),
        rule_states=tuple(
            sorted(
                (_area_of_rule(evaluation.rule_id), evaluation.rule_id, evaluation.state)
                for evaluation in data.rule_evaluations
            )
        ),
    )


def _comparison_entry(entry: ComparisonEntry) -> dict[str, object]:
    """One canonical comparison entry (docs/13 §15)."""
    record: dict[str, object] = {
        "identity_key": entry.identity_key,
        "rule_id": entry.rule_id,
        "category": entry.category,
    }
    if entry.base_finding_id is not None:
        record["base_finding_id"] = entry.base_finding_id
    if entry.target_finding_id is not None:
        record["target_finding_id"] = entry.target_finding_id
    if entry.qualified:
        record["qualified"] = True
    return record


def comparison_to_dict(result: ComparisonResult) -> dict[str, object]:
    """Serialize a comparison result to its canonical form (docs/13 §15)."""
    if not result.comparable:
        return {"comparable": False, "reason": result.reason}
    return {
        "comparable": True,
        "base": dict(result.base_context),
        "target": dict(result.target_context),
        "context_differences": dict(result.context_differences),
        "qualifications": [dict(item) for item in result.qualifications],
        "new": [_comparison_entry(entry) for entry in result.new],
        "resolved": [_comparison_entry(entry) for entry in result.resolved],
        "unchanged": [_comparison_entry(entry) for entry in result.unchanged],
    }
