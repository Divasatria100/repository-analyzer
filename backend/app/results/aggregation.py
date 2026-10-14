"""Analysis result aggregation (TASK-146/147, docs/10 §5.15).

Pure functions combining the four analyzer domains into one canonical
in-memory result. No database access, no network, no analyzer execution:
callers supply analyzer outputs plus file metadata. Deterministic for
equivalent inputs; source analyzer outputs are never mutated.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from app.analyzers.findings import Finding, Limitation

#: Canonical domain states (docs/10 §7.2, docs/13 §6.3, FR-100).
NO_FINDINGS = "No findings detected"
NOT_PERFORMED = "Analysis not performed"
FAILED = "Analysis failed"
INCOMPLETE = "Analysis incomplete"
UNAVAILABLE = "Analysis unavailable"

DOMAIN_STATES = frozenset({NO_FINDINGS, NOT_PERFORMED, FAILED, INCOMPLETE, UNAVAILABLE})

#: Canonical rule evaluation states (docs/10 §7.2, docs/13 §6.4).
EVALUATED = "Evaluated"
PARTIALLY_EVALUATED = "Partially evaluated"
NOT_EVALUATED = "Not evaluated"
RULE_FAILED = "Failed"

RULE_EVAL_STATES = frozenset({EVALUATED, PARTIALLY_EVALUATED, NOT_EVALUATED, RULE_FAILED})

#: Canonical file coverage states (docs/10 §7.2, docs/13 §13).
FULLY_ANALYZED = "Fully analyzed"
PARTIALLY_ANALYZED = "Partially analyzed"
NOT_ANALYZED = "Not analyzed"
FILE_FAILED = "Failed"

FILE_COVERAGE_STATES = frozenset({FULLY_ANALYZED, PARTIALLY_ANALYZED, NOT_ANALYZED, FILE_FAILED})

#: Terminal outcomes (docs/10 §7.2).
COMPLETED = "Completed"
COMPLETED_WITH_LIMITATIONS = "Completed with limitations"
ANALYSIS_FAILED = "Failed"

TERMINAL_OUTCOMES = frozenset({COMPLETED, COMPLETED_WITH_LIMITATIONS, ANALYSIS_FAILED})

#: Canonical areas in stable presentation order.
AREAS = ("security", "dependency", "architecture", "code_structure")

#: Analyzer coverage statuses meaning "ran to completion for its scope".
_COVERED_STATUSES = frozenset({"covered", "supported"})
#: Analyzer coverage statuses meaning "ran only in part".
_PARTIAL_STATUSES = frozenset({"partially_covered", "partial"})
#: Analyzer coverage statuses meaning "did not run for lack of scope".
_SKIPPED_STATUSES = frozenset({"unsupported", "not_applicable"})


@dataclass(frozen=True)
class RuleCoverage:
    """Normalized per-rule coverage from any analyzer's coverage vocabulary."""

    rule_id: str
    status: str
    reason: str = ""


@dataclass(frozen=True)
class FileMeta:
    """File index metadata consumed for coverage derivation (plain data)."""

    path: str
    file_type: str = "other"
    extension: str = ""
    size: int = 0
    language: str | None = None
    support_status: str = "unrecognized"
    is_binary: bool = False
    is_generated: bool = False
    excluded: bool = False
    exclusion_reason: str | None = None
    eligibility: str = "not_eligible"
    eligibility_reason: str = ""
    parse_result: str | None = None


@dataclass(frozen=True)
class AdvisoryInfo:
    """Which advisory source was consulted, when, and with what outcome.

    Outcome vocabulary is exactly docs/13 §4.3: ``Succeeded``,
    ``Partly succeeded``, ``Unavailable``.
    """

    source: str
    consulted_at: datetime | None = None
    status: str = "Unavailable"


#: Per-rule signal sets for the architecture configuration block
#: (docs/13 §4.2: thresholds keyed by rule identifier).
ARCH_RULE_THRESHOLDS = {
    "ARCH-HIGH-FAN-OUT": ("fan_out",),
    "ARCH-HIGH-FAN-IN": ("fan_in",),
    "ARCH-HIGH-COUPLING": ("coupling",),
    "ARCH-LARGE-MODULE": ("module_lines", "module_declarations"),
    "ARCH-LARGE-CLASS": ("class_lines", "class_methods"),
    "ARCH-LARGE-FUNCTION": ("function_lines", "function_complexity"),
}

#: Coupling definition identifier, versioned with the rule set (ARCH-REQ-032).
COUPLING_DEFINITION = "coupling-def-1"


def default_configuration(thresholds: dict[str, object]) -> dict[str, object]:
    """Build the canonical analysis configuration snapshot (docs/13 §4.2).

    Generated files default to included in V1.0 (no exclusion setting
    exists; the file index records per-file treatment explicitly).
    """
    architecture_thresholds = {
        rule_id: {signal: thresholds[signal] for signal in signals if signal in thresholds}
        for rule_id, signals in ARCH_RULE_THRESHOLDS.items()
    }
    return {
        "generated_files": "Included",
        "architecture": {
            "coupling_definition": COUPLING_DEFINITION,
            "thresholds": architecture_thresholds,
        },
        "thresholds": dict(sorted(thresholds.items())),
    }


@dataclass(frozen=True)
class AnalysisMeta:
    """Aggregation-time analysis context (plain data, no ORM)."""

    analysis_id: str
    repository_id: str
    resolved_commit_sha: str | None = None
    resolved_branch: str | None = None
    analyzer_version: str = ""
    rule_set_version: str = ""
    configuration: dict[str, object] | None = None
    advisory: AdvisoryInfo | None = None


@dataclass
class DomainInput:
    """One domain's analyzer outputs for aggregation (never mutated)."""

    analyzer_id: str
    category: str
    findings: tuple[Finding, ...] = ()
    rule_failures: tuple[str, ...] = ()
    analyzer_failed: bool = False
    coverages: tuple[RuleCoverage, ...] = ()
    limitations: tuple[Limitation, ...] = ()
    limited: bool = False


@dataclass(frozen=True)
class DomainResult:
    """Aggregated per-domain state with reason."""

    category: str
    state: str | None
    reason: str | None = None


@dataclass(frozen=True)
class RuleEvaluationRecord:
    """Aggregated per-rule evaluation state."""

    category: str
    rule_id: str
    state: str
    reason: str | None = None


@dataclass(frozen=True)
class FileCoverageRecord:
    """Aggregated per-file, per-scope coverage (only non-Fully states)."""

    path: str
    scope_kind: str  # "area"
    scope_value: str
    state: str
    reason: str | None = None


@dataclass
class AggregatedResult:
    """Canonical in-memory aggregation (deterministic, immutable inputs)."""

    meta: AnalysisMeta
    findings: tuple[Finding, ...] = ()
    domains: tuple[DomainResult, ...] = ()
    rule_evaluations: tuple[RuleEvaluationRecord, ...] = ()
    file_coverages: tuple[FileCoverageRecord, ...] = ()
    limitations: tuple[Limitation, ...] = ()
    outcome: str = ANALYSIS_FAILED
    outcome_explanation: str = ""


def normalize_coverage_status(status: str) -> str:
    """Map an analyzer coverage status to a canonical rule-evaluation state."""
    normalized = status.strip().lower()
    if normalized == "failed":
        return RULE_FAILED
    if normalized in _PARTIAL_STATUSES:
        return PARTIALLY_EVALUATED
    if normalized in _SKIPPED_STATUSES:
        return NOT_EVALUATED
    if normalized in _COVERED_STATUSES:
        return EVALUATED
    raise ValueError(f"Unknown coverage status: {status!r}")


def derive_domain_state(bundle: DomainInput) -> DomainResult:
    """Derive one domain's canonical state with an explicit reason.

    Precedence (all explicit and tested): analyzer failure, then failed
    coverage, then any rule failure, then any partial coverage or domain
    limitation flag, then no coverage at all, then all-unsupported, else
    clean (None when findings exist, "No findings detected" otherwise).
    """
    coverage_by_rule = {item.rule_id: item for item in bundle.coverages}
    failed_coverages = sorted(
        rule_id
        for rule_id, item in coverage_by_rule.items()
        if item.status.strip().lower() == "failed"
    )
    if bundle.analyzer_failed:
        return DomainResult(
            bundle.category, FAILED, f"The {bundle.category} analyzer did not complete."
        )
    if failed_coverages:
        return DomainResult(
            bundle.category,
            FAILED,
            f"Coverage failed for: {', '.join(failed_coverages)}.",
        )
    if bundle.rule_failures:
        return DomainResult(
            bundle.category,
            INCOMPLETE,
            f"Rules failed: {', '.join(sorted(bundle.rule_failures))}; "
            "sibling findings are preserved.",
        )
    partial = sorted(
        rule_id
        for rule_id, item in coverage_by_rule.items()
        if item.status.strip().lower() in _PARTIAL_STATUSES
    )
    if partial or bundle.limited:
        detail = f" Partially covered rules: {', '.join(partial)}." if partial else ""
        if bundle.limited:
            detail += " Domain processing reported incomplete data."
        return DomainResult(
            bundle.category,
            INCOMPLETE,
            f"The {bundle.category} area completed only in part.{detail}",
        )
    if not bundle.coverages:
        return DomainResult(
            bundle.category, NOT_PERFORMED, f"No rule coverage was reported for {bundle.category}."
        )
    if all(item.status.strip().lower() in _SKIPPED_STATUSES for item in bundle.coverages):
        return DomainResult(
            bundle.category,
            NOT_PERFORMED,
            f"No supported content was evaluated for {bundle.category}.",
        )
    if bundle.findings:
        return DomainResult(bundle.category, None, None)
    return DomainResult(bundle.category, NO_FINDINGS, None)


def derive_rule_evaluations(
    bundle: DomainInput, registered_rules: tuple[str, ...] = ()
) -> list[RuleEvaluationRecord]:
    """Derive per-rule states; rule failures override coverage states."""
    failures = set(bundle.rule_failures)
    coverage_by_rule = {item.rule_id: item for item in bundle.coverages}
    rule_ids = list(registered_rules) if registered_rules else sorted(coverage_by_rule)
    records: list[RuleEvaluationRecord] = []
    for rule_id in rule_ids:
        if rule_id in failures:
            records.append(
                RuleEvaluationRecord(
                    bundle.category, rule_id, RULE_FAILED, "The rule did not complete."
                )
            )
            continue
        coverage = coverage_by_rule.get(rule_id)
        if coverage is None:
            records.append(
                RuleEvaluationRecord(
                    bundle.category,
                    rule_id,
                    NOT_EVALUATED,
                    "No coverage was reported for the rule.",
                )
            )
            continue
        state = normalize_coverage_status(coverage.status)
        records.append(
            RuleEvaluationRecord(bundle.category, rule_id, state, coverage.reason or None)
        )
    return records


def _file_coverage_for_area(meta: FileMeta, area: str) -> FileCoverageRecord | None:
    """Derive one file/area coverage row; None means Fully analyzed.

    Manifest files are assessed by the dependency area from manifest parse
    outcomes supplied separately; here a manifest is Not analyzed for the
    source areas. Language/support/parse data drives the rest.
    """
    if area == "dependency":
        if meta.file_type == "manifest":
            return None  # resolved by the dependency bundle, not the index row
        return FileCoverageRecord(
            meta.path,
            "area",
            area,
            NOT_ANALYZED,
            f"Not a dependency manifest; not evaluated by {area}.",
        )
    language = (meta.language or "").lower()
    if language != "python":
        return FileCoverageRecord(
            meta.path, "area", area, NOT_ANALYZED, "Language not supported for source analysis."
        )
    if meta.parse_result == "failed":
        return FileCoverageRecord(meta.path, "area", area, FILE_FAILED, "File failed to parse.")
    if meta.parse_result in ("parsed_with_diagnostics",):
        return FileCoverageRecord(
            meta.path, "area", area, PARTIALLY_ANALYZED, "File parsed with diagnostics."
        )
    if meta.parse_result is None:
        return FileCoverageRecord(meta.path, "area", area, NOT_ANALYZED, "File was not parsed.")
    return None


def derive_file_coverages(
    files: list[FileMeta],
    manifest_states: dict[str, str] | None = None,
) -> list[FileCoverageRecord]:
    """Derive sparse file coverages (only non-Fully states are recorded)."""
    manifest_states = manifest_states or {}
    records: list[FileCoverageRecord] = []
    for meta in sorted(files, key=lambda item: item.path):
        for area in AREAS:
            if area == "dependency" and meta.file_type == "manifest":
                state = manifest_states.get(meta.path, NOT_ANALYZED)
                if state != FULLY_ANALYZED:
                    reason = {
                        PARTIALLY_ANALYZED: "Manifest only partially recognized.",
                        FILE_FAILED: "Manifest could not be analyzed.",
                    }.get(state, "Manifest was not evaluated for dependency analysis.")
                    records.append(FileCoverageRecord(meta.path, "area", area, state, reason))
                continue
            record = _file_coverage_for_area(meta, area)
            if record is not None:
                records.append(record)
    records.sort(key=lambda item: (item.path, item.scope_kind, item.scope_value, item.state))
    return records


def aggregate(
    meta: AnalysisMeta,
    files: list[FileMeta],
    domains: list[DomainInput],
    manifest_states: dict[str, str] | None = None,
    registered_rules: dict[str, tuple[str, ...]] | None = None,
) -> AggregatedResult:
    """Combine analyzer outputs into one canonical, deterministic result.

    Findings dedupe by stable identity (first in sorted order wins; the
    collision is recorded, never silent). No finding is synthesized, no
    value is rescaled, and no score is computed. Exactly one input bundle
    per domain is expected: duplicate categories raise instead of
    silently discarding one bundle's states.
    """
    registered_rules = registered_rules or {}
    categories = [bundle.category for bundle in domains]
    duplicates = sorted({category for category in categories if categories.count(category) > 1})
    if duplicates:
        raise ValueError(f"Duplicate domain inputs for categories: {duplicates!r}.")
    seen: set[str] = set()
    findings: list[Finding] = []
    duplicate_notices: list[str] = []
    for bundle in sorted(domains, key=lambda item: (item.category, item.analyzer_id)):
        for finding in sorted(
            bundle.findings,
            key=lambda item: (
                item.rule_id,
                item.location.file_path,
                item.location.start_line,
                item.identity_key,
            ),
        ):
            if finding.identity_key in seen:
                duplicate_notices.append(
                    f"Duplicate identity {finding.identity_key} from {finding.rule_id}; kept first."
                )
                continue
            seen.add(finding.identity_key)
            findings.append(finding)
    domain_results: list[DomainResult] = []
    rule_records: list[RuleEvaluationRecord] = []
    limitations: list[Limitation] = []
    by_category = {bundle.category: bundle for bundle in domains}
    for area in AREAS:
        area_bundle = by_category.get(area)
        if area_bundle is None:
            domain_results.append(
                DomainResult(area, UNAVAILABLE, f"No {area} analyzer output was provided.")
            )
            continue
        domain_results.append(derive_domain_state(area_bundle))
        rule_records.extend(derive_rule_evaluations(area_bundle, registered_rules.get(area, ())))
        limitations.extend(area_bundle.limitations)
    if duplicate_notices:
        limitations.append(
            Limitation(
                scope="analysis",
                reason="; ".join(sorted(set(duplicate_notices))),
            )
        )
    file_coverages = derive_file_coverages(files, manifest_states)
    outcome, explanation = derive_outcome(domain_results, rule_records, list(limitations))
    return AggregatedResult(
        meta=meta,
        findings=tuple(findings),
        domains=tuple(domain_results),
        rule_evaluations=tuple(
            sorted(rule_records, key=lambda item: (item.category, item.rule_id))
        ),
        file_coverages=tuple(file_coverages),
        limitations=tuple(
            sorted(limitations, key=lambda item: (item.scope, item.path or "", item.reason))
        ),
        outcome=outcome,
        outcome_explanation=explanation,
    )


def derive_outcome(
    domains: list[DomainResult],
    rule_records: list[RuleEvaluationRecord],
    limitations: list[Limitation],
) -> tuple[str, str]:
    """Derive the terminal outcome from states, evaluations, and limitations.

    Completed coexists only with "No findings detected"/null domains, all
    Evaluated rules, and zero recorded limitations (docs/13 §6.6). Failed
    requires that no domain produced usable output. Anything else that
    finished is Completed with limitations.
    """
    if not domains:
        return ANALYSIS_FAILED, "No analyzer domain produced output."
    if all(item.state in (FAILED, UNAVAILABLE) for item in domains):
        failed = sorted(item.category for item in domains if item.state == FAILED)
        detail = f" Failed domains: {', '.join(failed)}." if failed else ""
        return ANALYSIS_FAILED, f"No domain produced usable output.{detail}"
    clean_domains = all(item.state in (NO_FINDINGS, None) for item in domains)
    clean_rules = all(item.state == EVALUATED for item in rule_records)
    if clean_domains and clean_rules and not limitations:
        return COMPLETED, ""
    parts: list[str] = []
    for domain in sorted(domains, key=lambda entry: entry.category):
        if domain.state not in (NO_FINDINGS, None):
            parts.append(f"{domain.category}: {domain.state}")
    for record in sorted(rule_records, key=lambda entry: (entry.category, entry.rule_id)):
        if record.state != EVALUATED:
            parts.append(f"{record.rule_id}: {record.state}")
    if limitations:
        parts.append(f"{len(limitations)} recorded limitation(s)")
    return COMPLETED_WITH_LIMITATIONS, "Partial completion: " + "; ".join(parts) + "."
