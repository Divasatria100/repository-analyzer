"""Dependency analyzer execution pipeline (Phase 8, TASK-112–121).

The ``dependency`` analyzer runs the four registered V1.0 rules
(docs/10 §5.11A DEP-REQ-001–004) through the existing Phase 6 machinery:

* identity via :class:`app.analyzers.base.Analyzer` (``id = "dependency"``),
* deterministic rule-ID order, per-rule failure isolation (inherited),
* findings through the common Finding model only (TASK-121).

Conceptual flow (static only): indexed repository → manifest discovery →
ecosystem detection → manifest/lockfile parsing (read as data) →
normalized occurrences → direct/transitive classification → local
detections (duplicate/count/unused candidates) → OSV advisory lookup →
normalized results → findings + limitations → existing report flow.

The analyzer consumes :class:`AnalysisContext` (NCM + versions +
thresholds) plus a narrow :class:`ManifestProvider` for bounded read-as-data
manifest access and an optional :class:`OsvClient` for advisory matching
(injected like the security ``SourceProvider``; the context itself never
carries network clients). Nothing is installed, executed, imported, or
resolved through a package manager; OSV is the only external integration.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path

from app.analyzers.base import Analyzer
from app.analyzers.dependency.classification import classify_occurrences
from app.analyzers.dependency.detection import (
    DuplicateVersionGroup,
    count_with_completeness,
    find_duplicate_versions,
    find_unused_candidates,
)
from app.analyzers.dependency.discovery import (
    discover_from_index,
    index_paths_from_ncm,
)
from app.analyzers.dependency.identity import identity_key
from app.analyzers.dependency.metadata import (
    DEPENDENCY_ANALYZER_ID,
    DEPENDENCY_ANALYZER_VERSION,
    DEPENDENCY_RULE_SPECS,
    DUPLICATE_VERSION_SPEC,
    HIGH_DEPENDENCY_COUNT_SPEC,
    KNOWN_VULNERABILITY_SPEC,
    UNUSED_CANDIDATE_SPEC,
    DependencyRuleSpec,
)
from app.analyzers.dependency.models import (
    Advisory,
    DependencyOccurrence,
    ManifestOutcome,
    ManifestRef,
    SupportState,
)
from app.analyzers.dependency.osv import (
    OsvClient,
    OsvOutcome,
    OsvQuery,
    advisory_status,
    build_queries,
)
from app.analyzers.dependency.parsers import parse_manifest_text, read_manifest_text
from app.analyzers.findings import (
    Confidence,
    Evidence,
    Finding,
    Limitation,
    Severity,
    create_finding,
)
from app.analyzers.redaction import mask_secrets
from app.analyzers.rules import (
    RegisteredRule,
    RuleExecutionContext,
    RuleMetadata,
    RuleOutcome,
)
from app.core.logging import get_logger, log_event
from app.ncm import SourceLocation

_logger = get_logger("analyzers.dependency")


class ManifestProvider:
    """Narrow manifest access: discovery refs plus bounded text reads."""

    def manifests(self) -> list[ManifestRef]:
        """Discovered manifest refs in deterministic order."""
        raise NotImplementedError

    def read(self, ref: ManifestRef) -> str | None:
        """Bounded manifest text as data, or None when unavailable."""
        raise NotImplementedError

    def discovery_limitations(self) -> list[str]:
        """Limitations recorded during discovery (never silent)."""
        return []


class DictManifestProvider(ManifestProvider):
    """In-memory provider over ``{path: text}`` (tests, deterministic)."""

    def __init__(self, files: dict[str, str]) -> None:
        self._files = dict(files)
        discovery = discover_from_index(list(files.keys()))
        self._manifests = discovery.manifests
        self._limitations = list(discovery.limitations)

    def manifests(self) -> list[ManifestRef]:
        return list(self._manifests)

    def read(self, ref: ManifestRef) -> str | None:
        return self._files.get(ref.path)

    def discovery_limitations(self) -> list[str]:
        return list(self._limitations)


class WorkspaceManifestProvider(ManifestProvider):
    """Workspace-backed provider: discovery from the file index, reads as data."""

    def __init__(
        self,
        *,
        workspaces: object,
        workspace: Path,
        indexed_paths: list[str],
        file_max_bytes: int,
    ) -> None:
        self._workspaces = workspaces
        self._workspace = workspace
        self._file_max_bytes = file_max_bytes
        discovery = discover_from_index(
            indexed_paths,
            workspace=workspace,
            workspaces=workspaces,
            file_max_bytes=file_max_bytes,
        )
        self._manifests = discovery.manifests
        self._limitations = list(discovery.limitations)

    def manifests(self) -> list[ManifestRef]:
        return list(self._manifests)

    def read(self, ref: ManifestRef) -> str | None:
        return read_manifest_text(
            workspace=self._workspace,
            workspaces=self._workspaces,
            ref=ref,
            file_max_bytes=self._file_max_bytes,
        )

    def discovery_limitations(self) -> list[str]:
        return list(self._limitations)


@dataclass
class Inventory:
    """Normalized dependency inventory: occurrences plus parse products."""

    occurrences: list[DependencyOccurrence]
    outcomes: list[ManifestOutcome]
    discovery_limitations: list[str]
    texts: dict[str, str]


def build_inventory(provider: ManifestProvider) -> Inventory:
    """Discover, read, parse, and classify every manifest (deterministic)."""
    outcomes: list[ManifestOutcome] = []
    texts: dict[str, str] = {}
    for ref in sorted(provider.manifests(), key=lambda item: item.path):
        text = provider.read(ref)
        if text is None:
            outcomes.append(
                ManifestOutcome(
                    ref=ManifestRef(
                        path=ref.path,
                        kind=ref.kind,
                        format=ref.format,
                        ecosystem=ref.ecosystem,
                        project_context=ref.project_context,
                        support_state=SupportState.FAILED,
                    ),
                    reasons=["manifest could not be read safely; recorded as failed"],
                )
            )
            continue
        texts[ref.path] = text
        outcomes.append(parse_manifest_text(text, ref))
    occurrences = classify_occurrences(outcomes)
    occurrences.sort(
        key=lambda occ: (
            occ.ecosystem,
            occ.canonical_name,
            occ.source_file,
            occ.source_line or 0,
            occ.section,
        )
    )
    return Inventory(
        occurrences=occurrences,
        outcomes=outcomes,
        discovery_limitations=provider.discovery_limitations(),
        texts=texts,
    )


def occurrence_evidence(occurrence: DependencyOccurrence, texts: dict[str, str]) -> Evidence | None:
    """Single redacted declaration line as evidence (None when unavailable)."""
    text = texts.get(occurrence.source_file)
    line_number = occurrence.source_line
    if text is None or line_number is None:
        return None
    lines = text.splitlines()
    if line_number < 1 or line_number > len(lines):
        return None
    masked, had_secret = mask_secrets(lines[line_number - 1])
    return Evidence(
        path=occurrence.source_file,
        start_line=line_number,
        end_line=line_number,
        lines=(masked,),
        truncated=False,
        redacted=had_secret,
    )


def occurrence_location(occurrence: DependencyOccurrence) -> SourceLocation:
    """Finding location for one occurrence (repository-relative, 1-based)."""
    line = occurrence.source_line or 1
    return SourceLocation(
        file_path=occurrence.source_file,
        start_line=line,
        start_column=0,
        end_line=line,
        end_column=0,
    )


def manifest_limitations(outcomes: list[ManifestOutcome]) -> list[Limitation]:
    """Explicit limitations for failed/partial/unsupported manifests."""
    limitations: list[Limitation] = []
    for outcome in sorted(outcomes, key=lambda item: item.ref.path):
        ref = outcome.ref
        if ref.support_state == SupportState.FAILED:
            limitations.append(
                Limitation(
                    scope=f"dependency:{ref.path}",
                    reason="A manifest/lockfile should have been supported but could "
                    "not be analyzed; it is not treated as having no "
                    f"dependencies. Details: {'; '.join(outcome.reasons) or 'parse failure'}",
                    path=ref.path,
                )
            )
        elif ref.support_state == SupportState.PARTIAL:
            limitations.append(
                Limitation(
                    scope=f"dependency:{ref.path}",
                    reason="Only part of this manifest is recognized; coverage is "
                    f"partial. Details: {'; '.join(outcome.reasons) or 'partial support'}",
                    path=ref.path,
                )
            )
        elif ref.support_state == SupportState.UNSUPPORTED:
            limitations.append(
                Limitation(
                    scope=f"dependency:{ref.path}",
                    reason="This manifest format is outside the V1.0 boundary; "
                    "recorded as unsupported, not as evidence of no dependencies.",
                    path=ref.path,
                )
            )
        elif outcome.reasons:
            limitations.append(
                Limitation(
                    scope=f"dependency:{ref.path}",
                    reason="; ".join(outcome.reasons),
                    path=ref.path,
                )
            )
    return limitations


def introduced_by_chains(
    group: DuplicateVersionGroup, outcomes: list[ManifestOutcome]
) -> dict[str, list[str]]:
    """Map each resolved version to the lockfile parents introducing it.

    Built only from statically recorded relationships (``introduced_by``
    chains per DEP-REQ-002). Matching is version-aware: when an edge records
    an exact child version, only occurrences with that resolved version
    receive the parent; edges with range/unknown child versions attribute to
    every same-name occurrence in that file (the only supportable reading —
    e.g. Poetry constraints carry no exact version). Versions without
    recorded parents carry an empty chain rather than a fabricated one.
    """
    from app.analyzers.dependency.identity import is_plausible_exact_version

    parents: dict[str, dict[str, set[str]]] = {}
    for outcome in outcomes:
        ecosystem = outcome.ref.ecosystem
        for relation in outcome.relationships:
            if identity_key(ecosystem, relation.child) != f"{ecosystem}:{group.canonical_name}":
                continue
            # Group members share one normalized identity by construction;
            # only the ecosystem and resolved version still discriminate.
            for occ in group.occurrences:
                if occ.ecosystem != ecosystem or occ.resolved_version is None:
                    continue
                child_version = relation.child_version
                if child_version is not None and is_plausible_exact_version(child_version):
                    if occ.resolved_version.strip() != child_version.strip():
                        continue
                parents.setdefault(occ.resolved_version, {}).setdefault(
                    outcome.ref.path, set()
                ).add(relation.parent)
    chains: dict[str, list[str]] = {}
    for version in group.versions:
        entries: list[str] = []
        for path in sorted(parents.get(version, {})):
            for parent in sorted(parents[version][path]):
                entries.append(f"{parent} ({path})")
        chains[version] = entries
    return chains


def _sort_findings(findings: list[Finding]) -> list[Finding]:
    return sorted(
        findings,
        key=lambda item: (
            item.location.file_path,
            item.location.start_line,
            item.location.start_column,
            item.rule_id,
            item.identity_key,
        ),
    )


def _dedupe(findings: list[Finding]) -> list[Finding]:
    seen: set[str] = set()
    unique: list[Finding] = []
    for finding in _sort_findings(findings):
        if finding.identity_key in seen:
            continue
        seen.add(finding.identity_key)
        unique.append(finding)
    return unique


def _base_limitations(
    rule_id: str, inventory: Inventory, extra: list[Limitation] | None = None
) -> list[Limitation]:
    limitations = manifest_limitations(inventory.outcomes)
    for reason in inventory.discovery_limitations:
        limitations.append(Limitation(scope=f"dependency:{rule_id}", reason=reason))
    limitations.extend(extra or [])
    return limitations


# --- Rule executors ---------------------------------------------------------


def execute_duplicate_version(
    execution_context: RuleExecutionContext, inventory: Inventory
) -> RuleOutcome:
    """DEP-DUPLICATE-VERSION (DEP-REQ-002): Low severity, High confidence."""
    context = execution_context.context
    groups, compare_notes = find_duplicate_versions(inventory.occurrences)
    extra = [
        Limitation(scope=f"dependency:{DUPLICATE_VERSION_SPEC.rule_id}", reason=note)
        for note in compare_notes
    ]
    findings: list[Finding] = []
    for group in groups:
        chains = introduced_by_chains(group, inventory.outcomes)
        first = group.occurrences[0]
        occurrence_lines = [
            f"- {occ.project_context or '/'}: {occ.original_name} "
            f"{occ.resolved_version} [{occ.dependency_class.value}] ({occ.source_file})"
            for occ in group.occurrences
        ]
        chain_lines = []
        for version in group.versions:
            parents = chains.get(version, [])
            if parents:
                chain_lines.append(f"- {version} introduced by: {', '.join(parents)}")
            else:
                chain_lines.append(f"- {version}: no introducing parent was statically recorded")
        description = (
            f"Package {group.canonical_name} ({group.ecosystem}) occurs with "
            f"{len(group.versions)} distinct resolved versions "
            f"({', '.join(group.versions)}) in one analysis. "
            "Affected occurrences:\n" + "\n".join(occurrence_lines) + "\n"
            "Introduced-by chains (statically recorded only):\n" + "\n".join(chain_lines)
        )
        if len(group.project_contexts) > 1:
            description += (
                "\nOccurrences span separate project contexts "
                f"({', '.join(context or '/' for context in group.project_contexts)}); "
                "each context keeps its own provenance above and they are not "
                "claimed to form a single dependency graph."
            )
        evidence = occurrence_evidence(first, inventory.texts)
        rule_limitations = list(extra)
        if evidence is None:
            rule_limitations.append(
                Limitation(
                    scope=f"dependency:{DUPLICATE_VERSION_SPEC.rule_id}",
                    reason="Source excerpt was unavailable; the finding rests on "
                    "the normalized occurrence records described above.",
                    path=first.source_file,
                    rule_id=DUPLICATE_VERSION_SPEC.rule_id,
                )
            )
        findings.append(
            create_finding(
                rule_id=DUPLICATE_VERSION_SPEC.rule_id,
                analyzer_id=DEPENDENCY_ANALYZER_ID,
                category="dependency",
                title=f"Duplicate resolved versions: {group.canonical_name}",
                description=description,
                severity=Severity.LOW,
                confidence=Confidence.HIGH,
                location=occurrence_location(first),
                evidence=evidence,
                recommendation=DUPLICATE_VERSION_SPEC.recommendation,
                limitations=tuple(rule_limitations),
                analyzer_version=context.analyzer_version,
                rule_set_version=context.rule_set_version,
                severity_factors=("distinct exact resolved versions counted",),
                confidence_factors=("direct count of recorded occurrences",),
                analysis_id=context.analysis_id,
                subject_key=f"{group.ecosystem}:{group.canonical_name}:{','.join(group.versions)}",
            )
        )
    return RuleOutcome(
        findings=_dedupe(findings),
        limitations=_base_limitations(DUPLICATE_VERSION_SPEC.rule_id, inventory, extra),
    )


def execute_high_dependency_count(
    execution_context: RuleExecutionContext, inventory: Inventory
) -> RuleOutcome:
    """DEP-HIGH-DEPENDENCY-COUNT (DEP-REQ-003): strict ``>`` per scope."""
    from app.analyzers.thresholds import default_thresholds

    context = execution_context.context
    try:
        threshold = context.thresholds.dependencies
    except (AttributeError, ValueError):
        threshold = default_thresholds().dependencies
    incomplete_scopes = {
        outcome.ref.ecosystem
        for outcome in inventory.outcomes
        if outcome.ref.support_state in (SupportState.FAILED, SupportState.PARTIAL)
    }
    counts = count_with_completeness(inventory.occurrences, incomplete_scopes)
    findings: list[Finding] = []
    for scope in counts:
        if scope.count <= threshold:
            continue
        first = next(occ for occ in inventory.occurrences if occ.ecosystem == scope.ecosystem)
        description = (
            f"Scope {scope.ecosystem} declares {scope.count} total dependency "
            f"occurrences (direct + transitive), strictly above the threshold "
            f"of {threshold} occurrences per scope. This is a complexity "
            "indicator, not a vulnerability."
        )
        if scope.incomplete:
            description += (
                " Scopes with uninterpretable manifests are potentially "
                "incomplete, and this count states so."
            )
        evidence = occurrence_evidence(first, inventory.texts)
        findings.append(
            create_finding(
                rule_id=HIGH_DEPENDENCY_COUNT_SPEC.rule_id,
                analyzer_id=DEPENDENCY_ANALYZER_ID,
                category="dependency",
                title=f"High dependency count in scope {scope.ecosystem}",
                description=description,
                severity=Severity.LOW,
                confidence=Confidence.HIGH,
                location=occurrence_location(first),
                evidence=evidence,
                recommendation=HIGH_DEPENDENCY_COUNT_SPEC.recommendation,
                limitations=(),
                analyzer_version=context.analyzer_version,
                rule_set_version=context.rule_set_version,
                applied_thresholds=(("dependencies", threshold),),
                severity_factors=("occurrence count strictly exceeds threshold",),
                confidence_factors=("direct count of recorded occurrences",),
                analysis_id=context.analysis_id,
                subject_key=f"{scope.ecosystem}:count:{scope.count}",
            )
        )
    return RuleOutcome(
        findings=_dedupe(findings),
        limitations=_base_limitations(HIGH_DEPENDENCY_COUNT_SPEC.rule_id, inventory),
    )


def execute_unused_candidate(
    execution_context: RuleExecutionContext, inventory: Inventory
) -> RuleOutcome:
    """DEP-UNUSED-CANDIDATE (DEP-REQ-004): candidate wording, Info/Low always."""
    context = execution_context.context
    candidates, notes = find_unused_candidates(inventory.occurrences, context.ncm)
    extra = [
        Limitation(scope=f"dependency:{UNUSED_CANDIDATE_SPEC.rule_id}", reason=note)
        for note in notes
    ]
    npm_direct = sum(
        1
        for occ in inventory.occurrences
        if occ.ecosystem == "npm" and occ.dependency_class.value == "direct"
    )
    if npm_direct:
        extra.append(
            Limitation(
                scope=f"dependency:{UNUSED_CANDIDATE_SPEC.rule_id}",
                reason="npm scopes are not evaluated for unused candidates in V1.0 "
                "(no supported JavaScript import analysis); no conclusion was "
                "drawn for npm dependencies",
            )
        )
    findings: list[Finding] = []
    for candidate in candidates:
        occ = candidate.occurrence
        description = (
            f"Potentially unused dependency: no usage of {occ.original_name} "
            f"({occ.ecosystem}) was statically observed in analyzed source; "
            "manual review required. " + candidate.coverage_note
        )
        evidence = occurrence_evidence(occ, inventory.texts)
        findings.append(
            create_finding(
                rule_id=UNUSED_CANDIDATE_SPEC.rule_id,
                analyzer_id=DEPENDENCY_ANALYZER_ID,
                category="dependency",
                title=f"Potentially unused dependency: {occ.original_name}",
                description=description,
                severity=Severity.INFO,
                confidence=Confidence.LOW,
                location=occurrence_location(occ),
                evidence=evidence,
                recommendation=UNUSED_CANDIDATE_SPEC.recommendation,
                limitations=(),
                analyzer_version=context.analyzer_version,
                rule_set_version=context.rule_set_version,
                confidence_factors=("static heuristic only; usage may be hidden",),
                analysis_id=context.analysis_id,
                subject_key=f"{occ.ecosystem}:{occ.canonical_name}:unused-candidate",
            )
        )
    return RuleOutcome(
        findings=_dedupe(findings),
        limitations=_base_limitations(UNUSED_CANDIDATE_SPEC.rule_id, inventory, extra),
    )


def _advisories_by_triple(
    queries: list[OsvQuery], outcome: OsvOutcome
) -> dict[tuple[str, str, str], tuple[Advisory, ...]]:
    """Bounded advisories keyed by (ecosystem, package, version).

    Only advisories actually obtained for an exact-version query are
    recorded; they feed the dependency-level ``advisories`` associations
    (docs/12 §4.6.1, docs/13 §11.3). Duplicates are collapsed by id.
    """
    grouped: dict[tuple[str, str, str], dict[str, Advisory]] = {}
    for position, advisories in outcome.advisories.items():
        if position >= len(queries):
            continue
        query = queries[position]
        bucket = grouped.setdefault((query.ecosystem, query.package_name, query.version), {})
        for advisory in advisories:
            bucket.setdefault(advisory.advisory_id, advisory)
    return {key: tuple(bucket.values()) for key, bucket in grouped.items()}


def execute_known_vulnerability(
    execution_context: RuleExecutionContext,
    inventory: Inventory,
    analyzer: DependencyAnalyzer,
) -> RuleOutcome:
    """DEP-KNOWN-VULNERABILITY (DEP-REQ-001): exact-version matches only."""
    context = execution_context.context
    osv_client = analyzer.osv_client
    queries, skipped = build_queries(inventory.occurrences)
    extra = [
        Limitation(
            scope=f"dependency:{KNOWN_VULNERABILITY_SPEC.rule_id}",
            reason=f"occurrence {index}: {reason}; recorded instead of a finding",
        )
        for index, reason in sorted(skipped.items())
    ]
    if osv_client is None:
        analyzer.record_advisory_status(context.analysis_id, None)
        extra.append(
            Limitation(
                scope=f"dependency:{KNOWN_VULNERABILITY_SPEC.rule_id}",
                reason="Advisory information could not be obtained (no advisory "
                "client available); the absence of vulnerability matches is "
                "not a clean result.",
            )
        )
        return RuleOutcome(
            findings=[],
            limitations=_base_limitations(KNOWN_VULNERABILITY_SPEC.rule_id, inventory, extra),
        )
    outcome = osv_client.query_batch(queries)
    analyzer.record_advisory_status(context.analysis_id, advisory_status(outcome, len(queries)))
    analyzer.record_advisories(context.analysis_id, _advisories_by_triple(queries, outcome))
    if outcome.transport_failed:
        extra.append(
            Limitation(
                scope=f"dependency:{KNOWN_VULNERABILITY_SPEC.rule_id}",
                reason=f"Advisory lookup failed ({outcome.failure_reason or 'unavailable'}); "
                "valid local results are preserved and the absence of matches "
                "is not a clean result.",
            )
        )
    for position in sorted(outcome.failed_indexes):
        if position < len(queries):
            query = queries[position]
            extra.append(
                Limitation(
                    scope=f"dependency:{KNOWN_VULNERABILITY_SPEC.rule_id}",
                    reason=f"Advisory assessment failed for {query.package_name} "
                    f"{query.version} ({query.ecosystem}); not assessed as clean.",
                )
            )
    findings: list[Finding] = []
    for position, advisories in outcome.advisories.items():
        if position >= len(queries):
            continue
        query = queries[position]
        affected = [
            occ
            for occ in inventory.occurrences
            if occ.ecosystem == query.ecosystem
            and occ.canonical_name == query.package_name
            and (occ.resolved_version or "").strip() == query.version
        ]
        affected.sort(key=lambda occ: (occ.source_file, occ.source_line or 0))
        for advisory in sorted(advisories, key=lambda item: item.advisory_id):
            if not affected:
                continue
            first = affected[0]
            occurrence_lines = "\n".join(
                f"- {occ.original_name} {occ.resolved_version} "
                f"[{occ.dependency_class.value}] ({occ.source_file}"
                f"{':' + str(occ.source_line) if occ.source_line else ''})"
                for occ in affected
            )
            cve_part = ", ".join(
                alias for alias in advisory.aliases if alias.upper().startswith("CVE-")
            )
            alias_part = ", ".join(advisory.aliases) if advisory.aliases else "none recorded"
            description = (
                f"Advisory {advisory.advisory_id} affects {query.package_name} "
                f"{query.version} ({query.ecosystem}). This is advisory "
                "information for review, never a confirmed exploitable issue "
                "in the repository.\n"
                f"Aliases/CVE: {alias_part}"
                + (f" (CVE: {cve_part})" if cve_part else "")
                + f"\nSummary: {advisory.summary or 'not provided'}\n"
                f"Advisory severity information: {advisory.severity}\n"
                "Affected occurrences:\n" + occurrence_lines
            )
            evidence = occurrence_evidence(first, inventory.texts)
            rule_limitations: list[Limitation] = []
            if evidence is None:
                rule_limitations.append(
                    Limitation(
                        scope=f"dependency:{KNOWN_VULNERABILITY_SPEC.rule_id}",
                        reason="Source excerpt was unavailable; the finding rests on "
                        "the normalized occurrence records described above.",
                        path=first.source_file,
                        rule_id=KNOWN_VULNERABILITY_SPEC.rule_id,
                    )
                )
            findings.append(
                create_finding(
                    rule_id=KNOWN_VULNERABILITY_SPEC.rule_id,
                    analyzer_id=DEPENDENCY_ANALYZER_ID,
                    category="dependency",
                    title=f"Known vulnerability: {query.package_name} {query.version}",
                    description=description,
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    location=occurrence_location(first),
                    evidence=evidence,
                    recommendation=KNOWN_VULNERABILITY_SPEC.recommendation,
                    limitations=tuple(rule_limitations),
                    analyzer_version=context.analyzer_version,
                    rule_set_version=context.rule_set_version,
                    severity_factors=("exact-version advisory match",),
                    confidence_factors=("occurrence version is exact",),
                    analysis_id=context.analysis_id,
                    subject_key=(
                        f"{query.ecosystem}:{query.package_name}:"
                        f"{query.version}:{advisory.advisory_id}"
                    ),
                )
            )
    return RuleOutcome(
        findings=_dedupe(findings),
        limitations=_base_limitations(KNOWN_VULNERABILITY_SPEC.rule_id, inventory, extra),
    )


# --- Analyzer -----------------------------------------------------------------


def _bind(
    spec: DependencyRuleSpec,
    analyzer: DependencyAnalyzer,
    kind: str,
) -> RegisteredRule:
    """Bind a rule implementation to metadata plus analyzer-owned inputs."""

    def execute(execution_context: RuleExecutionContext) -> RuleOutcome:
        inventory = analyzer.inventory_for(execution_context.context)
        if kind == "known":
            return execute_known_vulnerability(execution_context, inventory, analyzer)
        if kind == "duplicate":
            return execute_duplicate_version(execution_context, inventory)
        if kind == "count":
            return execute_high_dependency_count(execution_context, inventory)
        return execute_unused_candidate(execution_context, inventory)

    metadata = RuleMetadata(
        rule_id=spec.rule_id,
        name=spec.name,
        description=spec.description,
        analyzer_id=DEPENDENCY_ANALYZER_ID,
        version=DEPENDENCY_ANALYZER_VERSION,
        default_severity=spec.default_severity,
        documentation_ref=spec.documentation_ref,
    )
    return RegisteredRule(metadata=metadata, execute=execute)


def build_dependency_rules(analyzer: DependencyAnalyzer) -> list[RegisteredRule]:
    """Build the registered dependency rules (deterministic rule-ID order)."""
    bound = [
        _bind(KNOWN_VULNERABILITY_SPEC, analyzer, "known"),
        _bind(DUPLICATE_VERSION_SPEC, analyzer, "duplicate"),
        _bind(HIGH_DEPENDENCY_COUNT_SPEC, analyzer, "count"),
        _bind(UNUSED_CANDIDATE_SPEC, analyzer, "unused"),
    ]
    return sorted(bound, key=lambda rule: rule.metadata.rule_id)


class DependencyAnalyzer(Analyzer):
    """Static dependency analyzer over manifests plus NCM usage evidence."""

    id = DEPENDENCY_ANALYZER_ID
    name = "Dependency Analyzer"
    version = DEPENDENCY_ANALYZER_VERSION

    def __init__(
        self,
        provider: ManifestProvider | None = None,
        osv_client: OsvClient | None = None,
    ) -> None:
        self._provider = provider
        self._osv_client = osv_client
        self._inventory_cache: dict[str, Inventory] = {}
        self._advisory_status: dict[str, str | None] = {}
        self._advisories: dict[str, dict[tuple[str, str, str], tuple[Advisory, ...]]] = {}

    @property
    def osv_client(self) -> OsvClient | None:
        """Injected advisory client (None means advisory-unavailable)."""
        return self._osv_client

    def record_advisory_status(self, analysis_id: str, status: str | None) -> None:
        """Record the advisory-data consultation status for one analysis.

        ``None`` means OSV was never consulted (no eligible query); a string
        is one of the persisted ``ADVISORY_STATUSES`` vocabulary. The
        pipeline reads this to record the honest advisory reference
        (PIPE-REQ-042, PIPE-REQ-044) instead of assuming success.
        """
        self._advisory_status[analysis_id] = status

    def advisory_status_for(self, context: object) -> str | None:
        """Advisory-data consultation status recorded for an analysis."""
        analysis_id = getattr(context, "analysis_id", "-")
        return self._advisory_status.get(analysis_id)

    def record_advisories(
        self,
        analysis_id: str,
        advisories: dict[tuple[str, str, str], tuple[Advisory, ...]],
    ) -> None:
        """Record bounded advisories keyed by (ecosystem, package, version).

        The pipeline maps these onto dependency occurrences so the
        association reaches persistence and the read result (docs/12 §4.6.1).
        """
        self._advisories[analysis_id] = advisories

    def advisories_for(self, context: object) -> dict[tuple[str, str, str], tuple[Advisory, ...]]:
        """Bounded advisories obtained for an analysis (empty when none)."""
        analysis_id = getattr(context, "analysis_id", "-")
        return self._advisories.get(analysis_id, {})

    def inventory_for(self, context: object) -> Inventory:
        """Normalized inventory for an analysis (cached per analysis ID)."""
        analysis_id = getattr(context, "analysis_id", "-")
        cached = self._inventory_cache.get(analysis_id)
        if cached is not None:
            return cached
        provider = self._provider
        if provider is None:
            ncm = getattr(context, "ncm", None)
            indexed = index_paths_from_ncm(ncm) if ncm is not None else []
            provider = DictManifestProvider({path: "" for path in indexed})
        inventory = build_inventory(provider)
        self._inventory_cache[analysis_id] = inventory
        log_event(
            _logger,
            logging.INFO,
            "dependency.inventory.built",
            "Dependency inventory built",
            analysis_id=analysis_id,
            occurrences=len(inventory.occurrences),
            manifests=len(inventory.outcomes),
        )
        return inventory

    def rules(self) -> list[RegisteredRule]:
        """Only the registered V1.0 dependency rules (never other domains)."""
        return build_dependency_rules(self)

    def coverage(self, context: object) -> list[dict[str, str]]:
        """Explicit per-rule coverage for an analysis (never clean-by-omission)."""
        inventory = self.inventory_for(context)
        failed = any(
            outcome.ref.support_state == SupportState.FAILED for outcome in inventory.outcomes
        )
        partial = any(
            outcome.ref.support_state == SupportState.PARTIAL for outcome in inventory.outcomes
        )
        rows: list[dict[str, str]] = []
        for spec in DEPENDENCY_RULE_SPECS:
            if not inventory.outcomes:
                rows.append(
                    {
                        "rule_id": spec.rule_id,
                        "status": SupportState.UNSUPPORTED.value,
                        "reason": "No dependency manifests in scope; the rule did not run.",
                    }
                )
            elif failed:
                rows.append(
                    {
                        "rule_id": spec.rule_id,
                        "status": SupportState.FAILED.value,
                        "reason": "Some manifests failed to parse; results are incomplete.",
                    }
                )
            elif partial:
                rows.append(
                    {
                        "rule_id": spec.rule_id,
                        "status": SupportState.PARTIAL.value,
                        "reason": "Some manifests are only partially recognized.",
                    }
                )
            else:
                rows.append(
                    {
                        "rule_id": spec.rule_id,
                        "status": SupportState.SUPPORTED.value,
                        "reason": "Manifests were analyzed with a sufficient representation.",
                    }
                )
        return rows


def dependency_provider_from_workspace(
    *,
    workspaces: object,
    workspace: Path,
    indexed_paths: list[str],
    file_max_bytes: int,
) -> WorkspaceManifestProvider:
    """Build the workspace-backed manifest provider for production runs."""
    return WorkspaceManifestProvider(
        workspaces=workspaces,
        workspace=workspace,
        indexed_paths=indexed_paths,
        file_max_bytes=file_max_bytes,
    )


__all__ = [
    "DependencyAnalyzer",
    "DictManifestProvider",
    "Inventory",
    "ManifestProvider",
    "WorkspaceManifestProvider",
    "build_inventory",
    "dependency_provider_from_workspace",
]
