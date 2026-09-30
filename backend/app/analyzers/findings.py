"""Shared Finding model (TASK-086–088, TASK-090 partial).

Domain-neutral, evidence-based static-analysis observations. Severity and
confidence are independent dimensions (docs/07 SEC-REQ-021, docs/08
ARCH-REQ-078); identity is deterministic and reproducible (docs/13 §8.1
composition, opaque string, no hash algorithm prescribed — SHA-256 over
canonical typed fields is the implementation choice).
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass, field
from enum import StrEnum

from app.ncm import SourceLocation


class Severity(StrEnum):
    """Frozen severity vocabulary (docs/07 SEC-REQ-017, docs/08 ARCH-REQ-077)."""

    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Info"

    @classmethod
    def allowed_for(cls, category: str) -> frozenset[Severity]:
        """Architecture never uses Critical; every other category uses all five."""
        if category == "architecture":
            return frozenset({cls.HIGH, cls.MEDIUM, cls.LOW, cls.INFO})
        return frozenset(cls)


class Confidence(StrEnum):
    """Frozen confidence vocabulary (docs/07 SEC-REQ-020)."""

    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"


@dataclass(frozen=True)
class Limitation:
    """Structured record of what could not be established (never false certainty)."""

    scope: str
    reason: str
    path: str | None = None
    rule_id: str | None = None

    def __post_init__(self) -> None:
        """Fail fast on empty scope/reason (vacuous limitations hide gaps)."""
        if not self.scope.strip():
            raise ValueError("Limitation scope must not be empty.")
        if not self.reason.strip():
            raise ValueError("Limitation reason must not be empty.")

    def to_dict(self) -> dict[str, object]:
        """Deterministic serialization."""
        return {
            "scope": self.scope,
            "reason": self.reason,
            "path": self.path,
            "rule_id": self.rule_id,
        }

    @classmethod
    def from_dict(cls, data: dict[str, object]) -> Limitation:
        """Rebuild from serialized form."""
        path = data.get("path")
        rule_id = data.get("rule_id")
        return cls(
            scope=str(data["scope"]),
            reason=str(data["reason"]),
            path=str(path) if path is not None else None,
            rule_id=str(rule_id) if rule_id is not None else None,
        )


@dataclass(frozen=True)
class Evidence:
    """Bounded, redacted source context (TASK-089 data carrier).

    Built exclusively by :func:`app.analyzers.evidence.build_evidence`,
    which enforces the frozen window, truncation marking, redaction, and
    repository-relative paths. Never contains a whole source file.
    """

    path: str
    start_line: int
    end_line: int
    lines: tuple[str, ...] = ()
    truncated: bool = False
    redacted: bool = False

    def to_dict(self) -> dict[str, object]:
        """Deterministic serialization."""
        return {
            "path": self.path,
            "start_line": self.start_line,
            "end_line": self.end_line,
            "lines": list(self.lines),
            "truncated": self.truncated,
            "redacted": self.redacted,
        }

    @classmethod
    def from_dict(cls, data: dict[str, object]) -> Evidence:
        """Rebuild from serialized form."""
        lines = data.get("lines", [])
        assert isinstance(lines, list)
        start_line = data["start_line"]
        end_line = data["end_line"]
        assert isinstance(start_line, int) and isinstance(end_line, int)
        return cls(
            path=str(data["path"]),
            start_line=start_line,
            end_line=end_line,
            lines=tuple(str(line) for line in lines),
            truncated=bool(data.get("truncated", False)),
            redacted=bool(data.get("redacted", False)),
        )


def compute_identity_key(
    *,
    analysis_id: str,
    rule_id: str,
    category: str,
    path: str,
    start_line: int,
    end_line: int,
    start_column: int,
    end_column: int,
    subject_key: str,
    occurrence_index: int = 0,
) -> str:
    """Deterministic opaque identity (SHA-256 over canonical typed fields).

    Stable across repeated analyses when inputs are unchanged; independent
    of object identity, UUIDs, execution order, and workspace paths.
    Severity, confidence, versions, and timestamps are deliberately excluded
    so retuning or rerunning never renames a logical finding. Evidence text
    and secrets are never inputs (docs/13 §8.1, SEC-REQ-055).
    """
    canonical = json.dumps(
        [
            analysis_id,
            rule_id,
            category,
            path,
            start_line,
            end_line,
            start_column,
            end_column,
            subject_key,
            occurrence_index,
        ],
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class Finding:
    """One evidence-based observation (never proof of exploitability)."""

    identity_key: str
    rule_id: str
    analyzer_id: str
    category: str
    title: str
    description: str
    severity: Severity
    confidence: Confidence
    location: SourceLocation
    evidence: Evidence | None = None
    recommendation: str = ""
    limitations: tuple[Limitation, ...] = ()
    analyzer_version: str = ""
    rule_set_version: str = ""
    finding_id: str = ""
    impact: str | None = None
    severity_factors: tuple[str, ...] = ()
    confidence_factors: tuple[str, ...] = ()
    applied_thresholds: tuple[tuple[str, object], ...] = field(default_factory=tuple)

    def to_dict(self) -> dict[str, object]:
        """Deterministic serialization (sorted keys, stable enum values)."""
        return {
            "identity_key": self.identity_key,
            "rule_id": self.rule_id,
            "analyzer_id": self.analyzer_id,
            "category": self.category,
            "title": self.title,
            "description": self.description,
            "severity": self.severity.value,
            "confidence": self.confidence.value,
            "location": self.location.to_dict(),
            "evidence": self.evidence.to_dict() if self.evidence else None,
            "recommendation": self.recommendation,
            "limitations": [limitation.to_dict() for limitation in self.limitations],
            "analyzer_version": self.analyzer_version,
            "rule_set_version": self.rule_set_version,
            "finding_id": self.finding_id,
            "impact": self.impact,
            "severity_factors": list(self.severity_factors),
            "confidence_factors": list(self.confidence_factors),
            "applied_thresholds": [
                [name, value] for name, value in sorted(self.applied_thresholds)
            ],
        }

    @classmethod
    def from_dict(cls, data: dict[str, object]) -> Finding:
        """Rebuild from serialized form (revalidated, never trusted raw)."""
        location = data["location"]
        assert isinstance(location, dict)
        evidence = data.get("evidence")
        limitations = data.get("limitations", [])
        assert isinstance(limitations, list)
        thresholds = data.get("applied_thresholds", [])
        assert isinstance(thresholds, list)
        severity_factors = data.get("severity_factors", [])
        confidence_factors = data.get("confidence_factors", [])
        assert isinstance(severity_factors, list) and isinstance(confidence_factors, list)
        impact = data.get("impact")
        severity = Severity(str(data["severity"]))
        category = str(data["category"])
        location_obj = SourceLocation.from_dict(location)
        if severity not in Severity.allowed_for(category):
            raise ValueError(f"Severity {severity.value!r} not allowed for {category!r}.")
        if os.path.isabs(location_obj.file_path):
            raise ValueError("Finding location path must be repository-relative.")
        evidence_obj = Evidence.from_dict(evidence) if isinstance(evidence, dict) else None
        if evidence_obj is not None and evidence_obj.path != location_obj.file_path:
            raise ValueError("Evidence path must match the finding location path.")
        return cls(
            identity_key=str(data["identity_key"]),
            rule_id=str(data["rule_id"]),
            analyzer_id=str(data["analyzer_id"]),
            category=category,
            title=str(data["title"]),
            description=str(data["description"]),
            severity=severity,
            confidence=Confidence(str(data["confidence"])),
            location=location_obj,
            evidence=evidence_obj,
            recommendation=str(data.get("recommendation", "")),
            limitations=tuple(
                Limitation.from_dict(item) for item in limitations if isinstance(item, dict)
            ),
            analyzer_version=str(data.get("analyzer_version", "")),
            rule_set_version=str(data.get("rule_set_version", "")),
            finding_id=str(data.get("finding_id", "")),
            impact=str(impact) if impact is not None else None,
            severity_factors=tuple(str(item) for item in severity_factors),
            confidence_factors=tuple(str(item) for item in confidence_factors),
            applied_thresholds=tuple(
                (str(pair[0]), pair[1]) for pair in thresholds if isinstance(pair, list)
            ),
        )


def create_finding(
    *,
    rule_id: str,
    analyzer_id: str,
    category: str,
    title: str,
    description: str,
    severity: Severity,
    confidence: Confidence,
    location: SourceLocation,
    evidence: Evidence | None = None,
    recommendation: str = "",
    limitations: tuple[Limitation, ...] = (),
    analyzer_version: str = "",
    rule_set_version: str = "",
    finding_id: str = "",
    impact: str | None = None,
    severity_factors: tuple[str, ...] = (),
    confidence_factors: tuple[str, ...] = (),
    applied_thresholds: tuple[tuple[str, object], ...] = (),
    analysis_id: str = "",
    subject_key: str = "",
    occurrence_index: int = 0,
    identity_key: str | None = None,
) -> Finding:
    """Build a validated finding with deterministic identity.

    Severity must be allowed for the category; the location path must be
    repository-relative (absolute paths rejected); identity is computed
    unless explicitly supplied (deserialization round-trip).
    """
    if severity not in Severity.allowed_for(category):
        raise ValueError(f"Severity {severity.value!r} not allowed for {category!r}.")
    if not location.file_path:
        raise ValueError("Finding location path must not be empty.")
    if os.path.isabs(location.file_path):
        raise ValueError("Finding location path must be repository-relative.")
    if evidence is not None and evidence.path != location.file_path:
        raise ValueError("Evidence path must match the finding location path.")
    resolved_identity = (
        identity_key
        if identity_key is not None
        else compute_identity_key(
            analysis_id=analysis_id,
            rule_id=rule_id,
            category=category,
            path=location.file_path,
            start_line=location.start_line,
            end_line=location.end_line,
            start_column=location.start_column,
            end_column=location.end_column,
            subject_key=subject_key,
            occurrence_index=occurrence_index,
        )
    )
    return Finding(
        identity_key=resolved_identity,
        rule_id=rule_id,
        analyzer_id=analyzer_id,
        category=category,
        title=title,
        description=description,
        severity=severity,
        confidence=confidence,
        location=location,
        evidence=evidence,
        recommendation=recommendation,
        limitations=limitations,
        analyzer_version=analyzer_version,
        rule_set_version=rule_set_version,
        finding_id=finding_id,
        impact=impact,
        severity_factors=severity_factors,
        confidence_factors=confidence_factors,
        applied_thresholds=applied_thresholds,
    )
