"""Dependency analysis value objects (Phase 8, TASK-112–121).

Parser-independent representation of dependency information extracted by
static reading of manifests and lockfiles (docs/09 §11.2, docs/10 §5.11A).
Manifests and lockfiles are data: they are read as text, never executed,
never installed, and never resolved through a package manager.

Ecosystem identifiers follow the OSV contract (``PyPI`` / ``npm``); the
internal normalized scope keys are ``pypi`` and ``npm``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum

#: Internal ecosystem scope keys (OSV identifiers are mapped in ``osv.py``).
ECOSYSTEM_PYPI = "pypi"
ECOSYSTEM_NPM = "npm"

SUPPORTED_ECOSYSTEMS = frozenset({ECOSYSTEM_PYPI, ECOSYSTEM_NPM})


class SupportState(StrEnum):
    """Per-manifest/dependency support states (TASK-113).

    Compatible with the security ``CoverageStatus`` vocabulary: supported
    content ran, partial ran with gaps, unsupported content is out of the
    V1.0 boundary, failed content should have been supported but was not
    analyzed, and not-applicable content is irrelevant to the check.
    """

    SUPPORTED = "supported"
    PARTIAL = "partial"
    UNSUPPORTED = "unsupported"
    FAILED = "failed"
    NOT_APPLICABLE = "not_applicable"


class ManifestKind(StrEnum):
    """Whether a discovered file declares dependencies or pins them."""

    MANIFEST = "manifest"
    LOCKFILE = "lockfile"


class DependencyClass(StrEnum):
    """Direct/transitive classification with an explicit unknown state."""

    DIRECT = "direct"
    TRANSITIVE = "transitive"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class ManifestRef:
    """One discovered manifest/lockfile (repository-relative, deterministic)."""

    path: str
    kind: ManifestKind
    format: str  # requirements_txt | pyproject_toml | poetry_lock | ...
    ecosystem: str  # pypi | npm | unknown
    project_context: str  # parent directory ("" for repository root)
    support_state: SupportState = SupportState.SUPPORTED


@dataclass(frozen=True)
class DependencyOccurrence:
    """One normalized dependency declaration occurrence (traceable)."""

    ecosystem: str
    canonical_name: str
    original_name: str
    constraint: str | None  # declared specifier/range, None when absent
    resolved_version: str | None  # exact version, None when not determinable
    source_file: str  # repository-relative manifest/lockfile path
    project_context: str  # parent directory of the source file
    section: str  # declaration section or dependency group
    dependency_class: DependencyClass = DependencyClass.UNKNOWN
    runtime_context: str = "unknown"  # runtime | development | optional | peer | unknown
    source_line: int | None = None
    support_state: SupportState = SupportState.SUPPORTED
    kind: str = "registry"  # registry | url | vcs | path | editable | unknown


@dataclass(frozen=True)
class LockRelation:
    """One statically recorded lockfile edge (names raw, versions optional).

    ``parent``/``child`` are package names as written in the lockfile;
    versions are exact strings when the lockfile records them for that node
    (npm ``packages`` entries) and ``None`` when it only records a range or
    nothing (npm ``requires`` maps, Poetry dependency constraints). A
    ``None`` version never fabricates an edge version — consumers must treat
    it as unknown provenance, not as a wildcard.
    """

    parent: str
    parent_version: str | None
    child: str
    child_version: str | None


@dataclass
class ManifestOutcome:
    """Parse product of one manifest/lockfile (never raises past this point)."""

    ref: ManifestRef
    occurrences: list[DependencyOccurrence] = field(default_factory=list)
    relationships: list[LockRelation] = field(default_factory=list)
    reasons: list[str] = field(default_factory=list)  # unsupported/partial notes

    @property
    def failed(self) -> bool:
        """A failed manifest contributes occurrences to nothing."""
        return self.ref.support_state == SupportState.FAILED


@dataclass
class Advisory:
    """Normalized OSV advisory record (defensive subset, secret-free)."""

    advisory_id: str
    aliases: tuple[str, ...] = ()
    summary: str = ""
    severity: str = "unknown"  # mapped severity label or "unknown"
    references: tuple[str, ...] = ()
    published: str | None = None
    modified: str | None = None
    ecosystem: str = ""
    package_name: str = ""
    affected_version: str | None = None
