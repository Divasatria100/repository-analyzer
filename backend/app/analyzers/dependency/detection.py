"""Local dependency detections: duplicate versions, count, unused (TASK-116–118).

Pure functions over normalized occurrences: deterministic, no network, no
execution. Advisory matching lives in ``osv.py`` and the analyzer; this
module only computes the static detections plus their limitations.
"""

from __future__ import annotations

from dataclasses import dataclass

from app.analyzers.dependency.identity import identity_key
from app.analyzers.dependency.models import DependencyOccurrence


@dataclass(frozen=True)
class DuplicateVersionGroup:
    """One package identity with distinct resolved versions (evidence-ready)."""

    ecosystem: str
    canonical_name: str
    versions: tuple[str, ...]  # sorted distinct exact versions
    occurrences: tuple[DependencyOccurrence, ...]  # sorted, deterministic
    project_contexts: tuple[str, ...]


@dataclass(frozen=True)
class ScopeCount:
    """Occurrence count for one package-manager scope (DEP-REQ-003)."""

    ecosystem: str
    count: int
    incomplete: bool = False


@dataclass(frozen=True)
class UnusedCandidate:
    """One direct dependency with no statically observed usage (candidate)."""

    occurrence: DependencyOccurrence
    coverage_note: str


def find_duplicate_versions(
    occurrences: list[DependencyOccurrence],
) -> tuple[list[DuplicateVersionGroup], list[str]]:
    """Group by normalized identity; report identities with ≥2 exact versions.

    Occurrences with ``resolved_version`` None are excluded from comparison
    (never treated as distinct versions); their presence is recorded as a
    limitation reason. Ordering is deterministic throughout.
    """
    limitations: list[str] = []
    by_identity: dict[str, list[DependencyOccurrence]] = {}
    for occ in occurrences:
        by_identity.setdefault(identity_key(occ.ecosystem, occ.original_name), []).append(occ)
    groups: list[DuplicateVersionGroup] = []
    for key in sorted(by_identity):
        members = by_identity[key]
        resolved = sorted({occ.resolved_version for occ in members if occ.resolved_version})
        if any(occ.resolved_version is None for occ in members):
            limitations.append(
                f"{key}: occurrences with unknown versions were excluded from duplicate comparison"
            )
        if len(resolved) < 2:
            continue
        ecosystem = members[0].ecosystem
        canonical = members[0].canonical_name
        ordered = tuple(
            sorted(members, key=lambda o: (o.source_file, o.source_line or 0, o.section))
        )
        contexts = tuple(sorted({occ.project_context for occ in members}))
        groups.append(
            DuplicateVersionGroup(
                ecosystem=ecosystem,
                canonical_name=canonical,
                versions=tuple(resolved),
                occurrences=ordered,
                project_contexts=contexts,
            )
        )
    return groups, limitations


def count_by_scope(
    occurrences: list[DependencyOccurrence],
) -> list[ScopeCount]:
    """Count total occurrences per ecosystem scope (DEP-REQ-003, frozen).

    What is counted is total dependency occurrences (direct + transitive),
    PyPI and npm separately. Repeated occurrences count individually; the
    finding decision (strict ``>``) is made by the analyzer rule.
    """
    totals: dict[str, int] = {}
    for occ in occurrences:
        totals[occ.ecosystem] = totals.get(occ.ecosystem, 0) + 1
    return [
        ScopeCount(ecosystem=ecosystem, count=totals[ecosystem]) for ecosystem in sorted(totals)
    ]


def count_with_completeness(
    occurrences: list[DependencyOccurrence],
    incomplete_scopes: set[str],
) -> list[ScopeCount]:
    """Scope counts annotated with manifest-completeness limitations."""
    totals: dict[str, int] = {}
    for occ in occurrences:
        totals[occ.ecosystem] = totals.get(occ.ecosystem, 0) + 1
    return [
        ScopeCount(
            ecosystem=ecosystem,
            count=totals[ecosystem],
            incomplete=ecosystem in incomplete_scopes,
        )
        for ecosystem in sorted(totals)
    ]


#: Documented distribution-name → top-level-module mapping (V1.0, static).
#: Used only to avoid false candidates when the names differ; unknown
#: packages fall back to the name-derived heuristic below.
DISTRIBUTION_TO_MODULES: dict[str, tuple[str, ...]] = {
    "pyyaml": ("yaml",),
    "pillow": ("PIL",),
    "beautifulsoup4": ("bs4",),
    "scikit-learn": ("sklearn",),
    "python-dateutil": ("dateutil",),
    "python-dotenv": ("dotenv",),
    "pymupdf": ("fitz",),
    "opencv-python": ("cv2",),
    "protobuf": ("google.protobuf",),
    "grpcio": ("grpc",),
    "psycopg2-binary": ("psycopg2",),
    "psycopg2": ("psycopg2",),
    "mysqlclient": ("MySQLdb",),
    "pymysql": ("pymysql",),
    "sqlalchemy": ("sqlalchemy",),
    "djangorestframework": ("rest_framework",),
    "pytest-django": ("pytest_django",),
    "typing-extensions": ("typing_extensions",),
    "importlib-metadata": ("importlib_metadata",),
    "zope-interface": ("zope.interface",),
}


def candidate_module_names(canonical: str) -> tuple[str, ...]:
    """Possible top-level import names for a PyPI distribution (static)."""
    lowered = canonical.lower()
    if lowered in DISTRIBUTION_TO_MODULES:
        return DISTRIBUTION_TO_MODULES[lowered]
    # Default heuristic: separators become underscores, first segment counts.
    guess = lowered.replace("-", "_").replace(".", "_")
    return (guess,)


def top_level_import_names(ncm: object) -> tuple[set[str], bool]:
    """Collect top-level import names from NCM Python modules.

    Returns ``(names, has_python_content)``. ``names`` holds lowercased
    first segments of import targets; ``has_python_content`` reports whether
    any Python module was available at all (coverage signal).
    """
    names: set[str] = set()
    has_python = False
    for module in getattr(ncm, "modules", []):
        language = (getattr(module, "language", "") or "").lower()
        if language != "python":
            continue
        has_python = True
        for imp in getattr(module, "imports", []):
            target = (getattr(imp, "target_text", "") or "").strip()
            if not target:
                continue
            first = target.split(".")[0].strip().lower()
            if first:
                names.add(first)
    return names, has_python


# Dynamic-import signals that force a coverage limitation instead of a claim.
_DYNAMIC_IMPORT_TOKENS = frozenset(
    {"importlib", "__import__", "import_module", "exec", "eval", "pkgutil", "entry_points"}
)


def has_dynamic_import_signals(ncm: object) -> bool:
    """True when analyzed Python source shows dynamic-loading constructs."""
    for module in getattr(ncm, "modules", []):
        if (getattr(module, "language", "") or "").lower() != "python":
            continue
        for imp in getattr(module, "imports", []):
            if (getattr(imp, "target_text", "") or "").strip().lower() in _DYNAMIC_IMPORT_TOKENS:
                return True
        for call in getattr(module, "calls", []):
            if (getattr(call, "callee_text", "") or "").strip().lower() in _DYNAMIC_IMPORT_TOKENS:
                return True
    return False


def find_unused_candidates(
    occurrences: list[DependencyOccurrence],
    ncm: object,
) -> tuple[list[UnusedCandidate], list[str]]:
    """Find direct PyPI dependencies with no statically observed usage.

    Candidate semantics (DEP-REQ-004): direct dependencies only, candidate
    wording only, Info/Low only. npm scopes are not evaluated here (no
    JavaScript parser in V1.0) — callers record that as a limitation.
    Development/optional dependencies are still reported as candidates
    (never claimed unused for production reasons).
    """
    limitations: list[str] = []
    import_names, has_python = top_level_import_names(ncm)
    if not has_python:
        limitations.append(
            "no supported Python source was available; unused-dependency "
            "candidates were not evaluated and nothing is claimed unused"
        )
        return [], limitations
    dynamic = has_dynamic_import_signals(ncm)
    candidates: list[UnusedCandidate] = []
    seen: set[str] = set()
    for occ in sorted(occurrences, key=lambda o: (o.ecosystem, o.canonical_name, o.source_file)):
        if occ.ecosystem != "pypi" or occ.dependency_class.value != "direct":
            continue
        key = f"pypi:{occ.canonical_name.lower()}"
        if key in seen:
            continue
        seen.add(key)
        possible = candidate_module_names(occ.canonical_name)
        if any(name.lower() in import_names for name in possible):
            continue
        if occ.canonical_name.lower() not in DISTRIBUTION_TO_MODULES and _is_unmappable(
            occ.canonical_name
        ):
            limitations.append(
                f"{occ.canonical_name}: no reliable import mapping is available; "
                "no conclusion was drawn"
            )
            continue
        note = (
            "no usage was statically observed; manual review required "
            "(framework-convention, configuration-driven, plugin, "
            "generated-code, dynamic-import, and runtime-loading usage "
            "cannot be seen by static analysis"
        )
        if dynamic:
            note += "; dynamic-loading constructs were observed in analyzed source"
        note += ")"
        candidates.append(UnusedCandidate(occurrence=occ, coverage_note=note))
    return candidates, limitations


def _is_unmappable(canonical: str) -> bool:
    """Conservative guard: never claim when even a heuristic is unreliable."""
    # Namespace-style or single-letter names without mapping stay inconclusive.
    return len(canonical) <= 1
