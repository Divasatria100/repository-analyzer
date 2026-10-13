"""Static manifest/lockfile parsers (TASK-112/114, data only).

Every parser reads repository content as data with the standard library
(``tomllib``/``json``/line scanning). Nothing is executed, installed, or
resolved through a package manager; version ranges are never solved.
Malformed files yield a failed outcome with a diagnostic reason — never a
clean empty result, never an exception past this boundary.
"""

from __future__ import annotations

import json
import os
import re
import stat
import tomllib
from pathlib import Path

from app.analyzers.dependency.identity import (
    canonical_name,
    classify_specifier_kind,
    is_plausible_exact_version,
    split_requirement_name,
    strip_extras,
)
from app.analyzers.dependency.models import (
    DependencyClass,
    DependencyOccurrence,
    LockRelation,
    ManifestOutcome,
    ManifestRef,
    SupportState,
)
from app.core.logging import get_logger

_logger = get_logger("analyzers.dependency.parsers")


def read_manifest_text(
    *,
    workspace: Path,
    workspaces: object,
    ref: ManifestRef,
    file_max_bytes: int,
) -> str | None:
    """Read one manifest as data (bounded, symlink-safe); None when unsafe."""
    resolve = getattr(workspaces, "resolve", None)
    if resolve is None:
        return None
    try:
        resolved = resolve(workspace, ref.path)
    except Exception:
        return None
    try:
        entry_stat = os.lstat(workspace / ref.path)
    except OSError:
        return None
    if stat.S_ISLNK(entry_stat.st_mode) or not stat.S_ISREG(entry_stat.st_mode):
        return None
    try:
        if resolved.is_symlink() or not resolved.is_file():
            return None
        if resolved.stat().st_size > file_max_bytes:
            return None
        return resolved.read_text(encoding="utf-8", errors="strict")
    except (OSError, ValueError, UnicodeDecodeError):
        return None


def find_line_for(text: str, needle: str, occurrence: int = 0) -> int | None:
    """Best-effort 1-based line number for a dependency name.

    The needle must appear as a delimited token (never as a substring of a
    longer name such as ``flask-cors`` when looking for ``flask``), and
    full-line comments are never matched. ``occurrence`` selects the n-th
    match (0-based) so repeated declarations in one file resolve to distinct
    lines. Returns ``None`` when no unambiguous match exists — callers must
    record unavailable evidence instead of fabricating a line number.
    """
    if not needle:
        return None
    pattern = re.compile(
        r"(?<![A-Za-z0-9_.\-@/+])" + re.escape(needle) + r"(?![A-Za-z0-9_.\-@/+])",
        re.IGNORECASE,
    )
    matches: list[int] = []
    for number, line in enumerate(text.splitlines(), start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if pattern.search(line):
            matches.append(number)
    if occurrence < len(matches):
        return matches[occurrence]
    return None


def _occurrence(
    *,
    ref: ManifestRef,
    original: str,
    constraint: str | None,
    resolved: str | None,
    section: str,
    dependency_class: DependencyClass,
    runtime_context: str,
    line: int | None,
    kind: str,
    support_state: SupportState = SupportState.SUPPORTED,
) -> DependencyOccurrence:
    return DependencyOccurrence(
        ecosystem=ref.ecosystem,
        canonical_name=canonical_name(ref.ecosystem, strip_extras(original)),
        original_name=original,
        constraint=constraint,
        resolved_version=resolved,
        source_file=ref.path,
        project_context=ref.project_context,
        section=section,
        dependency_class=dependency_class,
        runtime_context=runtime_context,
        source_line=line,
        support_state=support_state,
        kind=kind,
    )


# --- requirements.txt -------------------------------------------------------


def parse_requirements_txt(text: str, ref: ManifestRef) -> ManifestOutcome:
    """Parse ``requirements.txt`` lines statically (PEP 508 entries, static read)."""
    outcome = ManifestOutcome(ref=ref)
    for number, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.endswith("\\"):
            # Line continuation (hash-checking mode): the backslash joins the
            # next line and is never part of the version itself.
            line = line[:-1].rstrip()
            if not line:
                continue
        if line.startswith(("-", "--")):
            outcome.reasons.append(
                f"line {number}: pip option/include line is not statically "
                "evaluated; recorded as uninterpretable"
            )
            continue
        try:
            name, constraint = split_requirement_name(line)
        except Exception:
            outcome.reasons.append(f"line {number}: entry could not be parsed statically")
            continue
        if not name:
            outcome.reasons.append(f"line {number}: entry could not be parsed statically")
            continue
        kind = classify_specifier_kind(constraint)
        resolved = _pinned_requirement_version(constraint, kind)
        outcome.occurrences.append(
            _occurrence(
                ref=ref,
                original=name,
                constraint=constraint,
                resolved=resolved,
                section="requirements",
                dependency_class=DependencyClass.DIRECT,
                runtime_context="runtime",
                line=number,
                kind=kind,
            )
        )
    return outcome


def _pinned_requirement_version(constraint: str | None, kind: str) -> str | None:
    """Exact version from a requirements pin, or ``None`` when not exact.

    Only ``==`` (normalized equality) and ``===`` (arbitrary string equality,
    PEP 440: the installed version string is exactly the pinned string)
    without companions yield a resolved version, and only when the remainder
    is shaped like a version. Ranges, wildcards, hashes, and malformed
    remainders stay unresolved — never guessed, never sent to OSV.
    """
    if constraint is None or kind != "registry":
        return None
    text = constraint.strip()
    for prefix in ("===", "=="):
        if text.startswith(prefix) and "," not in text:
            remainder = text[len(prefix) :].strip().split(",")[0].strip()
            remainder = remainder.split()[0] if remainder else ""
            if remainder and is_plausible_exact_version(remainder):
                return remainder
            return None
    return None


# --- pyproject.toml ---------------------------------------------------------


def parse_pyproject_toml(text: str, ref: ManifestRef) -> ManifestOutcome:
    """Parse PEP 621 and Poetry dependency sections (recognized parts only)."""
    try:
        document = tomllib.loads(text)
    except (tomllib.TOMLDecodeError, ValueError) as exc:
        return ManifestOutcome(
            ref=ManifestRef(
                path=ref.path,
                kind=ref.kind,
                format=ref.format,
                ecosystem=ref.ecosystem,
                project_context=ref.project_context,
                support_state=SupportState.FAILED,
            ),
            reasons=[f"malformed TOML; recorded as failed, not clean: {type(exc).__name__}"],
        )
    outcome = ManifestOutcome(ref=ref)
    if not isinstance(document, dict):
        outcome.ref = _with_state(ref, SupportState.FAILED)
        outcome.reasons.append("unexpected TOML shape; recorded as failed, not clean")
        return outcome
    project = document.get("project")
    line_counts: dict[str, int] = {}
    if isinstance(project, dict):
        for entry in _as_str_list(project.get("dependencies")):
            name, constraint = split_requirement_name(entry)
            if not name:
                outcome.reasons.append("project.dependencies entry uninterpretable")
                continue
            outcome.occurrences.append(
                _occurrence(
                    ref=ref,
                    original=name,
                    constraint=constraint,
                    resolved=_pinned_from_constraint(constraint),
                    section="project.dependencies",
                    dependency_class=DependencyClass.DIRECT,
                    runtime_context="runtime",
                    line=_next_line(text, name, line_counts),
                    kind=classify_specifier_kind(constraint),
                )
            )
        optional = project.get("optional-dependencies")
        if isinstance(optional, dict):
            for group, entries in optional.items():
                for entry in _as_str_list(entries):
                    name, constraint = split_requirement_name(entry)
                    if not name:
                        continue
                    outcome.occurrences.append(
                        _occurrence(
                            ref=ref,
                            original=name,
                            constraint=constraint,
                            resolved=_pinned_from_constraint(constraint),
                            section=f"project.optional-dependencies.{group}",
                            dependency_class=DependencyClass.DIRECT,
                            runtime_context="optional",
                            line=_next_line(text, name, line_counts),
                            kind=classify_specifier_kind(constraint),
                        )
                    )
    poetry = document.get("tool")
    # (dependency name, spec, group-or-None): the group is tracked from the
    # section the entry was read from — never inferred from dots in the name,
    # so valid dotted names such as ``zope.interface`` keep their identity.
    poetry_deps: list[tuple[str, object, str | None]] = []
    poetry_partial_notes: list[str] = []
    if isinstance(poetry, dict) and isinstance(poetry.get("poetry"), dict):
        poetry_section = poetry["poetry"]
        assert isinstance(poetry_section, dict)
        raw_deps = poetry_section.get("dependencies")
        if isinstance(raw_deps, dict):
            for dep_name, dep_spec in raw_deps.items():
                poetry_deps.append((dep_name, dep_spec, None))
        for group_key in ("group",):
            groups = poetry_section.get(group_key)
            if isinstance(groups, dict):
                for group_name, group_body in groups.items():
                    if isinstance(group_body, dict) and isinstance(
                        group_body.get("dependencies"), dict
                    ):
                        deps = group_body["dependencies"]
                        assert isinstance(deps, dict)
                        for dep_name, dep_spec in deps.items():
                            poetry_deps.append((dep_name, dep_spec, group_name))
        dev_deps = poetry_section.get("dev-dependencies")
        if isinstance(dev_deps, dict):
            for dep_name, dep_spec in dev_deps.items():
                poetry_deps.append((dep_name, dep_spec, "dev"))
        if "scripts" in poetry_section or "plugins" in poetry_section:
            poetry_partial_notes.append(
                "poetry scripts/plugins sections are not dependency declarations; not evaluated"
            )
    poetry_line_counts: dict[str, int] = {}
    for dep_name, spec, group in poetry_deps:
        if dep_name.lower() == "python":
            continue
        if isinstance(spec, dict) and not any(key in spec for key in ("version", "git", "path")):
            # Not a Poetry dependency table (e.g. a TOML nested table from an
            # unquoted dotted key): never invent an occurrence from its key.
            outcome.reasons.append(
                f"tool.poetry entry {dep_name!r} is not a recognized dependency "
                "declaration; recorded as uninterpretable"
            )
            continue
        if group is None:
            section = "tool.poetry.dependencies"
            runtime = "runtime"
        else:
            section = f"tool.poetry.group.{group}.dependencies"
            runtime = "development" if group == "dev" else group
        constraint, resolved, kind = _poetry_spec(spec)
        line = find_line_for(text, dep_name, poetry_line_counts.get(dep_name, 0))
        poetry_line_counts[dep_name] = poetry_line_counts.get(dep_name, 0) + 1
        outcome.occurrences.append(
            _occurrence(
                ref=ref,
                original=dep_name,
                constraint=constraint,
                resolved=resolved,
                section=section,
                dependency_class=DependencyClass.DIRECT,
                runtime_context=runtime,
                line=line,
                kind=kind,
            )
        )
    outcome.reasons.extend(poetry_partial_notes)
    if not outcome.occurrences:
        # Successfully parsed but empty: a real empty result, not a failure.
        outcome.reasons.append("no recognized dependency declarations found")
    elif poetry_partial_notes or _has_unrecognized_dependency_sections(document):
        outcome.ref = _with_state(ref, SupportState.PARTIAL)
        outcome.reasons.append("only part of the dependency declarations are recognized")
    return outcome


def _with_state(ref: ManifestRef, state: SupportState) -> ManifestRef:
    return ManifestRef(
        path=ref.path,
        kind=ref.kind,
        format=ref.format,
        ecosystem=ref.ecosystem,
        project_context=ref.project_context,
        support_state=state,
    )


def _next_line(text: str, name: str, counts: dict[str, int]) -> int | None:
    """n-th match line for repeated declarations of one name in a file."""
    line = find_line_for(text, name, counts.get(name, 0))
    counts[name] = counts.get(name, 0) + 1
    return line


def _as_str_list(value: object) -> list[str]:
    if isinstance(value, (list, tuple)):
        return [item for item in value if isinstance(item, str)]
    return []


def _pinned_from_constraint(constraint: str | None) -> str | None:
    if constraint is None:
        return None
    text = constraint.strip()
    if text.startswith("==="):
        remainder = text[3:].strip().split(";")[0].strip()
        return remainder if remainder and is_plausible_exact_version(remainder) else None
    if text.startswith("==") and "," not in text and " " not in text.strip("="):
        pinned = text[2:].strip().split(";")[0].strip()
        return pinned if pinned and is_plausible_exact_version(pinned) else None
    return None


def _poetry_spec(spec: object) -> tuple[str | None, str | None, str]:
    """Interpret one Poetry dependency value statically (no solving)."""
    if isinstance(spec, str):
        text = spec.strip()
        kind = classify_specifier_kind(text)
        if kind != "registry":
            return text, None, kind
        if text.startswith("=="):
            return text, _pinned_from_constraint(text), "registry"
        return text, None, "registry"
    if isinstance(spec, dict):
        version = spec.get("version")
        git = spec.get("git")
        path = spec.get("path")
        if isinstance(git, str):
            return git, None, "vcs"
        if isinstance(path, str):
            return path, None, "path"
        if isinstance(version, str):
            kind = classify_specifier_kind(version)
            return version, _pinned_from_constraint(version), kind
        return None, None, "unknown"
    if isinstance(spec, list):
        return "multiple constraints", None, "registry"
    return None, None, "unknown"


def _has_unrecognized_dependency_sections(document: dict[str, object]) -> bool:
    poetry = document.get("tool")
    if isinstance(poetry, dict) and isinstance(poetry.get("poetry"), dict):
        section = poetry["poetry"]
        assert isinstance(section, dict)
        known = {"dependencies", "group", "dev-dependencies", "source", "scripts", "plugins"}
        return any(key not in known and "depend" in key.lower() for key in section)
    return False


# --- poetry.lock ------------------------------------------------------------


def parse_poetry_lock(text: str, ref: ManifestRef) -> ManifestOutcome:
    """Parse ``poetry.lock`` packages statically (resolved tree as recorded)."""
    try:
        document = tomllib.loads(text)
    except (tomllib.TOMLDecodeError, ValueError) as exc:
        return ManifestOutcome(
            ref=_with_state(ref, SupportState.FAILED),
            reasons=[f"malformed TOML; recorded as failed, not clean: {type(exc).__name__}"],
        )
    outcome = ManifestOutcome(ref=ref)
    packages = document.get("package")
    if not isinstance(packages, list):
        outcome.ref = _with_state(ref, SupportState.FAILED)
        outcome.reasons.append("no package list found; recorded as failed, not clean")
        return outcome
    for entry in packages:
        if not isinstance(entry, dict):
            continue
        name = entry.get("name")
        version = entry.get("version")
        if not isinstance(name, str):
            continue
        raw_version = version.strip() if isinstance(version, str) else ""
        resolved = raw_version if is_plausible_exact_version(raw_version) else None
        outcome.occurrences.append(
            _occurrence(
                ref=ref,
                original=name,
                constraint=f"=={resolved}" if resolved else None,
                resolved=resolved,
                section="poetry.lock.package",
                dependency_class=DependencyClass.UNKNOWN,
                runtime_context="unknown",
                line=find_line_for(text, name),
                kind="registry" if resolved else "unknown",
            )
        )
        dependencies = entry.get("dependencies")
        if isinstance(dependencies, dict):
            for child, child_spec in dependencies.items():
                if isinstance(child, str):
                    outcome.relationships.append(
                        LockRelation(
                            parent=name,
                            parent_version=resolved,
                            child=child,
                            child_version=_poetry_child_version(child_spec),
                        )
                    )
    return outcome


def _poetry_child_version(spec: object) -> str | None:
    """Exact child version when the lockfile records one, else ``None``.

    Poetry records dependency constraints (often ranges); only a
    version-shaped exact string is kept. Anything else stays unknown —
    consumers must not treat it as a resolved version.
    """
    if isinstance(spec, str):
        text = spec.strip()
        if text.startswith("=="):
            candidate = text[2:].strip()
            return candidate if is_plausible_exact_version(candidate) else None
        return text if is_plausible_exact_version(text) else None
    if isinstance(spec, dict):
        version = spec.get("version")
        if isinstance(version, str):
            text = version.strip()
            if text.startswith("=="):
                candidate = text[2:].strip()
                return candidate if is_plausible_exact_version(candidate) else None
            return text if is_plausible_exact_version(text) else None
    return None


# --- Pipfile.lock -----------------------------------------------------------


def parse_pipfile_lock(text: str, ref: ManifestRef) -> ManifestOutcome:
    """Parse ``Pipfile.lock`` default/develop sections statically."""
    try:
        document = json.loads(text)
    except (json.JSONDecodeError, ValueError, TypeError) as exc:
        return ManifestOutcome(
            ref=_with_state(ref, SupportState.FAILED),
            reasons=[f"malformed JSON; recorded as failed, not clean: {type(exc).__name__}"],
        )
    if not isinstance(document, dict):
        return ManifestOutcome(
            ref=_with_state(ref, SupportState.FAILED),
            reasons=["unexpected JSON shape; recorded as failed, not clean"],
        )
    outcome = ManifestOutcome(ref=ref)
    for section, runtime in (("default", "runtime"), ("develop", "development")):
        entries = document.get(section)
        if not isinstance(entries, dict):
            continue
        for name, meta in entries.items():
            version: str | None = None
            if isinstance(meta, dict) and isinstance(meta.get("version"), str):
                candidate = meta["version"].strip().lstrip("=").strip()
                # Only exact, version-shaped pins resolve. Wildcards (``*``),
                # empty strings, ranges, and malformed values stay ``None``
                # (unknown) — never guessed, never queried as exact.
                version = candidate if is_plausible_exact_version(candidate) else None
            elif not isinstance(meta, dict):
                outcome.reasons.append(
                    f"Pipfile.lock entry {name!r} has no parseable metadata; "
                    "recorded with unknown version"
                )
            outcome.occurrences.append(
                _occurrence(
                    ref=ref,
                    original=name,
                    constraint=f"=={version}" if version else None,
                    resolved=version,
                    section=f"Pipfile.lock.{section}",
                    dependency_class=DependencyClass.UNKNOWN,
                    runtime_context=runtime,
                    line=find_line_for(text, f'"{name}"'),
                    kind="registry" if version else "unknown",
                )
            )
    return outcome


# --- package.json -----------------------------------------------------------


_NPM_SECTIONS: tuple[tuple[str, str], ...] = (
    ("dependencies", "runtime"),
    ("devDependencies", "development"),
    ("optionalDependencies", "optional"),
    ("peerDependencies", "peer"),
)


def parse_package_json(text: str, ref: ManifestRef) -> ManifestOutcome:
    """Parse ``package.json`` dependency sections statically (JSON read only)."""
    try:
        document = json.loads(text)
    except (json.JSONDecodeError, ValueError, TypeError) as exc:
        return ManifestOutcome(
            ref=_with_state(ref, SupportState.FAILED),
            reasons=[f"malformed JSON; recorded as failed, not clean: {type(exc).__name__}"],
        )
    if not isinstance(document, dict):
        return ManifestOutcome(
            ref=_with_state(ref, SupportState.FAILED),
            reasons=["unexpected JSON shape; recorded as failed, not clean"],
        )
    outcome = ManifestOutcome(ref=ref)
    line_counts: dict[str, int] = {}
    for section, runtime in _NPM_SECTIONS:
        entries = document.get(section)
        if not isinstance(entries, dict):
            continue
        for name, spec in entries.items():
            constraint = spec if isinstance(spec, str) else None
            kind = classify_specifier_kind(constraint)
            resolved: str | None = None
            if constraint is not None and kind == "registry" and _is_bare_npm_version(constraint):
                resolved = constraint.strip()
            outcome.occurrences.append(
                _occurrence(
                    ref=ref,
                    original=name,
                    constraint=constraint,
                    resolved=resolved,
                    section=f"package.json.{section}",
                    dependency_class=DependencyClass.DIRECT,
                    runtime_context=runtime,
                    line=_next_line(text, f'"{name}"', line_counts),
                    kind=kind,
                )
            )
    if isinstance(document.get("workspaces"), (list, dict)):
        outcome.ref = _with_state(ref, SupportState.PARTIAL)
        outcome.reasons.append(
            "workspace/monorepo layout detected; occurrences keep their "
            "package/directory context and are not merged into one graph"
        )
    if isinstance(document.get("overrides"), dict):
        # Overrides pin/replace versions without declaring dependencies.
        outcome.reasons.append(
            "package.json `overrides` are version-resolution directives, not dependency "
            "declarations; they are not evaluated as occurrences"
        )
    return outcome


_NPM_EXACT_VERSION_RE = re.compile(r"^\d+\.\d+\.\d+([+-][A-Za-z0-9._\-+]+)?$")


def _is_bare_npm_version(spec: str) -> bool:
    """True only for a full ``X.Y.Z`` version (optional prerelease/build).

    Partial versions (``1``, ``1.2``) are npm ranges (``1.x``, ``1.2.x``),
    not exact versions, and must never resolve: per DEP-REQ-001 a
    range-derived version may never carry above Medium confidence, so partials
    stay unresolved here and are recorded as limitations downstream instead
    of being queried as exact.
    """
    return bool(_NPM_EXACT_VERSION_RE.match(spec.strip()))


# --- package-lock.json ------------------------------------------------------


def parse_package_lock_json(text: str, ref: ManifestRef) -> ManifestOutcome:
    """Parse ``package-lock.json`` recorded tree (v1/v2/v3, static read).

    Authoritative representation per the npm format (``packages`` is ignored
    by npm v7+ when present alongside legacy data, and v1 never has it):

    * lockfileVersion 1 (or missing with only ``dependencies``) → the
      ``dependencies`` tree, recursed so nested transitive nodes become
      occurrences instead of vanishing into edge-only records;
    * lockfileVersion 2 or 3 (or ``packages`` present with an unknown
      version) → the ``packages`` map only. The legacy ``dependencies``
      compatibility section of a v2 file describes the same nodes and is
      never counted a second time.
    """
    try:
        document = json.loads(text)
    except (json.JSONDecodeError, ValueError, TypeError) as exc:
        return ManifestOutcome(
            ref=_with_state(ref, SupportState.FAILED),
            reasons=[f"malformed JSON; recorded as failed, not clean: {type(exc).__name__}"],
        )
    if not isinstance(document, dict):
        return ManifestOutcome(
            ref=_with_state(ref, SupportState.FAILED),
            reasons=["unexpected JSON shape; recorded as failed, not clean"],
        )
    outcome = ManifestOutcome(ref=ref)
    lock_version = document.get("lockfileVersion")
    packages = document.get("packages")
    dependencies = document.get("dependencies")
    packages_map = packages if isinstance(packages, dict) else None
    deps_map = dependencies if isinstance(dependencies, dict) else None
    if lock_version == 1:
        if deps_map is None:
            outcome.ref = _with_state(ref, SupportState.FAILED)
            outcome.reasons.append(
                "lockfileVersion 1 without a `dependencies` tree; recorded as failed"
            )
            return outcome
        _parse_v1_dependencies(deps_map, text, outcome, ref)
    elif packages_map is not None:
        _parse_packages_map(packages_map, outcome, ref)
        if deps_map is not None:
            outcome.reasons.append(
                f"lockfileVersion {lock_version}: authoritative `packages` section used; "
                "legacy `dependencies` compatibility section describes the same nodes "
                "and is not counted a second time"
            )
    elif deps_map is not None:
        _parse_v1_dependencies(deps_map, text, outcome, ref)
    else:
        outcome.ref = _with_state(ref, SupportState.FAILED)
        outcome.reasons.append("no recorded dependency entries found; recorded as failed")
        return outcome
    if not outcome.occurrences:
        outcome.ref = _with_state(ref, SupportState.FAILED)
        outcome.reasons.append("no recorded dependency entries found; recorded as failed")
    return outcome


def _lock_version_parts(raw: object) -> tuple[str | None, str]:
    """Split a lockfile version value into (resolved, kind).

    ``resolved`` is set only for registry version numbers shaped like an
    exact version. Non-registry values (git specifiers, tarball URLs,
    ``file:`` links per the npm format) resolve to ``None`` with an honest
    kind instead of being queried as exact versions downstream.
    """
    if not isinstance(raw, str) or not raw.strip():
        return None, "unknown"
    text = raw.strip()
    kind = classify_specifier_kind(text)
    if kind == "registry" and is_plausible_exact_version(text):
        return text, "registry"
    if kind == "registry":
        return None, "registry"
    return None, kind


def _parse_packages_map(
    packages: dict[str, object], outcome: ManifestOutcome, ref: ManifestRef
) -> None:
    """Parse a v2/v3 ``packages`` location map (names are last path segments)."""
    assert isinstance(packages, dict)
    # First pass: occurrences plus a location -> exact-version map so edges
    # below resolve to the tree instance npm actually recorded (nested first,
    # mirroring npm resolution), instead of attributing by bare name only.
    versions_by_key: dict[str, str | None] = {}
    for key, meta in packages.items():
        if not isinstance(meta, dict) or not key:
            continue
        name = key.split("node_modules/")[-1].strip()
        if not name:
            continue
        resolved, kind = _lock_version_parts(meta.get("version"))
        versions_by_key[key] = resolved
        runtime = "development" if "dev" in str(meta.get("dev")) else "unknown"
        outcome.occurrences.append(
            _occurrence(
                ref=ref,
                original=name,
                constraint=resolved,
                resolved=resolved,
                section="package-lock.packages",
                dependency_class=DependencyClass.UNKNOWN,
                runtime_context=runtime,
                line=None,
                kind=kind,
            )
        )
    for key, meta in packages.items():
        if not isinstance(meta, dict) or not key:
            continue
        parent = key.split("node_modules/")[-1].strip()
        if not parent:
            continue  # root entry: no parent package instance to attribute
        parent_version = versions_by_key.get(key)
        for edge_map in (meta.get("dependencies"), meta.get("optionalDependencies")):
            if not isinstance(edge_map, dict):
                continue
            for child in edge_map:
                outcome.relationships.append(
                    LockRelation(
                        parent=parent,
                        parent_version=parent_version,
                        child=child,
                        child_version=_resolve_tree_instance(key, child, versions_by_key),
                    )
                )


def _resolve_tree_instance(
    parent_key: str, child: str, versions_by_key: dict[str, str | None]
) -> str | None:
    """Exact child version at the tree location npm recorded, if knowable.

    npm nests a dependency under its parent when versions conflict, so the
    edge resolves to the nested instance first and to the top-level instance
    otherwise. ``None`` means the instance could not be established — never
    a guessed version.
    """
    nested = f"{parent_key}/node_modules/{child}" if parent_key else f"node_modules/{child}"
    if nested in versions_by_key:
        return versions_by_key[nested]
    for key, version in versions_by_key.items():
        if key.split("node_modules/")[-1].strip() == child and key.count("node_modules/") == 1:
            return version
    return None


def _parse_v1_dependencies(
    dependencies: object, text: str, outcome: ManifestOutcome, ref: ManifestRef
) -> None:
    """Parse a v1 ``dependencies`` tree recursively (nested nodes kept)."""
    if not isinstance(dependencies, dict):
        return
    _parse_v1_level(dependencies, text, outcome, ref, parent=None, parent_version=None, counts={})


def _parse_v1_level(
    level: dict[str, object],
    text: str,
    outcome: ManifestOutcome,
    ref: ManifestRef,
    parent: str | None,
    parent_version: str | None,
    counts: dict[str, int],
) -> None:
    for name, meta in level.items():
        if not isinstance(meta, dict):
            continue
        resolved, kind = _lock_version_parts(meta.get("version"))
        outcome.occurrences.append(
            _occurrence(
                ref=ref,
                original=name,
                constraint=resolved,
                resolved=resolved,
                section="package-lock.dependencies",
                dependency_class=DependencyClass.UNKNOWN,
                runtime_context="unknown",
                line=_next_line(text, f'"{name}"', counts),
                kind=kind,
            )
        )
        if parent is not None:
            outcome.relationships.append(
                LockRelation(
                    parent=parent,
                    parent_version=parent_version,
                    child=name,
                    child_version=resolved,
                )
            )
        requires = meta.get("requires")
        if isinstance(requires, dict):
            for child, child_spec in requires.items():
                outcome.relationships.append(
                    LockRelation(
                        parent=name,
                        parent_version=resolved,
                        child=child,
                        child_version=(
                            child_spec.strip()
                            if isinstance(child_spec, str)
                            and is_plausible_exact_version(child_spec.strip())
                            else None
                        ),
                    )
                )
        nested = meta.get("dependencies")
        if isinstance(nested, dict):
            _parse_v1_level(
                nested, text, outcome, ref, parent=name, parent_version=resolved, counts=counts
            )


def parse_manifest_text(text: str, ref: ManifestRef) -> ManifestOutcome:
    """Dispatch to the format parser (never raises for malformed input)."""
    try:
        if ref.format == "requirements_txt":
            return parse_requirements_txt(text, ref)
        if ref.format == "pyproject_toml":
            return parse_pyproject_toml(text, ref)
        if ref.format == "poetry_lock":
            return parse_poetry_lock(text, ref)
        if ref.format == "pipfile_lock":
            return parse_pipfile_lock(text, ref)
        if ref.format == "package_json":
            return parse_package_json(text, ref)
        if ref.format == "package_lock_json":
            return parse_package_lock_json(text, ref)
    except Exception as exc:  # defensive: a parser bug never takes down analysis
        _logger.error("dependency.parse.failed")
        return ManifestOutcome(
            ref=_with_state(ref, SupportState.FAILED),
            reasons=[f"parser did not complete ({type(exc).__name__}); recorded as failed"],
        )
    return ManifestOutcome(
        ref=_with_state(ref, SupportState.UNSUPPORTED),
        reasons=[f"format {ref.format} is outside the V1.0 boundary"],
    )
