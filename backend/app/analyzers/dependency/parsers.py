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
import stat
import tomllib
from pathlib import Path

from app.analyzers.dependency.identity import (
    canonical_name,
    classify_specifier_kind,
    split_requirement_name,
    strip_extras,
)
from app.analyzers.dependency.models import (
    DependencyClass,
    DependencyOccurrence,
    ManifestOutcome,
    ManifestRef,
    SupportState,
)
from app.core.logging import get_logger, redact_text

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


def find_line_for(text: str, needle: str) -> int | None:
    """Best-effort 1-based line number for a dependency name (None when unsure)."""
    lowered = needle.lower()
    for number, line in enumerate(text.splitlines(), start=1):
        if lowered in line.lower():
            return number
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
        resolved: str | None = None
        if constraint is not None and constraint.strip().startswith("==") and kind == "registry":
            pinned = constraint.strip()[2:].strip().split(",")[0].strip()
            pinned = pinned.split()[0] if pinned else ""
            resolved = pinned or None
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
                    line=find_line_for(text, name),
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
                            line=find_line_for(text, name),
                            kind=classify_specifier_kind(constraint),
                        )
                    )
    poetry = document.get("tool")
    poetry_deps: dict[str, object] = {}
    poetry_partial_notes: list[str] = []
    if isinstance(poetry, dict) and isinstance(poetry.get("poetry"), dict):
        poetry_section = poetry["poetry"]
        assert isinstance(poetry_section, dict)
        raw_deps = poetry_section.get("dependencies")
        if isinstance(raw_deps, dict):
            poetry_deps.update(raw_deps)
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
                            poetry_deps[f"{group_name}.{dep_name}"] = dep_spec
        dev_deps = poetry_section.get("dev-dependencies")
        if isinstance(dev_deps, dict):
            for dep_name, dep_spec in dev_deps.items():
                poetry_deps[f"dev.{dep_name}"] = dep_spec
        if "scripts" in poetry_section or "plugins" in poetry_section:
            poetry_partial_notes.append(
                "poetry scripts/plugins sections are not dependency declarations; not evaluated"
            )
    for qualified, spec in poetry_deps.items():
        if "." in qualified and not qualified.startswith("python"):
            group, _, dep_name = qualified.partition(".")
            section = f"tool.poetry.group.{group}.dependencies"
            runtime = "development" if group == "dev" else "runtime"
        else:
            dep_name, section, runtime = qualified, "tool.poetry.dependencies", "runtime"
        if dep_name.lower() == "python":
            continue
        constraint, resolved, kind = _poetry_spec(spec)
        outcome.occurrences.append(
            _occurrence(
                ref=ref,
                original=dep_name,
                constraint=constraint,
                resolved=resolved,
                section=section,
                dependency_class=DependencyClass.DIRECT,
                runtime_context=runtime,
                line=find_line_for(text, dep_name),
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


def _as_str_list(value: object) -> list[str]:
    if isinstance(value, (list, tuple)):
        return [item for item in value if isinstance(item, str)]
    return []


def _pinned_from_constraint(constraint: str | None) -> str | None:
    if constraint is None:
        return None
    text = constraint.strip()
    if text.startswith("==") and "," not in text and " " not in text.strip("="):
        pinned = text[2:].strip().split(";")[0].strip()
        return pinned or None
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
        resolved = version if isinstance(version, str) and version.strip() else None
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
            parent = name
            for child in dependencies:
                if isinstance(child, str):
                    outcome.relationships.append((parent, child))
    return outcome


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
                raw_version = meta["version"].strip()
                version = raw_version.lstrip("=").strip() or None
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
                    line=find_line_for(text, f'"{name}"'),
                    kind=kind,
                )
            )
    if isinstance(document.get("workspaces"), (list, dict)):
        outcome.ref = _with_state(ref, SupportState.PARTIAL)
        outcome.reasons.append(
            "workspace/monorepo layout detected; occurrences keep their "
            "package/directory context and are not merged into one graph"
        )
    return outcome


def _is_bare_npm_version(spec: str) -> bool:
    text = spec.strip()
    if not text:
        return False
    return text.replace(".", "").replace("-", "").replace("+", "").isdigit() and text[0].isdigit()


# --- package-lock.json ------------------------------------------------------


def parse_package_lock_json(text: str, ref: ManifestRef) -> ManifestOutcome:
    """Parse ``package-lock.json`` recorded tree (v1/v2/v3, static read)."""
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
    packages = document.get("packages")
    if isinstance(packages, dict):
        for key, meta in packages.items():
            if not isinstance(meta, dict) or not key:
                continue
            name = key.split("node_modules/")[-1].strip()
            if not name:
                continue
            version = meta.get("version")
            resolved = version.strip() if isinstance(version, str) and version.strip() else None
            outcome.occurrences.append(
                _occurrence(
                    ref=ref,
                    original=name,
                    constraint=resolved,
                    resolved=resolved,
                    section="package-lock.packages",
                    dependency_class=DependencyClass.UNKNOWN,
                    runtime_context="development" if "dev" in str(meta.get("dev")) else "unknown",
                    line=None,
                    kind="registry" if resolved else "unknown",
                )
            )
            dependencies = meta.get("dependencies")
            if isinstance(dependencies, dict):
                for child in dependencies:
                    outcome.relationships.append((name, child))
    dependencies = document.get("dependencies")
    if isinstance(dependencies, dict):
        for name, meta in dependencies.items():
            if not isinstance(meta, dict):
                continue
            version = meta.get("version")
            resolved = version.strip() if isinstance(version, str) and version.strip() else None
            outcome.occurrences.append(
                _occurrence(
                    ref=ref,
                    original=name,
                    constraint=resolved,
                    resolved=resolved,
                    section="package-lock.dependencies",
                    dependency_class=DependencyClass.UNKNOWN,
                    runtime_context="unknown",
                    line=find_line_for(text, f'"{name}"'),
                    kind="registry" if resolved else "unknown",
                )
            )
            requires = meta.get("requires")
            if isinstance(requires, dict):
                for child in requires:
                    outcome.relationships.append((name, child))
            nested = meta.get("dependencies")
            if isinstance(nested, dict):
                for child in nested:
                    outcome.relationships.append((name, child))
    if not outcome.occurrences:
        outcome.ref = _with_state(ref, SupportState.FAILED)
        outcome.reasons.append("no recorded dependency entries found; recorded as failed")
    return outcome


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


def redacted_constraint_text(constraint: str | None) -> str | None:
    """Redact credentials from a constraint before evidence/logging use."""
    if constraint is None:
        return None
    return redact_text(constraint)
