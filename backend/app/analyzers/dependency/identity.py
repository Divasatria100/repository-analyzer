"""Dependency identity normalization and version semantics (TASK-114).

PyPI names follow the PEP 503 normalization (case-insensitive;
``-``, ``_``, ``.`` runs collapse to ``-``). npm names keep their scope
and case (``@scope/package`` preserved); npm comparison is case-sensitive
while PyPI comparison is case-insensitive. The two rules are never mixed.
"""

from __future__ import annotations

import re

from app.analyzers.dependency.models import ECOSYSTEM_NPM, ECOSYSTEM_PYPI

_PYPI_NORMALIZE_RE = re.compile(r"[-_.]+")

_VERSION_OPERATOR_RE = re.compile(r"(===|==|~=|!=|>=|<=|>|<|===|@|\+|~|\^|\*|x|X|,|\s\|\||\s)")

_NPM_RANGE_CHARS_RE = re.compile(r"[\^~<>=xX\*| \-]")

_KNOWN_VCS_PREFIXES = ("git+", "hg+", "svn+", "bzr+")


def normalize_pypi_name(name: str) -> str:
    """PEP 503 normalization for PyPI distribution names."""
    return _PYPI_NORMALIZE_RE.sub("-", name.strip().lower())


def normalize_npm_name(name: str) -> str:
    """npm package-name normalization: strip only, scope and case preserved."""
    return name.strip()


def canonical_name(ecosystem: str, name: str) -> str:
    """Ecosystem-correct canonical identity (never cross-applied)."""
    if ecosystem == ECOSYSTEM_PYPI:
        return normalize_pypi_name(name)
    if ecosystem == ECOSYSTEM_NPM:
        return normalize_npm_name(name)
    return name.strip().lower()


def identity_key(ecosystem: str, name: str) -> str:
    """Comparison key for duplicate detection (PyPI case-insensitive)."""
    if ecosystem == ECOSYSTEM_PYPI:
        return f"{ecosystem}:{normalize_pypi_name(name)}"
    return f"{ecosystem}:{normalize_npm_name(name)}"


def classify_specifier_kind(value: str | None) -> str:
    """Classify a declared dependency reference (registry/url/vcs/path/...)."""
    if value is None or not value.strip():
        return "unknown"
    text = value.strip()
    lowered = text.lower()
    if text.startswith(("http://", "https://", "ftp://", "file://")):
        return "url"
    if text.startswith(_KNOWN_VCS_PREFIXES) or lowered.startswith("git://"):
        return "vcs"
    if lowered.startswith(("file:", "path:", "./", "../", "/", "~/")):
        return "path"
    if "-e " in f" {lowered} " or lowered.startswith(("-e ", "--editable")):
        return "editable"
    return "registry"


def is_exact_pinned(constraint: str | None) -> bool:
    """True only for exact pins (``==``/``===`` for PyPI, bare ``x.y.z`` npm)."""
    if constraint is None:
        return False
    text = constraint.strip()
    if not text:
        return False
    if text.startswith(("==", "===")) and "," not in text:
        remainder = text.split(None, 1)[-1] if " " in text else text[2:]
        remainder = remainder.strip()
        return bool(remainder) and not _VERSION_OPERATOR_RE.search(remainder)
    if "," in text or " " in text.strip():
        return False
    # Bare npm version: digits and dots only (no range characters).
    if _NPM_RANGE_CHARS_RE.search(text):
        return False
    return bool(re.match(r"^\d+\.\d+\.\d+([+-].+)?$", text)) or bool(
        re.match(r"^\d+\.\d+([+-].+)?$", text)
    )


def split_requirement_name(line: str) -> tuple[str, str | None]:
    """Split a requirement line into (name, constraint-or-None), static only."""
    text = line.strip()
    for marker in (";", "#"):
        if marker in text:
            # Keep version part before environment markers/comments.
            head, _, _ = text.partition(marker)
            text = head.strip()
            break
    match = re.match(r"^\s*([A-Za-z0-9_.\-\[\]@/:]+)\s*(.*)$", text)
    if not match:
        return text, None
    name = match.group(1).strip().rstrip(",")
    rest = match.group(2).strip()
    # Extras (``requests[security]``) belong to the name for display but the
    # canonical identity strips them.
    name = re.sub(r"\[.*\]$", "", name)
    if not rest:
        return name, None
    if rest.startswith(("http://", "https://", "git+", "@")):
        return name, rest
    return name, rest or None


def strip_extras(name: str) -> str:
    """Remove ``[extra]`` suffixes before canonicalization."""
    return re.sub(r"\[.*\]$", "", name.strip())
