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


_NPM_SHORTHAND_VCS_PREFIXES = ("github:", "gist:", "bitbucket:", "gitlab:")

#: Characters permitted inside one exact version token (PEP 440 versions,
#: epochs with ``!``, pre/post/dev releases, semver build metadata). Anything
#: else (spaces, commas, operators, slashes, backslashes, ``*``) means the
#: value is not an exact version.
_EXACT_VERSION_RE = re.compile(r"[A-Za-z0-9._\-+!]+")


def classify_specifier_kind(value: str | None) -> str:
    """Classify a declared dependency reference (registry/url/vcs/path/...)."""
    if value is None or not value.strip():
        return "unknown"
    text = value.strip()
    lowered = text.lower()
    if text.startswith(("http://", "https://", "ftp://", "file://")):
        return "url"
    if text.startswith("@"):
        # PEP 508 direct reference (``pkg @ https://...``): a URL, not registry.
        return "url"
    if lowered.startswith("npm:"):
        # npm alias (``npm:other@1.0.0``): a registry reference with an
        # embedded name; the version is never extracted as exact here.
        return "registry"
    if text.startswith(_KNOWN_VCS_PREFIXES) or lowered.startswith("git://"):
        return "vcs"
    if lowered.startswith(_NPM_SHORTHAND_VCS_PREFIXES):
        # npm ``github:user/repo``-style shorthands address git repositories.
        return "vcs"
    if "-e " in f" {lowered} " or lowered.startswith(("-e ", "--editable")):
        return "editable"
    if lowered.startswith(("file:", "path:", "link:", "portal:", "./", "../", "/", "~/")):
        return "path"
    if "/" in text and not text.startswith("@"):
        # Registry names never contain ``/`` outside ``@scope/`` prefixes:
        # ``user/repo`` is the npm GitHub shorthand (a git source).
        return "vcs"
    return "registry"


def is_plausible_exact_version(value: str | None) -> bool:
    """True only for strings shaped like one exact version (never a range).

    Rejects wildcards (``*``), dist-tags without digits (``latest``),
    operators, whitespace, commas, URLs, paths, and stray characters such as
    a requirements line-continuation backslash. A plausible shape is still
    not proof of resolvability — lockfile provenance decides that — but an
    implausible shape must never be stored or queried as a resolved version.
    """
    if value is None:
        return False
    text = value.strip()
    if not text or not text[0].isalnum():
        return False
    if not re.fullmatch(r"[A-Za-z0-9._\-+!]+", text):
        return False
    return any(char.isdigit() for char in text)


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
