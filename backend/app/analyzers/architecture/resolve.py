"""Python import-to-module resolution over NCM paths (TASK-124 support).

Maps an :class:`ImportRef` written in one module to the repository-relative
path of the imported module, using only the set of known parsed module
paths. No filesystem access, no imports, no execution — a pure function of
(strings, known-paths).

Resolution rules (documented; conservative — unmapped stays unresolved):

* Absolute ``a.b.c`` (or ``from a.b import c`` recorded as ``a.b.c``):
  longest dotted-prefix wins. Each candidate prefix maps to
  ``<prefix as path>.py`` or ``<prefix as path>/__init__.py`` relative to
  the repository root. The longest prefix with a known parsed module wins,
  so ``from pkg import submodule`` (recorded ``pkg.submodule``) reaches the
  submodule file when present and falls back to the package initializer.
* Relative (leading dots, ``level`` = number of dots): level 1 anchors at
  the importing file's own directory (its package); each further dot climbs
  one directory. The remainder resolves like an absolute import beneath the
  anchor. ``from . import name`` anchors at the own directory; an importer
  that is itself ``__init__.py`` anchors at its own directory.
* Only targets that resolve to a *parsed* module path in the analysis map
  to internal modules. Everything else stays unmapped (the caller records
  it external/unresolved per the parser's resolution hint).
"""

from __future__ import annotations


def _candidate_files(dotted: str) -> list[str]:
    """Possible repository-relative files for a dotted module path."""
    stem = dotted.replace(".", "/")
    return [f"{stem}.py", f"{stem}/__init__.py"]


def resolve_absolute(target: str, known: set[str]) -> str | None:
    """Resolve an absolute dotted target to a known module path, if any."""
    parts = target.split(".")
    for width in range(len(parts), 0, -1):
        prefix = ".".join(parts[:width])
        for candidate in _candidate_files(prefix):
            if candidate in known:
                return candidate
    return None


def resolve_relative(target: str, level: int, importer_path: str, known: set[str]) -> str | None:
    """Resolve a relative import (leading dots stripped) beneath its anchor."""
    stripped = target.lstrip(".")
    directory = importer_path.rsplit("/", 1)[0] if "/" in importer_path else ""
    # Level 1 anchors at the own directory; each extra dot climbs one level.
    anchor = directory
    for _ in range(level - 1):
        anchor = anchor.rsplit("/", 1)[0] if "/" in anchor else ""
    if not stripped:
        # ``from . import x`` is recorded per-name (``.x``); a bare anchor
        # means the package initializer itself when one exists.
        for candidate in (f"{anchor}/__init__.py" if anchor else "__init__.py",):
            if candidate in known:
                return candidate
        return None
    parts = stripped.split(".")
    for width in range(len(parts), 0, -1):
        suffix = "/".join(parts[:width])
        base = f"{anchor}/{suffix}" if anchor else suffix
        for candidate in (f"{base}.py", f"{base}/__init__.py"):
            if candidate in known:
                return candidate
    return None


def resolve_import(
    target: str,
    *,
    is_relative: bool,
    level: int,
    importer_path: str,
    known: set[str],
) -> str | None:
    """Resolve one import target to a known parsed module path, if possible."""
    if not target:
        return None
    if is_relative or target.startswith("."):
        dots = 0
        for char in target:
            if char != ".":
                break
            dots += 1
        return resolve_relative(target, max(dots, level), importer_path, known)
    return resolve_absolute(target, known)
