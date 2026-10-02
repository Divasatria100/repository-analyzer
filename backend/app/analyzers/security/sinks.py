"""Shared sink tables for security injection rules (TASK-097–100 support).

One table per rule maps NCM ``callee_text`` values (dotted names as
written, e.g. ``cursor.execute``) to sink candidacy. Rules add their own
argument/origin analysis on top; no sink logic is duplicated across rule
files.

Two match tiers keep matching honest:

* ``suffixes`` — specific dotted names matched directly.
* ``guarded_suffixes`` / ``bare_names`` — generic shapes matched only
  with import corroboration from the same file, so unrelated same-named
  helpers (``server.run``, ``parser.open``) are not claimed as sinks.

Only APIs actually handled by the rules are listed. Recognition of an
API is a rule-set decision (docs/07 SEC-REQ-010), not a claim of
framework support.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class SinkSpec:
    """One recognized sink family: direct plus import-guarded shapes."""

    #: Dotted suffixes matched directly against NCM ``callee_text``.
    suffixes: tuple[str, ...] = ()
    #: Bare names matched directly (language builtins only, e.g. ``open``).
    direct_names: tuple[str, ...] = ()
    #: Generic suffixes matched only with import corroboration.
    guarded_suffixes: tuple[str, ...] = ()
    #: Bare names matched only with import corroboration.
    bare_names: tuple[str, ...] = ()
    #: Import target fragments that corroborate guarded shapes.
    import_hints: tuple[str, ...] = ()


SQL_SINKS = SinkSpec(
    guarded_suffixes=(".execute", ".executemany", ".executescript"),
    bare_names=("execute", "executemany", "executescript"),
    import_hints=(
        "sqlite3",
        "psycopg2",
        "psycopg",
        "asyncpg",
        "pymysql",
        "MySQLdb",
        "cx_Oracle",
        "oracledb",
        "sqlalchemy",
        "pyodbc",
    ),
)

#: Receiver-name fragments suggesting a database handle. Corroborate a
#: generic ``.execute*`` call alongside (not instead of) import evidence.
SQL_RECEIVER_HINTS = (
    "cursor",
    "conn",
    "connection",
    "db",
    "database",
    "session",
    "engine",
    "query",
)

COMMAND_SINKS = SinkSpec(
    suffixes=(
        "subprocess.run",
        "subprocess.call",
        "subprocess.Popen",
        "subprocess.check_call",
        "subprocess.check_output",
        "os.system",
        "os.popen",
    ),
    guarded_suffixes=(
        ".run",
        ".call",
        ".Popen",
        ".check_call",
        ".check_output",
        ".system",
        ".popen",
    ),
    bare_names=("system", "popen", "run", "call", "Popen", "check_call", "check_output"),
    import_hints=("subprocess", "os"),
)

PATH_SINKS = SinkSpec(
    suffixes=(
        "os.open",
        "os.remove",
        "os.unlink",
        "os.rename",
        "os.replace",
        "os.rmdir",
        "os.mkdir",
        "os.makedirs",
        "shutil.copy",
        "shutil.copy2",
        "shutil.copytree",
        "shutil.move",
        "shutil.rmtree",
        "tarfile.extractall",
        "zipfile.extractall",
        "pathlib.Path",
    ),
    guarded_suffixes=(
        ".open",
        ".read_text",
        ".write_text",
        ".read_bytes",
        ".write_bytes",
        ".unlink",
        ".rename",
        ".replace",
        ".mkdir",
        ".rmdir",
        ".extractall",
        ".remove",
        ".copy",
        ".copy2",
        ".move",
    ),
    bare_names=(),
    import_hints=("os", "pathlib", "shutil", "tarfile", "zipfile", "io"),
    direct_names=("open",),
)

SSRF_SINKS = SinkSpec(
    suffixes=(
        "requests.get",
        "requests.post",
        "requests.put",
        "requests.delete",
        "requests.head",
        "requests.options",
        "requests.patch",
        "requests.request",
        "httpx.get",
        "httpx.post",
        "httpx.put",
        "httpx.delete",
        "httpx.head",
        "httpx.options",
        "httpx.patch",
        "httpx.request",
        "urllib.request.urlopen",
        "urllib.request.Request",
        "http.client.HTTPConnection",
        "http.client.HTTPSConnection",
    ),
    guarded_suffixes=(".urlopen", ".get", ".post", ".request"),
    bare_names=("urlopen", "get", "post", "request"),
    import_hints=("requests", "httpx", "urllib.request", "urllib", "http.client"),
)


def _import_corroborated(import_targets: frozenset[str], hints: tuple[str, ...]) -> bool:
    """True when a file import matches one of the hint fragments."""
    for hint in hints:
        for target in import_targets:
            if target == hint or target.startswith(hint + "."):
                return True
    return False


def callee_matches(callee: str, spec: SinkSpec, import_targets: frozenset[str]) -> bool:
    """True when an NCM ``callee_text`` matches a sink spec.

    Specific dotted suffixes and builtin direct names match directly.
    Generic shapes and other bare names match only with import
    corroboration from the same file.
    """
    if callee in spec.direct_names:
        return True
    for suffix in spec.suffixes:
        if callee == suffix or callee.endswith("." + suffix):
            return True
    if not _import_corroborated(import_targets, spec.import_hints):
        return False
    for suffix in spec.guarded_suffixes:
        if callee == suffix.lstrip(".") or callee.endswith(suffix):
            return True
    return callee in spec.bare_names


def receiver_of(callee: str) -> str:
    """The dotted receiver prefix of a call (``""`` for bare names)."""
    head, dot, _ = callee.rpartition(".")
    return head if dot else ""


def sql_sink_match(callee: str, import_targets: frozenset[str]) -> bool:
    """SQL gate: generic ``.execute*`` plus import or receiver corroboration."""
    attr = callee.rpartition(".")[2]
    if attr not in ("execute", "executemany", "executescript"):
        return False
    if _import_corroborated(import_targets, SQL_SINKS.import_hints):
        return True
    receiver = receiver_of(callee).lower()
    if not receiver:
        return False
    return any(hint in receiver for hint in SQL_RECEIVER_HINTS)
