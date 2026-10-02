"""Shared sink tables for security rules (TASK-097–105 support).

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


DESERIALIZATION_SINKS = SinkSpec(
    suffixes=(
        "pickle.loads",
        "pickle.load",
        "_pickle.loads",
        "_pickle.load",
        "cPickle.loads",
        "cPickle.load",
        "marshal.loads",
        "marshal.load",
        "shelve.open",
        "yaml.unsafe_load",
    ),
    guarded_suffixes=(
        ".loads",
        ".load",
        ".unsafe_load",
    ),
    bare_names=("loads", "load", "unsafe_load"),
    import_hints=("pickle", "_pickle", "cPickle", "marshal", "shelve", "yaml", "ruamel.yaml"),
)

#: Callee shapes that are data-only deserialization (never unsafe sinks).
SAFE_DESERIALIZATION_CALLEES = frozenset(
    {
        "json.loads",
        "json.load",
        "yaml.safe_load",
        "yaml.safe_load_all",
        "yaml.full_load",
    }
)

#: yaml.load is unsafe only with an object-constructing loader.
YAML_UNSAFE_LOADERS = ("UnsafeLoader", "Loader", "FullLoader")
YAML_SAFE_LOADERS = ("SafeLoader", "CSafeLoader", "BaseLoader")

DYNAMIC_EXEC_SINKS = SinkSpec(
    direct_names=("eval", "exec", "compile", "__import__"),
)

#: Callee shapes that look dynamic but belong to other rules (never this one).
DYNAMIC_EXEC_EXCLUSIONS = frozenset(
    {
        "ast.literal_eval",
        "literal_eval",
    }
)

CRYPTO_SINKS = SinkSpec(
    suffixes=(
        "hashlib.md5",
        "hashlib.sha1",
        "hashlib.new",
        "Crypto.Hash.MD5.new",
        "Crypto.Hash.SHA.new",
        "Crypto.Hash.SHA1.new",
        "Cryptodome.Hash.MD5.new",
        "Cryptodome.Hash.SHA.new",
        "Cryptodome.Hash.SHA1.new",
        "Crypto.Cipher.DES.new",
        "Crypto.Cipher.DES3.new",
        "Crypto.Cipher.ARC4.new",
        "Crypto.Cipher.ARC2.new",
        "Cryptodome.Cipher.DES.new",
        "Cryptodome.Cipher.DES3.new",
        "Cryptodome.Cipher.ARC4.new",
        "Cryptodome.Cipher.ARC2.new",
    ),
    guarded_suffixes=(
        ".md5",
        ".sha1",
        ".new",
    ),
    bare_names=("md5", "sha1"),
    import_hints=("hashlib", "Crypto", "Cryptodome", "cryptography"),
)

#: Weak hash names recognized inside ``hashlib.new(...)`` literals.
WEAK_HASH_NAMES = frozenset({"md5", "sha1", "sha"})

#: Strong hash names that must never be reported by this rule.
STRONG_HASH_NAMES = frozenset(
    {
        "sha256",
        "sha384",
        "sha512",
        "sha224",
        "sha3_224",
        "sha3_256",
        "sha3_384",
        "sha3_512",
        "blake2b",
        "blake2s",
        "shake_128",
        "shake_256",
    }
)

#: Non-cryptographic random generators (stdlib ``random`` only).
RANDOM_SINKS = SinkSpec(
    suffixes=(
        "random.random",
        "random.choice",
        "random.choices",
        "random.randint",
        "random.randrange",
        "random.uniform",
        "random.sample",
        "random.shuffle",
    ),
)

TLS_CALL_SINKS = SinkSpec(
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
        "urllib3.request",
        "urllib3.urlopen",
        "ssl._create_unverified_context",
        "ssl.SSLContext",
        "ssl.wrap_socket",
        "aiohttp.TCPConnector",
    ),
    guarded_suffixes=(
        ".get",
        ".post",
        ".request",
        ".urlopen",
        "._create_unverified_context",
        ".SSLContext",
        ".wrap_socket",
        ".TCPConnector",
    ),
    bare_names=(
        "get",
        "post",
        "request",
        "urlopen",
        "SSLContext",
        "wrap_socket",
        "TCPConnector",
    ),
    import_hints=("requests", "httpx", "urllib3", "ssl", "aiohttp"),
)

CORS_MIDDLEWARE_SINKS = SinkSpec(
    suffixes=("CORSMiddleware",),
    guarded_suffixes=(".CORSMiddleware", ".add_middleware"),
    bare_names=("CORSMiddleware", "add_middleware"),
    import_hints=("fastapi", "starlette"),
)

LOGGING_SINKS = SinkSpec(
    suffixes=(
        "logging.debug",
        "logging.info",
        "logging.warning",
        "logging.warn",
        "logging.error",
        "logging.exception",
        "logging.critical",
        "logging.log",
    ),
    guarded_suffixes=(
        ".debug",
        ".info",
        ".warning",
        ".warn",
        ".error",
        ".exception",
        ".critical",
        ".log",
    ),
    bare_names=("debug", "info", "warning", "warn", "error", "exception", "critical", "log"),
    import_hints=("logging",),
    direct_names=("print",),
)


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
