"""Security rule metadata (TASK-095).

Extends the Phase 6 :class:`RuleMetadata` (registration identity) with
the security-specific declaration each injection rule needs: subcategory,
confidence guidance, supported languages, recognized sink/source
concepts, and coverage notes. The Phase 6 schema is reused unchanged for
registration; this spec is the single home for the extra fields (no
parallel metadata model beyond this extension).
"""

from __future__ import annotations

from dataclasses import dataclass

from app.analyzers.rules import RuleMetadata

#: Analyzer identity shared by all security rules (Phase 6 convention).
SECURITY_ANALYZER_ID = "security"

#: V1.0 supports Python only (docs/07 SEC-REQ-006, docs/09).
SECURITY_SUPPORTED_LANGUAGES = ("python",)


@dataclass(frozen=True)
class SecurityRuleSpec:
    """Full static declaration for one security rule."""

    rule_id: str
    name: str
    subcategory: str
    description: str
    default_severity: str
    severity_range: str
    supported_languages: tuple[str, ...]
    supported_sinks: tuple[str, ...]
    supported_sources: tuple[str, ...]
    coverage_notes: str
    recommendation: str
    documentation_ref: str = "docs/07-security-analysis-requirements.md"

    def to_metadata(self, version: str) -> RuleMetadata:
        """Project onto the Phase 6 registration schema (reused, unmodified)."""
        return RuleMetadata(
            rule_id=self.rule_id,
            name=self.name,
            description=self.description,
            analyzer_id=SECURITY_ANALYZER_ID,
            version=version,
            default_severity=self.default_severity,
            documentation_ref=self.documentation_ref,
        )

    def to_dict(self) -> dict[str, object]:
        """Deterministic serialization of the full declaration."""
        return {
            "rule_id": self.rule_id,
            "name": self.name,
            "category": "security",
            "subcategory": self.subcategory,
            "description": self.description,
            "default_severity": self.default_severity,
            "severity_range": self.severity_range,
            "analyzer": SECURITY_ANALYZER_ID,
            "supported_languages": list(self.supported_languages),
            "supported_sinks": list(self.supported_sinks),
            "supported_sources": list(self.supported_sources),
            "coverage_notes": self.coverage_notes,
            "recommendation": self.recommendation,
            "documentation_ref": self.documentation_ref,
        }


SQL_INJECTION_SPEC = SecurityRuleSpec(
    rule_id="SEC-SQL-INJECTION",
    name="SQL Injection",
    subcategory="injection",
    description=(
        "Detects potential SQL injection where externally influenced or "
        "unresolved input reaches SQL statement construction passed to a "
        "recognized query execution API (cursor/connection execute family). "
        "Parameterized queries with static statement text are not reported. "
        "Findings are potential issues for review, not confirmed exploits."
    ),
    default_severity="High",
    severity_range="Medium to Critical",
    supported_languages=SECURITY_SUPPORTED_LANGUAGES,
    supported_sinks=(
        "cursor.execute / executemany / executescript (sqlite3, psycopg2/psycopg, "
        "asyncpg, pymysql/MySQLdb, cx_Oracle/oracledb, sqlalchemy, pyodbc receivers "
        "or database-handle receiver names)",
    ),
    supported_sources=(
        "sys.argv, input()/stdin, socket reads, request-derived values, "
        "locally propagated variables, function parameters (unresolved)",
    ),
    coverage_notes=(
        "Python only. Requires bounded source access around NCM call sites. "
        "Custom query wrappers, ORM-internal construction, and validation in "
        "other modules are not followed and stay unresolved."
    ),
    recommendation=(
        "Review whether any part of the statement can be influenced by "
        "untrusted input. Where it can, use parameterized queries or the "
        "query-construction facilities of the database library, and validate "
        "identifiers that cannot be parameterized against a fixed set."
    ),
)

COMMAND_INJECTION_SPEC = SecurityRuleSpec(
    rule_id="SEC-COMMAND-INJECTION",
    name="Command Injection",
    subcategory="injection",
    description=(
        "Detects potential command injection where externally influenced or "
        "unresolved input reaches operating-system command execution APIs "
        "(subprocess family, os.system/os.popen), especially with shell "
        "interpretation. Structured argument lists without a shell are treated "
        "as lower risk. Findings are potential issues, never executed."
    ),
    default_severity="High",
    severity_range="Medium to Critical",
    supported_languages=SECURITY_SUPPORTED_LANGUAGES,
    supported_sinks=("subprocess.run/call/Popen/check_call/check_output, os.system, os.popen",),
    supported_sources=(
        "sys.argv, input()/stdin, socket reads, request-derived values, "
        "locally propagated variables, function parameters (unresolved)",
    ),
    coverage_notes=(
        "Python only. Shell involvement is read from the bounded call text. "
        "Quoting/validation elsewhere and custom command helpers are not "
        "modeled and stay unresolved."
    ),
    recommendation=(
        "Review whether any part of the command can be influenced by untrusted "
        "input. Where it can, avoid shell invocation, pass arguments as a "
        "list, validate values against an allow-list, or use a library API "
        "instead of an external command."
    ),
)

PATH_TRAVERSAL_SPEC = SecurityRuleSpec(
    rule_id="SEC-PATH-TRAVERSAL",
    name="Path Traversal",
    subcategory="injection",
    description=(
        "Detects potential path traversal where externally influenced or "
        "unresolved path input reaches filesystem operations without visible "
        "evidence of canonicalization or containment validation. A dynamic "
        "path alone is not treated as sufficient for high confidence."
    ),
    default_severity="Medium",
    severity_range="Low to High",
    supported_languages=SECURITY_SUPPORTED_LANGUAGES,
    supported_sinks=(
        "open(), os.open/remove/unlink/rename/replace/rmdir/mkdir, "
        "pathlib read/write/open/unlink/rename operations, shutil "
        "copy/move/remove operations, archive extraction",
    ),
    supported_sources=(
        "request-derived filenames, sys.argv, input()/stdin, locally "
        "propagated path components, function parameters (unresolved)",
    ),
    coverage_notes=(
        "Python only. Validation is recognized only when visible in the local "
        "scope (resolve + containment check). Validation elsewhere is not "
        "visible and stays unresolved."
    ),
    recommendation=(
        "Review whether the path can be influenced by untrusted input. Where "
        "it can, resolve the final path and check that it stays within an "
        "intended base directory, and validate or generate filenames rather "
        "than accepting them directly."
    ),
)

SSRF_SPEC = SecurityRuleSpec(
    rule_id="SEC-SSRF",
    name="Server-Side Request Forgery",
    subcategory="injection",
    description=(
        "Detects potential SSRF where externally influenced or unresolved URL "
        "input reaches outbound HTTP/network request sinks. Fixed constant "
        "URLs are not reported; configurable URLs are reported at most at "
        "Info severity with Low confidence."
    ),
    default_severity="Medium",
    severity_range="Low to High",
    supported_languages=SECURITY_SUPPORTED_LANGUAGES,
    supported_sinks=(
        "requests get/post/put/delete/head/options/patch/request, httpx "
        "equivalents, urllib.request.urlopen/Request, http.client connections",
    ),
    supported_sources=(
        "request-derived URLs, sys.argv, input()/stdin, configuration values "
        "(configurable), locally propagated URLs, parameters (unresolved)",
    ),
    coverage_notes=(
        "Python only. Network topology, reachable destinations, and "
        "restrictions applied outside the visible scope are unknown. Requests "
        "are never sent."
    ),
    recommendation=(
        "Review whether the URL or its host can be influenced by untrusted "
        "input. Where it can, validate against an allow-list of permitted "
        "destinations and restrict schemes, redirects, and resolved addresses."
    ),
)

UNSAFE_DESERIALIZATION_SPEC = SecurityRuleSpec(
    rule_id="SEC-UNSAFE-DESERIALIZATION",
    name="Unsafe Deserialization",
    subcategory="injection",
    description=(
        "Detects potential unsafe deserialization where externally influenced, "
        "unresolved, or insufficiently trusted serialized data reaches a "
        "deserialization mechanism capable of arbitrary object construction "
        "(pickle/marshal families, shelve, unsafe YAML loaders). Data-only "
        "formats such as JSON and safe YAML loaders are never reported. "
        "Findings are potential issues for review, not confirmed exploits."
    ),
    default_severity="High",
    severity_range="Medium to Critical",
    supported_languages=SECURITY_SUPPORTED_LANGUAGES,
    supported_sinks=(
        "pickle.loads/load, marshal.loads/load, shelve.open, "
        "yaml.unsafe_load and yaml.load without a safe loader",
    ),
    supported_sources=(
        "sys.argv, input()/stdin, socket reads, request-derived values, "
        "locally propagated variables, function parameters (unresolved)",
    ),
    coverage_notes=(
        "Python only. Limited to the rule-set deserialization mechanisms; "
        "custom frameworks, integrity checks elsewhere, and caller-side "
        "validation stay unresolved. Requires bounded source access around "
        "NCM call sites."
    ),
    recommendation=(
        "Review where the serialized data originates. Where it may be "
        "untrusted, avoid object-capable pickle/marshal deserialization, "
        "prefer a data-only format such as JSON or a YAML loader limited to "
        "plain data, and verify integrity before deserializing data that "
        "must use a richer format."
    ),
)

DANGEROUS_DYNAMIC_EXECUTION_SPEC = SecurityRuleSpec(
    rule_id="SEC-DANGEROUS-DYNAMIC-EXECUTION",
    name="Dangerous Dynamic Execution",
    subcategory="injection",
    description=(
        "Detects potential dangerous dynamic execution where externally "
        "influenced or unresolved content reaches eval, exec, compile, or "
        "dynamic module loading. Static constant expressions are reported at "
        "most at Info severity; ast.literal_eval, SQL execution, and command "
        "execution belong to other rules and are never reported here. "
        "Detected code is never executed by the analyzer."
    ),
    default_severity="High",
    severity_range="Low to Critical",
    supported_languages=SECURITY_SUPPORTED_LANGUAGES,
    supported_sinks=("eval(), exec(), compile(), __import__() with a dynamic name",),
    supported_sources=(
        "sys.argv, input()/stdin, socket reads, request-derived values, "
        "locally propagated variables, function parameters (unresolved)",
    ),
    coverage_notes=(
        "Python only. Only builtin dynamic-execution calls are recognized; "
        "restricted-namespace evaluation elsewhere and custom loaders stay "
        "unresolved. Requires bounded source access around NCM call sites."
    ),
    recommendation=(
        "Review whether the executed content can be influenced by untrusted "
        "input. Where it can, replace dynamic execution with explicit parsing, "
        "allowlisted operations, structured data, safe APIs such as "
        "ast.literal_eval for literals, or predefined dispatch tables."
    ),
)

WEAK_CRYPTO_SPEC = SecurityRuleSpec(
    rule_id="SEC-WEAK-CRYPTO",
    name="Weak Cryptography",
    subcategory="cryptography",
    description=(
        "Detects clearly weak cryptographic primitives where the API usage "
        "itself provides strong evidence: MD5/SHA-1 hashing, DES/3DES/RC4 "
        "ciphers, ECB cipher mode, and non-cryptographic randomness used for "
        "secrets. Purpose context (password handling vs checksums) drives "
        "severity and confidence; comments, names, and string-only mentions "
        "are never reported."
    ),
    default_severity="Medium",
    severity_range="Info to High",
    supported_languages=SECURITY_SUPPORTED_LANGUAGES,
    supported_sinks=(
        "hashlib.md5/sha1/new('md5'/'sha1'), Crypto/Cryptodome MD5/SHA/DES/"
        "DES3/ARC4 constructors, ECB cipher mode, stdlib random for secrets",
    ),
    supported_sources=(
        "call arguments and surrounding purpose context (names, function "
        "purpose, usedforsecurity markers)",
    ),
    coverage_notes=(
        "Python only. Purpose is inferred from visible names and context only; "
        "ambiguous purpose lowers confidence and requires manual review. "
        "Key management, custom primitives, and runtime configuration are "
        "outside static reach."
    ),
    recommendation=(
        "Review the purpose of the primitive. For password hashing use a "
        "dedicated password-hashing algorithm such as Argon2id, bcrypt, or "
        "scrypt; for integrity/security hashing use SHA-256 or stronger "
        "modern constructions; for encryption use authenticated modern "
        "encryption schemes. Algorithm choice depends on purpose."
    ),
)

DISABLED_TLS_SPEC = SecurityRuleSpec(
    rule_id="SEC-DISABLED-TLS",
    name="Disabled or Weakened TLS Verification",
    subcategory="transport-security",
    description=(
        "Detects explicit TLS verification disabling in recognized Python "
        "HTTP-client and ssl APIs: verify=False, session.verify = False, "
        "unverified SSL contexts, CERT_NONE, disabled hostname checking, and "
        "obsolete protocol versions. Similarly named options in unrecognized "
        "APIs are never reported. Requests are never sent."
    ),
    default_severity="Medium",
    severity_range="Low to High",
    supported_languages=SECURITY_SUPPORTED_LANGUAGES,
    supported_sinks=(
        "requests/httpx/urllib3 verify=False, session.verify = False, "
        "ssl._create_unverified_context, CERT_NONE, check_hostname = False, "
        "obsolete ssl.PROTOCOL_* versions, aiohttp TCPConnector(ssl=False)",
    ),
    supported_sources=(
        "keyword arguments and attribute assignments in recognized APIs; "
        "configuration values that remain unresolved",
    ),
    coverage_notes=(
        "Python only. Only recognized APIs with known setting meanings are "
        "reported. Runtime configuration, deployment trust stores, and which "
        "endpoints the client contacts are unknown."
    ),
    recommendation=(
        "Review whether verification is disabled outside development or test "
        "contexts. Where it is, keep certificate verification enabled and, if "
        "a private certificate authority is needed, configure the trusted "
        "certificate bundle instead of disabling verification."
    ),
)

INSECURE_CORS_SPEC = SecurityRuleSpec(
    rule_id="SEC-INSECURE-CORS",
    name="Insecure CORS Configuration",
    subcategory="configuration",
    description=(
        "Detects clearly insecure CORS configuration: wildcard origins in "
        "FastAPI/Starlette CORSMiddleware or CORS response headers, "
        "especially combined with credential allowance. Explicit finite "
        "origin allowlists are never reported. A wildcard alone never exceeds "
        "Low severity; unresolved origin configuration stays unresolved."
    ),
    default_severity="Medium",
    severity_range="Info to High",
    supported_languages=SECURITY_SUPPORTED_LANGUAGES,
    supported_sinks=(
        "FastAPI/Starlette CORSMiddleware allow_origins, CORS response "
        "headers (Access-Control-Allow-Origin) assigned in code",
    ),
    supported_sources=(
        "allow_origins values, allow_credentials settings, header values, "
        "configuration values that remain unresolved",
    ),
    coverage_notes=(
        "Python only. Framework coverage is FastAPI/Starlette CORSMiddleware "
        "plus literal CORS response-header assignments. Proxy/gateway "
        "configuration and restrictions applied elsewhere stay unresolved."
    ),
    recommendation=(
        "Review which origins need access and whether the resources involved "
        "are sensitive or authenticated. Restrict to an explicit allow-list "
        "of trusted origins, avoid wildcard origins for sensitive APIs, and "
        "where credentials are involved restrict allowed methods and headers "
        "to those needed."
    ),
)


SECURITY_RULE_SPECS: tuple[SecurityRuleSpec, ...] = (
    SQL_INJECTION_SPEC,
    COMMAND_INJECTION_SPEC,
    PATH_TRAVERSAL_SPEC,
    SSRF_SPEC,
    UNSAFE_DESERIALIZATION_SPEC,
    DANGEROUS_DYNAMIC_EXECUTION_SPEC,
    WEAK_CRYPTO_SPEC,
    DISABLED_TLS_SPEC,
    INSECURE_CORS_SPEC,
)

SPEC_BY_RULE_ID: dict[str, SecurityRuleSpec] = {spec.rule_id: spec for spec in SECURITY_RULE_SPECS}
