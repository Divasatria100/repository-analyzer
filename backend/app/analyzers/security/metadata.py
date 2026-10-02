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

SECURITY_RULE_SPECS: tuple[SecurityRuleSpec, ...] = (
    SQL_INJECTION_SPEC,
    COMMAND_INJECTION_SPEC,
    PATH_TRAVERSAL_SPEC,
    SSRF_SPEC,
)

SPEC_BY_RULE_ID: dict[str, SecurityRuleSpec] = {spec.rule_id: spec for spec in SECURITY_RULE_SPECS}
