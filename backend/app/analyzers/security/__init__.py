"""Security analysis domain (Phase 7): NCM in, evidence-based findings out."""

from app.analyzers.security.analyzer import (
    SECURITY_ANALYZER_VERSION,
    SecurityAnalyzer,
    build_security_rules,
)
from app.analyzers.security.coverage import (
    SUPPORTED_LANGUAGE,
    Coverage,
    CoverageStatus,
    ScopeSummary,
    coverage_for,
    summarize_scope,
)
from app.analyzers.security.evidence import (
    EVIDENCE_LINES_AFTER,
    EVIDENCE_LINES_BEFORE,
    EVIDENCE_MAX_EXCERPT_LINES,
    build_security_evidence,
)
from app.analyzers.security.metadata import (
    SECURITY_ANALYZER_ID,
    SECURITY_RULE_SPECS,
    SECURITY_SUPPORTED_LANGUAGES,
    SPEC_BY_RULE_ID,
    SecurityRuleSpec,
)

__all__ = [
    "SECURITY_ANALYZER_ID",
    "SECURITY_ANALYZER_VERSION",
    "SECURITY_RULE_SPECS",
    "SECURITY_SUPPORTED_LANGUAGES",
    "SPEC_BY_RULE_ID",
    "SUPPORTED_LANGUAGE",
    "Coverage",
    "CoverageStatus",
    "EVIDENCE_LINES_AFTER",
    "EVIDENCE_LINES_BEFORE",
    "EVIDENCE_MAX_EXCERPT_LINES",
    "ScopeSummary",
    "SecurityAnalyzer",
    "SecurityRuleSpec",
    "build_security_rules",
    "build_security_evidence",
    "coverage_for",
    "summarize_scope",
]
