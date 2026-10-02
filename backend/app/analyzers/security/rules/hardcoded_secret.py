"""SEC-HARDCODED-SECRET: hardcoded secrets via repository-wide scanning (TASK-108).

Scans every eligible repository text file (any extension: source,
.env-style files, JSON, YAML, TOML, other configs, Docker/CI config,
docs text) for credential-shaped content: recognized token formats
(AWS-style keys, bearer tokens), private key material, credentials in
connection strings, and secret-like assignments. Binary files are never
scanned; unreadable, oversize, and .git content is excluded with
recorded reasons; placeholders, test markers, and environment references
are never reported.

Detected values are masked before evidence is built, so no plaintext
secret ever reaches persistence, serialization, reports, or logs. Only
categories, names, and length classes travel outward. Findings report
potentially exposed secrets, never confirmed credentials, and nothing
here contacts an external service or executes repository content.
"""

from __future__ import annotations

import dataclasses
import re

from app.analyzers.context import AnalysisContext
from app.analyzers.findings import Confidence, Finding, Limitation, Severity
from app.analyzers.rules import RuleExecutionContext, RuleOutcome
from app.analyzers.security.common import (
    EvaluatedSink,
    adjust_for_partial,
    dedupe_findings,
    make_location_finding,
    summarize_scope,
)
from app.analyzers.security.coverage import Coverage, CoverageStatus
from app.analyzers.security.metadata import HARDCODED_SECRET_SPEC
from app.analyzers.security.source import (
    SourceProvider,
    strip_structural_comment,
    structure_mask,
)
from app.ncm import SourceLocation

SPEC = HARDCODED_SECRET_SPEC

#: Extensions never scanned as text (binary content, never source).
_BINARY_EXTENSIONS = frozenset(
    {
        ".png",
        ".jpg",
        ".jpeg",
        ".gif",
        ".bmp",
        ".ico",
        ".webp",
        ".tiff",
        ".ttf",
        ".otf",
        ".woff",
        ".woff2",
        ".eot",
        ".exe",
        ".dll",
        ".so",
        ".dylib",
        ".a",
        ".lib",
        ".o",
        ".obj",
        ".class",
        ".pyc",
        ".pyo",
        ".jar",
        ".war",
        ".zip",
        ".tar",
        ".gz",
        ".bz2",
        ".xz",
        ".7z",
        ".rar",
        ".mp3",
        ".mp4",
        ".avi",
        ".mov",
        ".mkv",
        ".wav",
        ".flac",
        ".pdf",
        ".sqlite",
        ".db",
    }
)
_BINARY_NAMES = frozenset({".DS_Store", "Thumbs.db"})

#: Secret-like assignment names (word boundaries applied by the matcher).
_SECRET_NAME_ALTS = (
    "passwords?",
    "passwd",
    "pwd",
    "secrets?",
    "tokens?",
    "api[_-]?keys?",
    "apikeys?",
    "api[_-]?tokens?",
    "api(?:_[a-z0-9]+)+_keys?",
    "access_tokens?",
    "refresh_tokens?",
    "auth_tokens?",
    "session_tokens?",
    "client_secrets?",
    "private_keys?",
    "credentials?",
    "aws_secrets?",
    "db_passwords?",
    "db_pass",
    "secret_keys?",
)

#: Secret-like name with a compound-name-tolerant left boundary, so
#: BACKUP_API_KEY and MY_PASSWORD match while TOKENIZER stays silent.
_NAME_SEP_RE = re.compile(
    r"(?i)(?:^|(?<=[\W_]))(?:" + "|".join(_SECRET_NAME_ALTS) + r")\b\s*([:=])"
)

#: Trailing name parts that mark measurement/presence metadata, never secrets.
_MEASUREMENT_SUFFIX_RE = re.compile(
    r"_(count|length|len|size|present|exists|valid|verified|checked|masked|redacted|hash)$",
    re.IGNORECASE,
)

#: Whole-value placeholders and template markers (never reported).
_PLACEHOLDER_FULL_RE = re.compile(
    r"^(?:<.*>|\$\{.+\}|\$[A-Za-z_]+|(.)\1+|x+|0+|1+|-+|\*+|\.+|n/a|na|tbd)$",
    re.IGNORECASE,
)

#: Separator-stripped placeholder spellings (``CHANGE_ME`` ∼ ``changeme``).
_PLACEHOLDER_COMPACT = frozenset({"changeme", "yourkey", "yourtoken"})

#: Placeholder words matched per underscore/dash/dot/space-separated token.
_PLACEHOLDER_TOKEN_RE = re.compile(
    r"fake|example|sample|dummy|placeholder|changeme|change[_-]?me|your[_-]?|todo|lorem",
    re.IGNORECASE,
)

#: Environment/config references (values supplied at runtime, not hardcoded).
_ENV_REF_RE = re.compile(
    r"getenv|environ|process\.env|config\.|settings\.|input\s*\(|os\.",
    re.IGNORECASE,
)

_AWS_KEY_RE = re.compile(r"\b(AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b")
_BEARER_RE = re.compile(r"\bBearer\s+([A-Za-z0-9\-._~+/=]{16,})")
_PRIVATE_KEY_RE = re.compile(
    r"-----\s*BEGIN\s+(?:RSA\s+|EC\s+|DSA\s+|OPENSSH\s+)?PRIVATE\s+KEY\s*-----"
)
_PRIVATE_KEY_END_RE = re.compile(
    r"-----\s*END\s+(?:RSA\s+|EC\s+|DSA\s+|OPENSSH\s+)?PRIVATE\s+KEY\s*-----"
)
_BASE64_BODY_RE = re.compile(r"^[A-Za-z0-9+/=\s]{16,}$")
_URL_CREDS_RE = re.compile(r"(?i)([a-zA-Z][a-zA-Z0-9+.-]*://)([^/\s]*?):([^@/\s]{4,})@")

#: Paths that downgrade confidence one level (still reported, never silent).
_TEST_PATH_RE = re.compile(
    r"(^|/)(tests?|testing|fixtures?|examples?|docs?|tutorials?)(/|$)|test_|_test\.|example",
    re.IGNORECASE,
)

#: Cap on listed paths inside the non-Python summary limitation.
_SUMMARY_PATH_CAP = 10


def secret_entry_scannable(path: str, language: str | None) -> bool:
    """NCM-only eligibility: scannable unless .git or a binary shape."""
    _ = language
    normalized = path.replace("\\", "/")
    if normalized == ".git" or normalized.startswith(".git/"):
        return False
    basename = normalized.rpartition("/")[2]
    if basename in _BINARY_NAMES:
        return False
    lowered = normalized.lower()
    for extension in _BINARY_EXTENSIONS:
        if lowered.endswith(extension):
            return False
    return True


#: Extensions parsed as code: assignments inside string literals are data,
#: not assignments (docstring interiors are skipped separately).
_CODE_EXTENSIONS = frozenset(
    {
        ".py",
        ".pyi",
        ".pyw",
        ".js",
        ".jsx",
        ".ts",
        ".tsx",
        ".java",
        ".go",
        ".rb",
        ".php",
        ".c",
        ".cc",
        ".cpp",
        ".h",
        ".hpp",
        ".cs",
        ".swift",
        ".kt",
        ".rs",
        ".sh",
        ".bash",
        ".ps1",
        ".pl",
        ".pm",
        ".lua",
    }
)


def _is_code_file(path: str) -> bool:
    lowered = path.replace("\\", "/").lower()
    return any(lowered.endswith(extension) for extension in _CODE_EXTENSIONS)


def _docstring_interior(lines: list[str]) -> set[int]:
    """1-based lines inside multiline triple-quoted strings (code files).

    Crude toggle over triple-quote occurrences: single-line pairs cancel
    out, so only genuinely multiline regions are skipped. Documented
    heuristic; documentation examples are a known false-positive source.
    """
    interior: set[int] = set()
    inside = False
    for idx, line in enumerate(lines, start=1):
        opens = line.count("'''") + line.count('"""')
        if inside:
            interior.add(idx)
        elif opens % 2 == 1:
            positions = [p for p in (line.find("'''"), line.find('"""')) if p != -1]
            if positions and line[min(positions) + 3 :].strip():
                interior.add(idx)
        if opens % 2 == 1:
            inside = not inside
    return interior


def _is_test_path(path: str) -> bool:
    return bool(_TEST_PATH_RE.search(path.replace("\\", "/")))


def _length_class(length: int) -> str:
    if length < 12:
        return "short (<12)"
    if length < 32:
        return "medium (12-31)"
    return "long (>=32)"


def _shape_strength(value: str) -> str:
    """Strong credential shape vs weak (short/low-entropy) shape."""
    if len(value) >= 16:
        return "strong"
    classes = sum(
        (
            any(c.islower() for c in value),
            any(c.isupper() for c in value),
            any(c.isdigit() for c in value),
            any(not c.isalnum() for c in value),
        )
    )
    if len(value) >= 12 and classes >= 3:
        return "strong"
    if len(value) >= 10 and classes >= 4:
        return "strong"
    return "weak"


def _value_excluded(value: str) -> bool:
    """Placeholders, env refs, code, and non-values (never reported)."""
    if not value or len(value) < 4:
        return True
    if "(" in value or value != value.strip():
        return True
    if value.lower() in ("true", "false", "none", "null", "nil", "0"):
        return True
    if _PLACEHOLDER_FULL_RE.match(value):
        return True
    if re.sub(r"[_\-. ]+", "", value).lower() in _PLACEHOLDER_COMPACT:
        return True
    if _ENV_REF_RE.search(value):
        return True
    tokens = re.split(r"[_.\- /]+", value)
    if any(_PLACEHOLDER_TOKEN_RE.fullmatch(token or " ") for token in tokens):
        return True
    if _PLACEHOLDER_TOKEN_RE.search(value) and (
        value.lower().startswith("test") or value.lower().endswith("test")
    ):
        return True
    return False


def _downgrade(confidence: Confidence, path: str) -> Confidence:
    """Test/example paths report one confidence level lower (never silent)."""
    if not _is_test_path(path):
        return confidence
    if confidence is Confidence.HIGH:
        return Confidence.MEDIUM
    return Confidence.LOW


class _SecretHit:
    """One detected secret occurrence with its mask span and verdict inputs."""

    __slots__ = (
        "lineno",
        "start",
        "end",
        "category",
        "name",
        "severity",
        "confidence",
        "descriptor",
    )

    def __init__(
        self,
        lineno: int,
        start: int,
        end: int,
        category: str,
        name: str,
        severity: Severity,
        confidence: Confidence,
        descriptor: str,
    ) -> None:
        self.lineno = lineno
        self.start = start
        self.end = end
        self.category = category
        self.name = name
        self.severity = severity
        self.confidence = confidence
        self.descriptor = descriptor


def _priority(hit: _SecretHit) -> int:
    order = {
        "private-key": 0,
        "cloud-credential": 1,
        "bearer-token": 2,
        "url-credential": 3,
        "assignment": 4,
    }
    return order.get(hit.category, 5)


def _overlaps(first: _SecretHit, second: _SecretHit) -> bool:
    return first.lineno == second.lineno and first.start < second.end and second.start < first.end


def _dedupe_overlaps(hits: list[_SecretHit]) -> list[_SecretHit]:
    """Drop generic hits overlapped by a more specific detector."""
    kept: list[_SecretHit] = []
    for hit in sorted(hits, key=lambda h: (_priority(h), h.lineno, h.start)):
        if any(_overlaps(hit, other) for other in kept):
            continue
        kept.append(hit)
    return sorted(kept, key=lambda h: (h.lineno, h.start))


def _extract_value(line: str, pos: int) -> tuple[str, int, int] | None:
    """Value after a name separator: quoted or bare token with its span.

    Bare (unquoted) values must be plain tokens: anything containing
    attribute access, subscripts, or calls is code, not a hardcoded value.
    """
    rest = line[pos:].lstrip()
    offset = pos + (len(line[pos:]) - len(rest))
    if not rest:
        return None
    if rest[0] in ("'", '"'):
        quote = rest[0]
        if rest[:3] in ("'''", '"""'):
            closing = rest.find(rest[:3], 3)
            if closing == -1:
                return None
            return rest[3:closing], offset + 3, offset + 3 + closing - 3
        closing = rest.find(quote, 1)
        if closing == -1:
            return None
        return rest[1:closing], offset + 1, offset + 1 + closing
    match = re.match(r"[^\s,}#;]+", rest)
    if match is None:
        return None
    token = match.group(0).rstrip(",;")
    if any(char in token for char in ".[({}"):
        return None
    return token, offset, offset + len(token)


#: Template markers showing a value slot, not a literal secret.
_TEMPLATE_MARKER_RE = re.compile(r"\{|\}|%s|%d|%\(")


def _in_string_span(masked: str, raw: str, pos: int) -> bool:
    """True when a raw offset sits inside a string literal (masked blank)."""
    return 0 <= pos < len(masked) and masked[pos] == " " and raw[pos] != " "


def _scan_line(
    line: str, lineno: int, path: str, is_code: bool, in_docstring: bool
) -> list[_SecretHit]:
    """Detector pass over one line (values only; names alone never fire).

    In code files the line is comment-stripped first and assignment names
    inside string literals are ignored (they are data, not assignments).
    Assignment detection additionally skips docstring interiors (prose
    documentation), while format-based detectors (private keys, cloud
    keys, bearer tokens, URL credentials) still apply there: embedded key
    material keeps its High-confidence shape wherever it appears.
    """
    work = strip_structural_comment(line) if is_code else line
    masked = structure_mask(work) if is_code else work
    hits: list[_SecretHit] = []
    marker = _PRIVATE_KEY_RE.search(work)
    if marker:
        hits.append(
            _SecretHit(
                lineno,
                marker.start(),
                marker.end(),
                "private-key",
                "private-key",
                Severity.CRITICAL,
                _downgrade(Confidence.HIGH, path),
                "private key block marker; body masked",
            )
        )
    for match in _AWS_KEY_RE.finditer(work):
        if match.group(0) == "AKIAIOSFODNN7EXAMPLE":
            # The documented AWS example key: a sample value, not a secret.
            continue
        hits.append(
            _SecretHit(
                lineno,
                match.start(),
                match.end(),
                "cloud-credential",
                match.group(0)[:4],
                Severity.HIGH,
                _downgrade(Confidence.HIGH, path),
                f"AWS-style access key ID ({match.group(0)[:4]} prefix retained), "
                f"length class {_length_class(len(match.group(0)))}",
            )
        )
    for match in _BEARER_RE.finditer(work):
        token = match.group(1)
        if _value_excluded(token):
            continue
        confidence = Confidence.HIGH if len(token) >= 20 else Confidence.MEDIUM
        hits.append(
            _SecretHit(
                lineno,
                match.start(1),
                match.end(1),
                "bearer-token",
                "bearer",
                Severity.HIGH,
                _downgrade(confidence, path),
                f"bearer token, length class {_length_class(len(token))}",
            )
        )
    for match in _URL_CREDS_RE.finditer(work):
        password = match.group(3)
        if _value_excluded(password):
            continue
        hits.append(
            _SecretHit(
                lineno,
                match.start(3),
                match.end(3),
                "url-credential",
                "url-password",
                Severity.HIGH,
                _downgrade(Confidence.MEDIUM, path),
                "credential embedded in connection string/URL",
            )
        )
    for match in _NAME_SEP_RE.finditer(work):
        if in_docstring:
            continue
        in_string = is_code and _in_string_span(masked, work, match.start())
        name = match.group(0).strip().rstrip(":=").strip().strip("\"'").lower()
        if _MEASUREMENT_SUFFIX_RE.search(name):
            continue
        extracted = _extract_value(work, match.end())
        if extracted is None:
            continue
        value, start, end = extracted
        if _value_excluded(value):
            continue
        if in_string and (_shape_strength(value) != "strong" or _TEMPLATE_MARKER_RE.search(value)):
            # Inside a string literal in code (format strings, messages):
            # only a strong template-free literal counts as embedded.
            continue
        strength = _shape_strength(value)
        confidence = Confidence.MEDIUM if strength == "strong" else Confidence.LOW
        hits.append(
            _SecretHit(
                lineno,
                start,
                end,
                "assignment",
                name,
                Severity.HIGH,
                _downgrade(confidence, path),
                f"credential-shaped value assigned to `{name}`, "
                f"length class {_length_class(len(value))}",
            )
        )
    return _dedupe_overlaps(hits)


def _private_key_body_spans(lines: list[str], lineno: int) -> list[tuple[int, int, int]]:
    """Mask spans for base64 body lines following a private-key marker."""
    spans: list[tuple[int, int, int]] = []
    for offset in range(1, 64):
        idx = lineno - 1 + offset
        if idx < 0 or idx >= len(lines):
            break
        text = lines[idx]
        if _PRIVATE_KEY_END_RE.search(text):
            spans.append((idx + 1, 0, len(text)))
            break
        if _BASE64_BODY_RE.match(text.strip()):
            spans.append((idx + 1, 0, len(text)))
            continue
        if not text.strip():
            continue
        break
    return spans


def _masked_lines(
    lines: list[str], hits: list[_SecretHit], extra: list[tuple[int, int, int]]
) -> tuple[list[str], bool]:
    """Copy of lines with every detected secret value replaced by ***."""
    masked_any = False
    masked = list(lines)
    by_line: dict[int, list[tuple[int, int]]] = {}
    for hit in hits:
        by_line.setdefault(hit.lineno, []).append((hit.start, hit.end))
    for lineno, start, end in extra:
        by_line.setdefault(lineno, []).append((start, end))
    for lineno, spans in by_line.items():
        if lineno < 1 or lineno > len(masked):
            continue
        text = masked[lineno - 1]
        for start, end in sorted(spans, reverse=True):
            text = text[:start] + "***" + text[end:]
            masked_any = True
        masked[lineno - 1] = text
    return masked, masked_any


def _hit_finding(
    *,
    context: AnalysisContext,
    hit: _SecretHit,
    path: str,
    lines: list[str],
    masked_any: bool,
    partial: bool,
) -> Finding:
    """Build one secret finding (identity/descriptions carry no values)."""
    location = SourceLocation(
        file_path=path,
        start_line=hit.lineno,
        start_column=hit.start,
        end_line=hit.lineno,
        end_column=hit.end,
    )
    verdict = EvaluatedSink(
        severity=hit.severity,
        confidence=adjust_for_partial(hit.confidence, partial),
        title="Potential hardcoded secret",
        description=(
            f"Potential hardcoded secret: {hit.category} ({hit.descriptor}) "
            f"associated with `{hit.name}`. The value itself is masked and "
            "never included here. This pattern deserves security review; it "
            "is not a confirmed or active credential."
        ),
        subject_key=f"{hit.category}:{hit.name}:{hit.lineno}",
        severity_factors=(f"secret category: {hit.category}",),
        confidence_factors=(f"secret category: {hit.category}",),
        impact=(
            "If the value is a real credential, anyone with repository "
            "access could use it, and the repository history may keep it "
            "available even after removal."
        ),
    )
    finding = make_location_finding(
        spec=SPEC,
        analyzer_version=context.analyzer_version,
        rule_set_version=context.rule_set_version,
        analysis_id=context.analysis_id,
        location=location,
        lines=lines,
        verdict=verdict,
        partial=partial,
    )
    if masked_any and finding.evidence is not None and not finding.evidence.redacted:
        finding = dataclasses.replace(
            finding,
            evidence=dataclasses.replace(finding.evidence, redacted=True),
        )
    return finding


def _scan_file(
    *,
    context: AnalysisContext,
    path: str,
    lines: list[str],
    partial: bool,
) -> list[Finding]:
    """Scan one file's lines into findings (values pre-masked for evidence)."""
    is_code = _is_code_file(path)
    interior = _docstring_interior(lines) if is_code else set()
    hits: list[_SecretHit] = []
    for lineno, line in enumerate(lines, start=1):
        hits.extend(_scan_line(line, lineno, path, is_code, lineno in interior))
    extra: list[tuple[int, int, int]] = []
    for hit in hits:
        if hit.category == "private-key":
            extra.extend(_private_key_body_spans(lines, hit.lineno))
    masked, _ = _masked_lines(lines, hits, extra)
    return [
        _hit_finding(
            context=context, hit=hit, path=path, lines=masked, masked_any=True, partial=partial
        )
        for hit in hits
    ]


def execute_hardcoded_secret(
    execution_context: RuleExecutionContext, source: SourceProvider | None
) -> tuple[RuleOutcome, Coverage]:
    """Rule entry point (returns outcome plus explicit coverage)."""
    context = execution_context.context
    scope = summarize_scope(context.ncm)
    limitations: list[Limitation] = []
    for failed in scope.failed_python_files:
        limitations.append(
            Limitation(
                scope=f"security:{SPEC.rule_id}",
                reason="A Python file failed to parse; it is still content-scanned "
                "for secrets when readable, and never treated as clean.",
                path=failed,
                rule_id=SPEC.rule_id,
            )
        )
    entries = sorted(context.ncm.files, key=lambda item: item.path)
    if not entries:
        coverage = Coverage(
            rule_id=SPEC.rule_id,
            status=CoverageStatus.UNSUPPORTED,
            reason="No repository files in scope; the rule did not run.",
        )
        return RuleOutcome(findings=[], limitations=limitations), coverage
    findings: list[Finding] = []
    scanned = 0
    unevaluated = False
    non_python_scanned: list[str] = []
    for entry in entries:
        if not secret_entry_scannable(entry.path, entry.language):
            if entry.path == ".git" or entry.path.replace("\\", "/").startswith(".git/"):
                limitations.append(
                    Limitation(
                        scope=f"security:{SPEC.rule_id}",
                        reason="Excluded from secret scanning: version-control metadata.",
                        path=entry.path,
                        rule_id=SPEC.rule_id,
                    )
                )
            else:
                limitations.append(
                    Limitation(
                        scope=f"security:{SPEC.rule_id}",
                        reason="Excluded from secret scanning: binary content.",
                        path=entry.path,
                        rule_id=SPEC.rule_id,
                    )
                )
            continue
        source_file = source.read(entry.path) if source is not None else None
        if source_file is None:
            unevaluated = True
            limitations.append(
                Limitation(
                    scope=f"security:{SPEC.rule_id}",
                    reason="Not scanned for secrets: unreadable as text or exceeds "
                    "the size limit; not treated as clean.",
                    path=entry.path,
                    rule_id=SPEC.rule_id,
                )
            )
            continue
        text_lines = list(source_file.lines)
        if any("\x00" in line for line in text_lines):
            limitations.append(
                Limitation(
                    scope=f"security:{SPEC.rule_id}",
                    reason="Excluded from secret scanning: binary content.",
                    path=entry.path,
                    rule_id=SPEC.rule_id,
                )
            )
            continue
        scanned += 1
        is_python = (entry.language or "").lower() == "python" and entry.module is not None
        if not is_python:
            non_python_scanned.append(entry.path)
        partial = False
        if entry.module is not None:
            partial = entry.module.completeness != "fully"
        findings.extend(
            _scan_file(context=context, path=entry.path, lines=text_lines, partial=partial)
        )
    if non_python_scanned:
        shown = sorted(non_python_scanned)[:_SUMMARY_PATH_CAP]
        suffix = ""
        if len(non_python_scanned) > _SUMMARY_PATH_CAP:
            suffix = f" and {len(non_python_scanned) - _SUMMARY_PATH_CAP} more"
        limitations.append(
            Limitation(
                scope=f"security:{SPEC.rule_id}",
                reason="Non-Python text files scanned for SEC-HARDCODED-SECRET "
                f"only ({len(non_python_scanned)} files: {', '.join(shown)}{suffix}); "
                "not analyzed for any other rule.",
                rule_id=SPEC.rule_id,
            )
        )
    if unevaluated or scope.is_degraded:
        coverage = Coverage(
            rule_id=SPEC.rule_id,
            status=CoverageStatus.PARTIALLY_COVERED,
            reason=(
                "Some files could not be scanned or the representation is "
                "degraded; unscanned content is not treated as clean."
            ),
        )
    elif scanned > 0:
        coverage = Coverage(
            rule_id=SPEC.rule_id,
            status=CoverageStatus.COVERED,
            reason="Eligible repository text files were content-scanned for secrets.",
        )
    else:
        coverage = Coverage(
            rule_id=SPEC.rule_id,
            status=CoverageStatus.NOT_APPLICABLE,
            reason=(
                "No eligible text files were encountered; this does not mean "
                "the repository is free of secrets."
            ),
        )
        limitations.append(
            Limitation(
                scope=f"security:{SPEC.rule_id}",
                reason=coverage.reason,
                rule_id=SPEC.rule_id,
            )
        )
    return RuleOutcome(findings=dedupe_findings(findings), limitations=limitations), coverage
