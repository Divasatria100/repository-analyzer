"""SEC-POTENTIAL-AUTHORIZATION: potential missing authorization (TASK-107).

Points reviewers to route handlers that perform resource-sensitive
operations without a recognizable authorization or ownership check in
the analyzed flow, using framework-independent signals only. Every
finding states that manual review is required and never concludes that
authorization is broken. Confidence is never High. Public endpoints and
handlers without resource operations are never reported.
"""

from __future__ import annotations

import re

from app.analyzers.findings import Confidence, Finding, Limitation, Severity
from app.analyzers.rules import RuleExecutionContext, RuleOutcome
from app.analyzers.security.common import (
    EvaluatedSink,
    adjust_for_partial,
    base_limitations,
    dedupe_findings,
    function_parameters,
    make_location_finding,
)
from app.analyzers.security.coverage import Coverage, CoverageStatus, coverage_for, summarize_scope
from app.analyzers.security.flow import Origin, analyze_expression, build_assignment_map
from app.analyzers.security.metadata import POTENTIAL_AUTHORIZATION_SPEC
from app.analyzers.security.source import SourceFile, SourceProvider, mask_strings
from app.ncm import FunctionDef, NormalizedModule, SourceLocation

SPEC = POTENTIAL_AUTHORIZATION_SPEC

#: Route-registration decorator calls: @<recv>.<method>("<path>", ...).
_ROUTE_METHODS = ("get", "post", "put", "delete", "patch", "options", "head", "route", "api_route")
_ROUTE_DECO_RE = re.compile(
    r"""@\s*(?:[A-Za-z_][A-Za-z0-9_]*\.)*("""
    + "|".join(_ROUTE_METHODS)
    + r""")\s*\(\s*["'](/[^"']*)["']"""
)

#: Bare decorator names treated as route signals (any receiver).
_ROUTE_BARE_ATTRS = frozenset(_ROUTE_METHODS)

#: Receivers whose bare decorator may register a route.
_ROUTE_RECEIVERS = frozenset({"app", "router", "api", "blueprint", "bp", "routes", "view", "views"})

#: Route-registration calls visible as NCM call sites.
_ROUTE_CALL_ATTRS = frozenset({"add_url_rule", "add_api_route"})

#: Paths that are public by convention (never authorization findings).
_PUBLIC_PATH_RE = re.compile(
    r"^/(health|healthy|healthz|ready|live|liveness|readiness|public|about|status|"
    r"ping|version|docs|openapi\.json|redoc|static|favicon\.ico|robots\.txt)?/?$",
    re.IGNORECASE,
)
_PUBLIC_FUNC_RE = re.compile(
    r"^(health|healthcheck|healthy|public|public_page|about|status|ping|version|docs|"
    r"openapi|root|index|home|landing)_?.*$",
    re.IGNORECASE,
)

#: Calls/conditions/guards whose name or structure indicates authorization.
_AUTH_CALL_RE = re.compile(
    r"\b(check_permission|require_roles?|require_admin|require_auth|require_permission|authorize|"
    r"verify_permission|has_permission|ensure_admin|login_required|permission_required|"
    r"admin_required|role_required|jwt_required|auth_required|get_current_user|"
    r"require_login|requires_auth|deny_unless)\b",
    re.IGNORECASE,
)
_AUTH_COND_RE = re.compile(
    r"\b(is_admin|is_authenticated|is_superuser|is_staff|current_user|authenticated)\b"
    r"|raise\s+[A-Za-z_.]*(Forbidden|Unauthorized|PermissionDenied|NotAuthenticated)"
    r"|abort\s*\(\s*40[13]",
)
_AUTH_DEPENDS_RE = re.compile(
    r"Depends\s*\([^)]*\b(admin|auth|permission|role|user|scope)\w*\b", re.IGNORECASE
)
_AUTH_DECORATOR_RE = re.compile(
    r"(login_required|permission_required|admin_required|role_required|jwt_required|"
    r"auth_required|require_auth|requires_auth|authorize)",
    re.IGNORECASE,
)

#: Resource-modifying call attributes (any receiver).
_WRITE_OP_RE = re.compile(
    r"\.(delete|remove|update|save|create|insert|drop|destroy|write|unlink|rename|"
    r"write_text|write_bytes|execute|executemany)\s*\("
)

#: Resource-lookup call attributes (need an identifier argument to count).
_LOOKUP_OP_RE = re.compile(
    r"\.(query|filter|get|find|first|one|all|objects|fetch|select)\s*\(" r"|\bopen\s*\("
)

#: Entity names for bare helper calls (``get_user(x)``, ``delete_user(x)``).
_ENTITY_NAMES = (
    "user",
    "users",
    "account",
    "accounts",
    "customer",
    "customers",
    "patient",
    "patients",
    "member",
    "members",
    "employee",
    "employees",
    "profile",
    "profiles",
    "order",
    "orders",
    "payment",
    "payments",
    "record",
    "records",
    "item",
    "items",
    "object",
    "objects",
    "data",
)
_BARE_READ_HELPER_RE = re.compile(
    r"^(get|fetch|load|find|lookup|retrieve|read)_(" + "|".join(_ENTITY_NAMES) + r")$",
    re.IGNORECASE,
)
_BARE_WRITE_HELPER_RE = re.compile(
    r"^(delete|remove|update|create|destroy)_(" + "|".join(_ENTITY_NAMES) + r")$",
    re.IGNORECASE,
)

#: Lines above a `def` scanned for route decorators (bounded).
_ROUTE_SCANBACK_LINES = 6


def module_has_route_indicators(module: NormalizedModule) -> bool:
    """NCM-only pre-check: any bare route decorator or registration call."""
    for func in module.functions:
        if _has_bare_route(func):
            return True
    for call in module.calls:
        if call.callee_text.rpartition(".")[2] in _ROUTE_CALL_ATTRS:
            return True
    return False


def _has_bare_route(func: FunctionDef) -> bool:
    """Bare decorator route signal on one NCM function."""
    for name in func.decorator_names:
        attr = name.rpartition(".")[2].lower()
        receiver = name.rpartition(".")[0].rpartition(".")[2].lower()
        if attr in _ROUTE_BARE_ATTRS and (not receiver or receiver in _ROUTE_RECEIVERS):
            return True
    return False


def _route_above(lines: list[str], def_line: int) -> tuple[str, str] | None:
    """Find a route decorator call in bounded lines above a `def` line.

    Single-line decorators match directly. A decorator whose argument list
    spans lines is joined downward (bounded) before matching, so the path
    literal is still found.
    """
    start = max(0, def_line - 1 - _ROUTE_SCANBACK_LINES)
    for lineno in range(def_line - 1, start, -1):
        line = lines[lineno - 1] if 1 <= lineno <= len(lines) else ""
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped.startswith("@"):
            match = _ROUTE_DECO_RE.search(stripped)
            if match:
                return match.group(2), stripped
            if "(" not in stripped:
                return None
            joined = _join_decorator_block(lines, lineno)
            match = _ROUTE_DECO_RE.search(joined)
            if match:
                return match.group(2), joined
            return None
        if re.match(r"(async\s+)?def\s", stripped) or re.match(r"class\s", stripped):
            return None
    return None


def _join_decorator_block(lines: list[str], first_line: int) -> str:
    """Join a multiline decorator call downward until parens balance (bounded)."""
    parts: list[str] = []
    depth = 0
    for offset in range(_ROUTE_SCANBACK_LINES):
        index = first_line - 1 + offset
        if index < 0 or index >= len(lines):
            break
        raw = lines[index]
        parts.append(raw.strip())
        for char in raw:
            if char in "([":
                depth += 1
            elif char in ")]":
                depth -= 1
        if depth <= 0 and offset > 0:
            break
        if re.match(r"(async\s+)?def\s", raw.strip()) or re.match(r"class\s", raw.strip()):
            break
    return " ".join(parts)


def _auth_signals(masked_scope: str, decorator_names: tuple[str, ...]) -> tuple[str, ...]:
    """Recognizable authorization signals visible in handler scope."""
    found: list[str] = []
    for match in _AUTH_CALL_RE.finditer(masked_scope):
        found.append(f"authorization call `{match.group(1)}`")
    for match in _AUTH_COND_RE.finditer(masked_scope):
        found.append(f"authorization guard `{match.group(0)[:48]}`")
    for _match in _AUTH_DEPENDS_RE.finditer(masked_scope):
        found.append("authorization dependency")
    for name in decorator_names:
        if _AUTH_DECORATOR_RE.search(name):
            found.append(f"authorization decorator `{name}`")
    return tuple(dict.fromkeys(found))


def _is_public(route_path: str, func_name: str) -> bool:
    base = func_name.rpartition(".")[2]
    return bool(_PUBLIC_PATH_RE.match(route_path)) or bool(_PUBLIC_FUNC_RE.match(base))


def _call_argument_identifiers(call_text: str) -> list[str]:
    """Identifiers inside call arguments, minus the leading receiver chain."""
    open_index = call_text.find("(")
    receiver_idents: set[str] = set()
    if open_index != -1:
        receiver_idents = set(re.findall(r"[A-Za-z_][A-Za-z0-9_]*", call_text[:open_index]))
    args_text = call_text[open_index:] if open_index != -1 else call_text
    info = analyze_expression(args_text)
    return [name for name in info.identifiers if name not in receiver_idents]


def _call_text_slice(lines: list[str], location: SourceLocation) -> str:
    """Exact NCM span text for one call (bounded to ten lines).

    Parenthesis balancing starts at the chain head for chained calls
    (``get_session().query(...).delete()``), truncating before the outer
    operation; the recorded span covers the whole chain instead.
    """
    start_line, start_col = location.start_line, location.start_column
    end_line, end_col = location.end_line, location.end_column
    if start_line < 1 or end_line < start_line or start_line > len(lines):
        return ""
    end_line = min(end_line, start_line + 9, len(lines))
    if start_line == end_line:
        row = lines[start_line - 1]
        return row[start_col : min(end_col, len(row))]
    parts = [lines[start_line - 1][start_col:]]
    for lineno in range(start_line + 1, end_line):
        parts.append(lines[lineno - 1])
    parts.append(lines[end_line - 1][: min(end_col, len(lines[end_line - 1]))])
    return "\n".join(parts)


#: Attribute calls inside one expression, outermost last.
_OP_ATTR_RE = re.compile(r"\.([A-Za-z_][A-Za-z0-9_]*)\s*\(")


def _describe_op(call_text: str, callee: str) -> str:
    """Readable operation name for dotted and chained calls alike."""
    if callee != "<complex>":
        return f"`{callee}`"
    attrs = _OP_ATTR_RE.findall(mask_strings(call_text))
    if attrs:
        return f"`.{attrs[-1]}(...)`"
    return "`<chained call>`"


def _resource_op(
    module: NormalizedModule,
    func: FunctionDef,
    lines: list[str],
    parameters: dict[str, frozenset[str]],
) -> tuple[str | None, bool]:
    """First resource-sensitive operation in handler scope, if any.

    Returns (description, is_write). Write-like operations always count;
    lookups count only with a non-constant identifier argument.
    """
    calls = sorted(
        (c for c in module.calls if c.function_id == func.id),
        key=lambda c: (c.location.start_line, c.location.start_column),
    )
    if not calls:
        return None, False
    assignments = build_assignment_map(
        lines,
        max(c.location.start_line for c in calls),
        func.body_location.start_line,
        parameters,
    )
    lookup: tuple[str | None, bool] = (None, False)
    for call in calls:
        text = _call_text_slice(lines, call.location)
        if not text.strip():
            continue
        masked = mask_strings(text)
        base_name = call.callee_text.rpartition(".")[2]
        dotted = "." in call.callee_text
        if _WRITE_OP_RE.search(masked):
            return f"resource modification via {_describe_op(text, call.callee_text)}", True
        if not dotted and _BARE_WRITE_HELPER_RE.fullmatch(base_name):
            return f"resource modification via `{call.callee_text}`", True
        if lookup[0] is not None:
            continue
        dotted_lookup = bool(_LOOKUP_OP_RE.search(masked))
        bare_lookup = not dotted and _BARE_READ_HELPER_RE.fullmatch(base_name) is not None
        if not (dotted_lookup or bare_lookup):
            continue
        identifiers = _call_argument_identifiers(text)
        dynamic = [
            name
            for name in identifiers
            if assignments.origin_of(name, call.function_id) is not Origin.CONSTANT
        ]
        if dynamic:
            shown = ", ".join(sorted(set(dynamic))[:2])
            described = _describe_op(text, call.callee_text)
            lookup = (f"resource lookup via {described} keyed by `{shown}`", False)
    return lookup


def _handler_scope_text(lines: list[str], func: FunctionDef) -> str:
    """Signature plus body lines for one handler (bounded by construction)."""
    start = max(0, func.location.start_line - 1)
    end = min(len(lines), func.body_location.end_line)
    return "\n".join(lines[start:end])


def _evaluate_function(
    module: NormalizedModule,
    func: FunctionDef,
    source: SourceFile,
    parameters: dict[str, frozenset[str]],
    sibling_authorized: bool,
) -> EvaluatedSink | None:
    """Evaluate one route handler (None = no finding)."""
    lines = list(source.lines)
    if func.location.start_line < 1 or func.location.start_line > len(lines):
        return None
    route = _route_above(lines, func.location.start_line)
    if route is None:
        if not _has_bare_route(func):
            return None
        route_path, route_text = "<decorator route>", "@" + func.decorator_names[0]
    else:
        route_path, route_text = route
    base_name = func.qualified_name.rpartition(".")[2]
    if _is_public(route_path, base_name):
        return None
    scope_text = _handler_scope_text(lines, func)
    auth = _auth_signals(mask_strings(scope_text), func.decorator_names)
    if auth:
        return None
    resource_op, write_op = _resource_op(module, func, lines, parameters)
    if resource_op is None:
        return None
    if sibling_authorized:
        severity, confidence = Severity.MEDIUM, Confidence.MEDIUM
        consistency = (
            " Another handler in the same module shows a recognizable "
            "authorization check while this one does not."
        )
    elif write_op:
        severity, confidence = Severity.MEDIUM, Confidence.LOW
        consistency = ""
    else:
        severity, confidence = Severity.LOW, Confidence.LOW
        consistency = ""
    confidence = adjust_for_partial(confidence, module.completeness != "fully")
    assert confidence is not Confidence.HIGH
    description = (
        f"Potential missing authorization check: route `{route_text}` handled by "
        f"`{func.qualified_name}` performs {resource_op}, but no recognizable "
        f"authorization check was identified within the analyzed flow.{consistency} "
        "Manual review is required to determine whether this operation is "
        "intended to be restricted. This pattern deserves security review; it "
        "is not a confirmed vulnerability, and authorization is not concluded "
        "to be broken."
    )
    return EvaluatedSink(
        severity=severity,
        confidence=confidence,
        title="Potential missing authorization check",
        description=description,
        subject_key=f"{func.qualified_name}:{route_path}",
        severity_factors=(f"resource operation: {resource_op}",),
        confidence_factors=(
            "no recognizable authorization signal",
            "evidence basis: context",
        ),
        limitations=(
            Limitation(
                scope=f"security:{SPEC.rule_id}",
                reason="Authorization enforced outside the visible flow "
                "(middleware, decorators, gateways, data-layer scoping) "
                "cannot be seen by this rule.",
                path=func.location.file_path,
                rule_id=SPEC.rule_id,
            ),
        ),
        impact=(
            "If an authorization check is truly missing, a user could access "
            "or alter resources they should not be able to."
        ),
    )


def _authorized_handler_names(module: NormalizedModule, source: SourceFile) -> set[str]:
    """Qualified names of route handlers showing an authorization signal."""
    lines = list(source.lines)
    authorized: set[str] = set()
    for func in module.functions:
        if func.location.start_line < 1 or func.location.start_line > len(lines):
            continue
        route = _route_above(lines, func.location.start_line)
        if route is None and not _has_bare_route(func):
            continue
        scope_text = _handler_scope_text(lines, func)
        if _auth_signals(mask_strings(scope_text), func.decorator_names):
            authorized.add(func.qualified_name)
    return authorized


def _route_handlers_seen(module: NormalizedModule, source: SourceFile) -> bool:
    """Whether any function in the module is a route handler candidate."""
    lines = list(source.lines)
    for func in module.functions:
        if func.location.start_line < 1 or func.location.start_line > len(lines):
            continue
        if _route_above(lines, func.location.start_line) is not None or _has_bare_route(func):
            return True
    return False


def execute_potential_authorization(
    execution_context: RuleExecutionContext, source: SourceProvider | None
) -> tuple[RuleOutcome, Coverage]:
    """Rule entry point (returns outcome plus explicit coverage)."""
    context = execution_context.context
    scope = summarize_scope(context.ncm)
    limitations = base_limitations(SPEC.rule_id, scope)
    if not scope.has_supported_content:
        coverage = coverage_for(SPEC.rule_id, scope, sinks_found=False)
        limitations.append(
            Limitation(
                scope=f"security:{SPEC.rule_id}",
                reason=coverage.reason,
                rule_id=SPEC.rule_id,
            )
        )
        return RuleOutcome(findings=[], limitations=limitations), coverage
    findings: list[Finding] = []
    handlers_seen = False
    unevaluated = False
    for path in scope.python_modules:
        module = next((m for m in context.ncm.modules if m.file_path == path), None)
        if module is None:
            continue
        source_file = source.read(path) if source is not None else None
        if source_file is None:
            unevaluated = True
            limitations.append(
                Limitation(
                    scope=f"security:{SPEC.rule_id}",
                    reason="Source lines were unavailable for a Python module; "
                    "its handlers could not be evaluated and it is not clean.",
                    path=path,
                    rule_id=SPEC.rule_id,
                )
            )
            continue
        parameters = function_parameters(module)
        authorized_handlers = _authorized_handler_names(module, source_file)
        if _route_handlers_seen(module, source_file):
            handlers_seen = True
        for func in sorted(
            module.functions, key=lambda f: (f.location.start_line, f.location.start_column)
        ):
            verdict = _evaluate_function(
                module,
                func,
                source_file,
                parameters,
                bool(authorized_handlers - {func.qualified_name}),
            )
            if verdict is None:
                continue
            findings.append(
                make_location_finding(
                    spec=SPEC,
                    analyzer_version=context.analyzer_version,
                    rule_set_version=context.rule_set_version,
                    analysis_id=context.analysis_id,
                    location=func.location,
                    lines=source_file.lines,
                    verdict=verdict,
                    partial=module.completeness != "fully",
                )
            )
    coverage = coverage_for(SPEC.rule_id, scope, sinks_found=handlers_seen)
    if unevaluated and coverage.status is not CoverageStatus.PARTIALLY_COVERED:
        coverage = Coverage(
            rule_id=SPEC.rule_id,
            status=CoverageStatus.PARTIALLY_COVERED,
            reason=(
                "Some supported modules could not be evaluated because their "
                "source lines were unavailable; they are not treated as clean."
            ),
        )
    if coverage.status.value in ("not_applicable",):
        limitations.append(
            Limitation(
                scope=f"security:{SPEC.rule_id}",
                reason=coverage.reason,
                rule_id=SPEC.rule_id,
            )
        )
    return RuleOutcome(findings=dedupe_findings(findings), limitations=limitations), coverage
