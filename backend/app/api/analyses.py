"""Analysis endpoints (TASK-162–165, 167; docs/17 §§4.1–4.4, 4.6).

Read paths serve persisted snapshots only: nothing here executes
analyzers, recomputes results, or mutates sealed history. Creation
validates and persists acceptance (Queued); pipeline execution proceeds
out of band, so the 202 response always reflects the persisted stage.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Query, Response
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session

from app.api.common import (
    canonical_for_snapshot,
    get_analysis_or_404,
    require_completed_snapshot,
    status_rows,
    unavailable_areas,
)
from app.api.deps import get_db, get_github_client, get_settings_dep
from app.api.errors import ApiError
from app.api.pagination import paginate, parse_pagination
from app.core.config import Settings
from app.models.repository import Analysis, Repository
from app.reports.html import render_html
from app.reports.markdown import render_markdown
from app.repositories import ingestion as persistence
from app.repository.errors import InvalidRepositoryUrlError
from app.repository.github import GitHubClient
from app.repository.identity import normalize_github_url
from app.repository.ingestion import RULE_SET_VERSION
from app.repository.retrieval import check_remote_size
from app.results import (
    analysis_section,
    comparison_to_dict,
    repository_section,
    status_section,
)
from app.schemas.api import AnalysisCreateRequest

router = APIRouter()

#: Finding sort fields (docs/17 §4.3).
FINDING_SORTS = frozenset({"severity", "confidence", "rule", "category", "file"})

#: Finding filter vocabularies (docs/17 §§3.3, 4.3).
SEVERITIES = ("Critical", "High", "Medium", "Low", "Info")
CONFIDENCES = ("High", "Medium", "Low")
CATEGORIES = ("security", "architecture", "dependency", "code_structure")
RULE_PREFIXES = ("SEC-", "ARCH-", "DEP-", "CODE-")

SEVERITY_RANK = {name: rank for rank, name in enumerate(SEVERITIES)}
CONFIDENCE_RANK = {name: rank for rank, name in enumerate(CONFIDENCES)}

#: Area key per canonical section name.
SECTION_AREAS = {
    "security": "security",
    "architecture": "architecture",
    "dependencies": "dependency",
    "code_structure": "code_structure",
}

#: Module-level dependency singletons (ruff B008: no calls in defaults).
#: Each query parameter needs its own Query instance; sharing one across
#: parameters confuses FastAPI parameter resolution.
_db = Depends(get_db)
_settings = Depends(get_settings_dep)
_github = Depends(get_github_client)
_comparison_base_query = Query(default=None)
_category_query = Query(default=None)
_severity_query = Query(default=None)
_confidence_query = Query(default=None)
_rule_id_query = Query(default=None)
_q_query = Query(default=None)
_sort_query = Query(default="severity")
_order_query = Query(default="asc")
_page_query = Query(default=None)
_page_size_query = Query(default=None)
_format_query = Query(default="json")
_json_query = Query(default="json")


@router.post("/analyses", status_code=202)
def create_analysis(
    body: AnalysisCreateRequest,
    session: Session = _db,
    settings: Settings = _settings,
    github: GitHubClient = _github,
) -> dict[str, object]:
    """Accept a public repository URL and persist a Queued analysis (§4.1).

    All pre-persistence validation (URL form, accessibility, size,
    branch/commit resolution) runs before any row is written (docs/12
    §6.3). The remote always derives from the validated identity — never
    from client input.
    """
    raw_url = (body.url or "").strip()
    if not raw_url:
        raise ApiError(
            "INVALID_URL", "The submitted value is not a valid public GitHub repository URL."
        )
    try:
        identity = normalize_github_url(raw_url)
    except InvalidRepositoryUrlError as exc:
        raise ApiError("INVALID_URL", exc.user_message) from exc
    metadata = github.get_repository(identity)
    check_remote_size(
        metadata.size_kb * 1024 if metadata.size_kb is not None else None,
        settings.operational.repo_max_size_bytes,
    )
    if body.branch is not None:
        github.resolve_branch(identity, body.branch)
    if body.commit is not None:
        github.resolve_commit(identity, body.commit)
    repository = persistence.get_or_create_repository(
        session, identity, default_branch=metadata.default_branch
    )
    analysis = persistence.create_analysis(
        session,
        repository,
        requested_branch=body.branch,
        requested_commit=body.commit,
        analyzer_version=settings.application.version,
        rule_set_version=RULE_SET_VERSION,
    )
    session.flush()
    return {
        "analysis_id": analysis.id,
        "repository_id": repository.id,
        "stage": analysis.stage,
    }


@router.get("/analyses/{analysis_id}")
def get_analysis(
    analysis_id: str,
    comparison_base: str | None = _comparison_base_query,
    session: Session = _db,
) -> dict[str, object]:
    """Analysis status and, when completed, the full result (§4.2)."""
    analysis = get_analysis_or_404(session, analysis_id)
    if analysis.outcome not in ("Completed", "Completed with limitations"):
        domains, limitations, snapshot = status_rows(session, analysis.id)
        repository = session.get(Repository, analysis.repository_id)
        if repository is None:
            raise ApiError("INTERNAL_ERROR", "An unexpected error occurred.")
        return {
            "analysis": analysis_section(analysis),
            "repository": repository_section(analysis, repository),
            "status": status_section(
                analysis, domains, limitations, snapshot.sealed_at if snapshot else None
            ),
            "summary": None,
            "security": None,
            "architecture": None,
            "dependencies": None,
            "code_structure": None,
            "files": None,
            "comparison": None,
        }
    data = require_completed_snapshot(session, analysis)
    result = canonical_for_snapshot(data)
    if comparison_base is not None:
        result["comparison"] = _comparison(
            session, analysis_id=data.analysis.id, base_id=comparison_base
        )
    else:
        result["comparison"] = None
    return result


@router.get("/analyses/{analysis_id}/findings")
def list_findings(
    analysis_id: str,
    category: list[str] | None = _category_query,
    severity: list[str] | None = _severity_query,
    confidence: list[str] | None = _confidence_query,
    rule_id: list[str] | None = _rule_id_query,
    q: str | None = _q_query,
    sort: str = _sort_query,
    order: str = _order_query,
    page: str | None = _page_query,
    page_size: str | None = _page_size_query,
    session: Session = _db,
    settings: Settings = _settings,
) -> dict[str, object]:
    """Filterable cross-area findings explorer (§4.3, full objects)."""
    analysis = get_analysis_or_404(session, analysis_id)
    data = require_completed_snapshot(session, analysis)
    result = canonical_for_snapshot(data)
    status = result.get("status")
    assert isinstance(status, dict)
    entries: list[dict[str, object]] = []
    for key in ("security", "architecture", "dependencies", "code_structure"):
        section = result.get(key)
        if isinstance(section, dict):
            findings = section.get("findings")
            if isinstance(findings, list):
                entries.extend(item for item in findings if isinstance(item, dict))
    total = len(entries)
    filtered = _apply_filters(entries, category, severity, confidence, rule_id, q)
    ordered = _apply_sort(filtered, sort, order)
    current_page, current_size = parse_pagination(settings, page, page_size)
    response = paginate(ordered, total, current_page, current_size)
    missing = unavailable_areas(status)
    if missing:
        response["unavailable_areas"] = missing
    return response


@router.get("/analyses/{analysis_id}/architecture")
def get_architecture(analysis_id: str, session: Session = _db) -> dict[str, object]:
    """Bounded architecture document: graph, metrics, findings (§4.4)."""
    analysis = get_analysis_or_404(session, analysis_id)
    data = require_completed_snapshot(session, analysis)
    result = canonical_for_snapshot(data)
    section = result.get("architecture")
    if not isinstance(section, dict):
        raise ApiError(
            "REPORT_UNAVAILABLE",
            "Architecture results cannot be produced for this analysis state.",
        )
    graph = section.get("graph")
    if not isinstance(graph, dict):
        raise ApiError("INTERNAL_ERROR", "An unexpected error occurred.")
    return {
        "granularity": graph.get("granularity"),
        "potentially_incomplete": graph.get("potentially_incomplete"),
        "nodes": graph.get("nodes"),
        "edges": graph.get("edges"),
        "external_and_unresolved_references": graph.get("external_and_unresolved_references"),
        "cycles": section.get("cycles"),
        "metrics": section.get("metrics"),
        "metric_definitions": section.get("metric_definitions"),
        "findings": section.get("findings"),
        "rule_evaluations": section.get("rule_evaluations"),
    }


@router.get("/analyses/{analysis_id}/report")
def get_report(
    analysis_id: str,
    format: str = _format_query,
    session: Session = _db,
) -> Response:
    """Consolidated report derived from the canonical result (§4.6)."""
    if format not in ("json", "markdown", "html"):
        raise ApiError("VALIDATION_ERROR", "Unknown report format. Use json, markdown, or html.")
    analysis = get_analysis_or_404(session, analysis_id)
    if analysis.outcome not in ("Completed", "Completed with limitations"):
        raise ApiError(
            "ANALYSIS_NOT_COMPLETED", "The analysis has not reached a completed outcome."
        )
    data = require_completed_snapshot(session, analysis)
    result = canonical_for_snapshot(data)
    if format == "json":
        return JSONResponse(content=result)
    if format == "markdown":
        return Response(
            content=render_markdown(result),
            headers={"content-type": "text/markdown"},
        )
    return Response(
        content=render_html(result),
        headers={"content-type": "text/html"},
    )


def _comparison(session: Session, analysis_id: str, base_id: str) -> dict[str, object] | None:
    """Embed a comparison when the base analysis is usable (§4.2, §15)."""
    from app.repositories.results import compare_analyses

    base = session.get(Analysis, base_id)
    if base is None:
        raise ApiError("ANALYSIS_NOT_FOUND", "Analysis was not found.")
    if base.outcome not in ("Completed", "Completed with limitations"):
        raise ApiError(
            "ANALYSIS_NOT_COMPLETED", "The analysis has not reached a completed outcome."
        )
    return comparison_to_dict(compare_analyses(session, base_id, analysis_id))


def _apply_filters(
    entries: list[dict[str, object]],
    category: list[str] | None,
    severity: list[str] | None,
    confidence: list[str] | None,
    rule_id: list[str] | None,
    q: str | None,
) -> list[dict[str, object]]:
    """Apply contract filters; invalid values are VALIDATION_ERROR (400)."""
    for value in category or ():
        if value not in CATEGORIES:
            raise ApiError("VALIDATION_ERROR", f"Unknown category filter: {value!r}.")
    for value in severity or ():
        if value not in SEVERITIES:
            raise ApiError("VALIDATION_ERROR", f"Unknown severity filter: {value!r}.")
    for value in confidence or ():
        if value not in CONFIDENCES:
            raise ApiError("VALIDATION_ERROR", f"Unknown confidence filter: {value!r}.")
    for value in rule_id or ():
        if not value or not value.startswith(RULE_PREFIXES):
            raise ApiError("VALIDATION_ERROR", f"Unknown rule filter: {value!r}.")
    needle = (q or "").strip().lower()
    selected = entries
    if category:
        wanted = set(category)
        selected = [item for item in selected if item.get("category") in wanted]
    if severity:
        wanted = set(severity)
        selected = [item for item in selected if item.get("severity") in wanted]
    if confidence:
        wanted = set(confidence)
        selected = [item for item in selected if item.get("confidence") in wanted]
    if rule_id:
        wanted = set(rule_id)
        selected = [item for item in selected if item.get("rule_id") in wanted]
    if needle:
        selected = [item for item in selected if _matches(item, needle)]
    return selected


def _matches(entry: dict[str, object], needle: str) -> bool:
    """Case-insensitive substring search over path, module, rule id/name."""
    haystacks: list[str] = []
    rule_id = entry.get("rule_id")
    rule_name = entry.get("rule_name")
    if isinstance(rule_id, str):
        haystacks.append(rule_id)
    if isinstance(rule_name, str):
        haystacks.append(rule_name)
    subject = entry.get("subject")
    if isinstance(subject, dict):
        locations = subject.get("locations")
        if isinstance(locations, list):
            for location in locations:
                if isinstance(location, dict) and isinstance(location.get("path"), str):
                    haystacks.append(str(location.get("path")))
        modules = subject.get("modules")
        if isinstance(modules, list):
            haystacks.extend(str(item) for item in modules if isinstance(item, str))
    return any(needle in text.lower() for text in haystacks)


def _apply_sort(entries: list[dict[str, object]], sort: str, order: str) -> list[dict[str, object]]:
    """Deterministic ordering with stable tie-breakers (docs/17 §4.3)."""
    if sort not in FINDING_SORTS:
        raise ApiError("VALIDATION_ERROR", f"Unknown sort field: {sort!r}.")
    if order not in ("asc", "desc"):
        raise ApiError("VALIDATION_ERROR", f"Unknown sort order: {order!r}.")
    if sort == "severity":
        # Fixed severity-then-path order regardless of the order parameter.
        return sorted(entries, key=_severity_key)
    reverse = order == "desc"
    if sort == "confidence":
        return sorted(entries, key=_confidence_key, reverse=reverse)
    if sort == "rule":
        return sorted(
            entries,
            key=lambda item: (
                str(item.get("rule_id")),
                _path_of(item),
                str(item.get("finding_id")),
            ),
            reverse=reverse,
        )
    if sort == "category":
        return sorted(
            entries,
            key=lambda item: (
                str(item.get("category")),
                _path_of(item),
                str(item.get("finding_id")),
            ),
            reverse=reverse,
        )
    return sorted(
        entries,
        key=lambda item: (_path_of(item), _line_of(item), str(item.get("finding_id"))),
        reverse=reverse,
    )


def _severity_key(item: dict[str, object]) -> tuple[int, str, int, str]:
    return (
        SEVERITY_RANK.get(str(item.get("severity")), len(SEVERITY_RANK)),
        _path_of(item),
        _line_of(item),
        str(item.get("finding_id")),
    )


def _confidence_key(item: dict[str, object]) -> tuple[int, str, int, str]:
    return (
        CONFIDENCE_RANK.get(str(item.get("confidence")), len(CONFIDENCE_RANK)),
        _path_of(item),
        _line_of(item),
        str(item.get("finding_id")),
    )


def _path_of(item: dict[str, object]) -> str:
    subject = item.get("subject")
    if isinstance(subject, dict):
        locations = subject.get("locations")
        if isinstance(locations, list) and locations:
            first = locations[0]
            if isinstance(first, dict) and isinstance(first.get("path"), str):
                return str(first.get("path"))
    return ""


def _line_of(item: dict[str, object]) -> int:
    subject = item.get("subject")
    if isinstance(subject, dict):
        locations = subject.get("locations")
        if isinstance(locations, list) and locations:
            first = locations[0]
            if isinstance(first, dict):
                start = first.get("start_line")
                if isinstance(start, int):
                    return start
    return 0


def _repository_model() -> object:
    from app.models.repository import Repository

    return Repository
