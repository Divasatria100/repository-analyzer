"""HTML report rendering (docs/13 §19, docs/17 §4.6).

Same content and constraints as the Markdown report: derived from the
canonical result only, visible area states, separate severity and
confidence, redacted evidence shown as-is, no score.

Rendering uses Jinja2 with an application-owned template directory and
autoescaping always enabled. Repository-derived strings are never used as
a template source, never select the template, and never bypass escaping:
the template contains no ``|safe`` filter, repository URLs are rendered
as plain text (never as link destinations), and no executable context
(``script``, event handlers, remote assets) is produced. The report is a
static document usable without JavaScript or network requests.
"""

from __future__ import annotations

import json
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

#: Application-owned template directory (never the analyzed repository).
TEMPLATE_DIR = Path(__file__).resolve().parent / "templates"

#: Fixed application-owned template name (never repository-derived).
TEMPLATE_NAME = "report.html"

_ENV = Environment(
    loader=FileSystemLoader(str(TEMPLATE_DIR)),
    autoescape=select_autoescape(default_for_string=True, default=True),
    auto_reload=False,
)


def render_html(result: dict[str, object]) -> str:
    """Render the canonical result as a self-contained HTML report.

    Read-only over ``result``: the persisted canonical object is never
    mutated. Raises the underlying Jinja2 error on template failure
    without touching the input.
    """
    template = _ENV.get_template(TEMPLATE_NAME)
    return template.render(_context(result))


def _context(result: dict[str, object]) -> dict[str, object]:
    """Prepare plain presentation data from the canonical result."""
    repository = _mapping(result, "repository")
    analysis = _mapping(result, "analysis")
    analyzed = _mapping(repository, "analyzed_state")
    status = _mapping(result, "status")
    title = f"Analysis Report: {_s(repository.get('owner'))}/{_s(repository.get('name'))}"
    summary = result.get("summary")
    summary_available = isinstance(summary, dict)
    summary_areas: list[dict[str, object]] = []
    summary_files = "null"
    summary_languages = "null"
    if isinstance(summary, dict):
        for area in ("security", "architecture", "dependencies", "code_structure"):
            entry = summary.get(area)
            if isinstance(entry, dict):
                summary_areas.append(
                    {
                        "area": area,
                        "state": _s(entry.get("state")),
                        "findings": _inline(entry.get("findings")),
                    }
                )
        summary_files = _inline(summary.get("files"))
        summary_languages = _inline(summary.get("languages"))
    areas: list[dict[str, object]] = []
    for title_text, area, key in (
        ("Security", "security", "security"),
        ("Architecture", "architecture", "architecture"),
        ("Dependencies", "dependency", "dependencies"),
        ("Code Structure", "code_structure", "code_structure"),
    ):
        areas.append(_area_context(title_text, area, result.get(key), status))
    files = result.get("files")
    files_available = isinstance(files, list)
    file_rows: list[dict[str, object]] = []
    if isinstance(files, list):
        for entry in files:
            if not isinstance(entry, dict):
                continue
            file_rows.append(
                {
                    "path": _s(entry.get("path")),
                    "file_type": _s(entry.get("file_type")),
                    "support": _s(entry.get("support")),
                    "parse_result": _s(entry.get("parse_result")),
                    "finding_count": _s(entry.get("finding_count")),
                }
            )
    comparison = result.get("comparison")
    comparison_context: dict[str, object] | None = None
    if isinstance(comparison, dict):
        comparison_context = {
            "comparable": _s(comparison.get("comparable")),
            "counts": [
                {
                    "key": key,
                    "count": _s(
                        len(entries) if isinstance((entries := comparison.get(key)), list) else 0
                    ),
                }
                for key in ("new", "resolved", "unchanged")
            ],
        }
    return {
        "title": title,
        "repository": {
            "url": _s(repository.get("url")),
            "owner": _s(repository.get("owner")),
            "name": _s(repository.get("name")),
        },
        "analysis": {
            "analysis_id": _s(analysis.get("analysis_id")),
            "timestamp": _s(analysis.get("timestamp")),
            "analyzer_version": _s(analysis.get("analyzer_version")),
            "rule_set_version": _s(analysis.get("rule_set_version")),
            "configuration": _inline(analysis.get("configuration")),
            "advisory_data": _inline(analysis.get("advisory_data")),
        },
        "analyzed": {
            "branch": _inline(analyzed.get("branch")),
            "commit": _inline(analyzed.get("commit")),
        },
        "summary_available": summary_available,
        "summary_areas": summary_areas,
        "summary_files": summary_files,
        "summary_languages": summary_languages,
        "areas": areas,
        "files_available": files_available,
        "files": file_rows,
        "finding_rows": _finding_rows(result),
        "comparison": comparison_context,
        "status": _status_context(status),
    }


def _area_context(
    title: str, area: str, section: object, status: dict[str, object]
) -> dict[str, object]:
    """Presentation data for one area section (no analysis logic)."""
    state, reason = _domain_state(status, area)
    context: dict[str, object] = {
        "title": title,
        "state": _s(state),
        "reason": _s(reason) if reason else "",
        "available": isinstance(section, dict),
        "graph": None,
        "dep_count": None,
        "finding_count": 0,
        "findings": [],
    }
    if not isinstance(section, dict):
        return context
    if area == "architecture":
        graph = section.get("graph")
        if isinstance(graph, dict):
            nodes = graph.get("nodes") if isinstance(graph.get("nodes"), list) else []
            edges = graph.get("edges") if isinstance(graph.get("edges"), list) else []
            assert isinstance(nodes, list) and isinstance(edges, list)
            node_rows: list[dict[str, object]] = []
            for node in nodes:
                if not isinstance(node, dict):
                    continue
                finding_ids = node.get("finding_ids")
                node_rows.append(
                    {
                        "node_id": _s(node.get("node_id")),
                        "layer": _s(node.get("layer")),
                        "partial": _s(node.get("partially_represented")),
                        "count": _s(len(finding_ids) if isinstance(finding_ids, list) else 0),
                    }
                )
            edge_rows: list[dict[str, object]] = []
            for edge in edges:
                if isinstance(edge, dict):
                    edge_rows.append(
                        {"source": _s(edge.get("source")), "target": _s(edge.get("target"))}
                    )
            context["graph"] = {
                "module_count": _s(len(nodes)),
                "rel_count": _s(len(edges)),
                "nodes": node_rows,
                "edges": edge_rows,
            }
    if area == "dependency":
        items = section.get("items")
        context["dep_count"] = _s(len(items) if isinstance(items, list) else 0)
    findings = section.get("findings")
    finding_rows: list[dict[str, object]] = []
    if isinstance(findings, list):
        context["finding_count"] = _s(len(findings))
        for finding in findings:
            if isinstance(finding, dict):
                finding_rows.append(_finding_context(finding))
    context["findings"] = finding_rows
    return context


def _finding_context(finding: dict[str, object]) -> dict[str, object]:
    """Presentation data for one finding (evidence passed through as-is)."""
    context: dict[str, object] = {
        "finding_id": _s(finding.get("finding_id")),
        "rule_id": _s(finding.get("rule_id")),
        "severity": _s(finding.get("severity")),
        "confidence": _s(finding.get("confidence")),
        "explanation": _s(finding.get("explanation")),
        "impact": _s(finding.get("impact")) if finding.get("impact") is not None else None,
        "recommendation": _s(finding.get("recommendation")),
        "evidence": None,
    }
    evidence = finding.get("evidence")
    if isinstance(evidence, dict):
        inner = evidence.get("source_context")
        if isinstance(inner, dict) and inner.get("text") is not None:
            context["evidence"] = {
                "redacted": _s(evidence.get("redacted")),
                "start": _s(inner.get("start_line")),
                "end": _s(inner.get("end_line")),
                "text": _s(inner.get("text")),
            }
    return context


def _finding_rows(result: dict[str, object]) -> list[dict[str, object]]:
    """Cross-area finding index rows in canonical section order."""
    rows: list[dict[str, object]] = []
    for area, key in (
        ("security", "security"),
        ("architecture", "architecture"),
        ("dependency", "dependencies"),
        ("code_structure", "code_structure"),
    ):
        section = result.get(key)
        if not isinstance(section, dict):
            continue
        findings = section.get("findings")
        if not isinstance(findings, list):
            continue
        for finding in findings:
            if not isinstance(finding, dict):
                continue
            subject = finding.get("subject")
            locations = subject.get("locations") if isinstance(subject, dict) else None
            first = locations[0] if isinstance(locations, list) and locations else {}
            path = first.get("path") if isinstance(first, dict) else None
            rows.append(
                {
                    "finding_id": _s(finding.get("finding_id")),
                    "area": area,
                    "rule_id": _s(finding.get("rule_id")),
                    "severity": _s(finding.get("severity")),
                    "path": _s(path),
                }
            )
    return rows


def _status_context(status: dict[str, object]) -> dict[str, object]:
    """Presentation data for the status and limitations block."""
    domains: list[dict[str, object]] = []
    raw_domains = status.get("domains")
    if isinstance(raw_domains, list):
        for domain in raw_domains:
            if not isinstance(domain, dict):
                continue
            domains.append(
                {
                    "area": _s(domain.get("area")),
                    "state": _s(domain.get("state")),
                    "reason": _s(domain.get("reason")) if domain.get("reason") else "",
                }
            )
    limitations: list[str] = []
    raw_limitations = status.get("limitations")
    if isinstance(raw_limitations, list) and raw_limitations:
        for limitation in raw_limitations:
            if isinstance(limitation, dict):
                limitations.append(_inline(limitation))
    return {
        "outcome": _s(status.get("outcome")),
        "stage": _s(status.get("stage")),
        "explanation": _s(status.get("explanation")),
        "domains": domains,
        "limitations": limitations,
        "has_limitations": bool(limitations),
    }


def _domain_state(status: dict[str, object], area: str) -> tuple[object, object]:
    domains = status.get("domains")
    if isinstance(domains, list):
        for domain in domains:
            if isinstance(domain, dict) and domain.get("area") == area:
                return domain.get("state"), domain.get("reason")
    return "Analysis unavailable", "No domain state recorded."


def _mapping(payload: object, key: str) -> dict[str, object]:
    if isinstance(payload, dict):
        member = payload.get(key)
        if isinstance(member, dict):
            return member
    return {}


def _s(value: object) -> str:
    """Stringify one scalar for the template (None/bool keep JSON spelling).

    Escaping is left to Jinja2 autoescaping at the output boundary; this
    helper only normalizes nulls and booleans so the template stays
    logic-free.
    """
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


def _inline(value: object) -> str:
    if value is None:
        return "null"
    try:
        return json.dumps(value, sort_keys=True, default=str)
    except (TypeError, ValueError):
        return str(value)
