"""HTML report rendering (docs/13 §19, docs/17 §4.6).

Same content and constraints as the Markdown report: derived from the
canonical result only, visible area states, separate severity and
confidence, redacted evidence shown as-is, no score. Every
repository-derived string (evidence, module names, paths, reasons) is
escaped and presented as inert data. No analysis logic, no recomputation.
"""

from __future__ import annotations

import html
import json


def render_html(result: dict[str, object]) -> str:
    """Render the canonical result as a self-contained HTML report."""
    repository = _mapping(result, "repository")
    title = f"Analysis Report: {repository.get('owner')}/{repository.get('name')}"
    parts = [
        "<!DOCTYPE html>",
        '<html lang="en">',
        "<head>",
        '<meta charset="utf-8">',
        f"<title>{_text(title)}</title>",
        "</head>",
        "<body>",
        f"<h1>{_text(title)}</h1>",
        _repository_section(repository),
        _analysis_section(_mapping(result, "analysis"), repository),
        _summary_section(result.get("summary")),
        _area_section("Security", "security", result),
        _area_section("Architecture", "architecture", result),
        _area_section("Dependencies", "dependency", result),
        _area_section("Code Structure", "code_structure", result),
        _files_section(result.get("files")),
        _findings_section(result),
        _comparison_section(result.get("comparison")),
        _limitations_section(_mapping(result, "status")),
        "<section><h2>Static Analysis Statement</h2><p>Findings are static-analysis "
        "indicators to be validated by manual review. Static analysis cannot prove "
        "exploitability or the absence of issues; the recorded limitations above "
        "qualify how far these results can be trusted.</p></section>",
        "</body>",
        "</html>",
    ]
    return "\n".join(parts)


def _repository_section(repository: dict[str, object]) -> str:
    return (
        "<section><h2>Repository</h2><ul>"
        f"<li>URL: <code>{_text(repository.get('url'))}</code></li>"
        f"<li>Owner: <code>{_text(repository.get('owner'))}</code></li>"
        f"<li>Name: <code>{_text(repository.get('name'))}</code></li>"
        "</ul></section>"
    )


def _analysis_section(analysis: dict[str, object], repository: dict[str, object]) -> str:
    analyzed = _mapping(repository, "analyzed_state")
    return (
        "<section><h2>Analysis Context</h2><ul>"
        f"<li>Analysis ID: <code>{_text(analysis.get('analysis_id'))}</code></li>"
        f"<li>Timestamp: <code>{_text(analysis.get('timestamp'))}</code></li>"
        f"<li>Analyzer version: <code>{_text(analysis.get('analyzer_version'))}</code></li>"
        f"<li>Rule-set version: <code>{_text(analysis.get('rule_set_version'))}</code></li>"
        f"<li>Configuration: <code>{_text(_inline(analysis.get('configuration')))}</code></li>"
        f"<li>Advisory data: <code>{_text(_inline(analysis.get('advisory_data')))}</code></li>"
        f"<li>Branch: <code>{_text(_inline(analyzed.get('branch')))}</code></li>"
        f"<li>Commit: <code>{_text(_inline(analyzed.get('commit')))}</code></li>"
        "</ul></section>"
    )


def _summary_section(summary: object) -> str:
    if not isinstance(summary, dict):
        return (
            "<section><h2>Summary</h2><p>Summary is not available "
            "for this analysis state.</p></section>"
        )
    items = ""
    for area in ("security", "architecture", "dependencies", "code_structure"):
        entry = summary.get(area)
        if isinstance(entry, dict):
            items += (
                f"<li>{_text(area)}: state <code>{_text(entry.get('state'))}</code>, "
                f"findings <code>{_text(_inline(entry.get('findings')))}</code></li>"
            )
    items += f"<li>Files: <code>{_text(_inline(summary.get('files')))}</code></li>"
    items += f"<li>Languages: <code>{_text(_inline(summary.get('languages')))}</code></li>"
    return f"<section><h2>Summary</h2><ul>{items}</ul></section>"


def _area_section(title: str, area: str, result: dict[str, object]) -> str:
    status = _mapping(result, "status")
    state, reason = _domain_state(status, area)
    keys = {
        "security": "security",
        "architecture": "architecture",
        "dependency": "dependencies",
        "code_structure": "code_structure",
    }
    section = result.get(keys[area])
    body = f"<p>State: <code>{_text(state)}</code>"
    if reason:
        body += f" — {_text(reason)}"
    body += "</p>"
    if not isinstance(section, dict):
        body += "<p>This section is not available for this analysis state.</p>"
        return f"<section><h2>{_text(title)}</h2>{body}</section>"
    if area == "architecture":
        body += _architecture_graph(section)
    if area == "dependencies":
        items = section.get("items")
        body += (
            f"<p>Dependency occurrences: {_text(len(items) if isinstance(items, list) else 0)}.</p>"
        )
    findings = section.get("findings")
    if isinstance(findings, list):
        body += f"<p>Findings: {len(findings)}.</p>"
        for finding in findings:
            if isinstance(finding, dict):
                body += _finding_block(finding)
    return f"<section><h2>{_text(title)}</h2>{body}</section>"


def _architecture_graph(section: dict[str, object]) -> str:
    graph = section.get("graph")
    if not isinstance(graph, dict):
        return ""
    nodes = graph.get("nodes") if isinstance(graph.get("nodes"), list) else []
    edges = graph.get("edges") if isinstance(graph.get("edges"), list) else []
    assert isinstance(nodes, list) and isinstance(edges, list)
    rows = ""
    for node in nodes:
        if not isinstance(node, dict):
            continue
        finding_ids = node.get("finding_ids")
        count = len(finding_ids) if isinstance(finding_ids, list) else 0
        rows += (
            "<tr>"
            f"<td><code>{_text(node.get('node_id'))}</code></td>"
            f"<td><code>{_text(node.get('layer'))}</code></td>"
            f"<td><code>{_text(node.get('partially_represented'))}</code></td>"
            f"<td><code>{_text(count)}</code></td>"
            "</tr>"
        )
    edge_items = ""
    for edge in edges:
        if isinstance(edge, dict):
            edge_items += (
                f"<li><code>{_text(edge.get('source'))}</code> → "
                f"<code>{_text(edge.get('target'))}</code></li>"
            )
    # The tabular representation accompanies any visual graph (ARCH-REQ-022).
    return (
        f"<p>Modules: {len(nodes)}, relationships: {len(edges)}.</p>"
        "<table><thead><tr><th>Module</th><th>Layer</th>"
        "<th>Partially represented</th><th>Findings</th></tr></thead>"
        f"<tbody>{rows}</tbody></table><ul>{edge_items}</ul>"
    )


def _finding_block(finding: dict[str, object]) -> str:
    block = (
        f"<article><h3><code>{_text(finding.get('finding_id'))}</code> "
        f"{_text(finding.get('rule_id'))}</h3><ul>"
        f"<li>Severity: <code>{_text(finding.get('severity'))}</code></li>"
        f"<li>Confidence: <code>{_text(finding.get('confidence'))}</code></li>"
        f"<li>Explanation: {_text(finding.get('explanation'))}</li>"
    )
    if finding.get("impact") is not None:
        block += f"<li>Impact: {_text(finding.get('impact'))}</li>"
    block += f"<li>Recommendation: {_text(finding.get('recommendation'))}</li></ul>"
    evidence = finding.get("evidence")
    if isinstance(evidence, dict):
        context = evidence.get("source_context")
        if isinstance(context, dict) and context.get("text") is not None:
            block += (
                f"<p>Evidence (redacted: <code>{_text(evidence.get('redacted'))}</code>, "
                f"lines {_text(context.get('start_line'))}–{_text(context.get('end_line'))}):</p>"
                f"<pre>{_text(context.get('text'))}</pre>"
            )
    return block + "</article>"


def _files_section(files: object) -> str:
    if not isinstance(files, list):
        return (
            "<section><h2>Files</h2><p>Files are not available "
            "for this analysis state.</p></section>"
        )
    items = ""
    for entry in files:
        if not isinstance(entry, dict):
            continue
        items += (
            f"<li><code>{_text(entry.get('path'))}</code> "
            f"({_text(entry.get('file_type'))}, {_text(entry.get('support'))}, "
            f"parse <code>{_text(entry.get('parse_result'))}</code>, "
            f"findings {_text(entry.get('finding_count'))})</li>"
        )
    return f"<section><h2>Files</h2><ul>{items}</ul></section>"


def _findings_section(result: dict[str, object]) -> str:
    keys = (
        ("security", "security"),
        ("architecture", "architecture"),
        ("dependency", "dependencies"),
        ("code_structure", "code_structure"),
    )
    rows = ""
    for area, key in keys:
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
            rows += (
                "<tr>"
                f"<td><code>{_text(finding.get('finding_id'))}</code></td>"
                f"<td><code>{_text(area)}</code></td>"
                f"<td><code>{_text(finding.get('rule_id'))}</code></td>"
                f"<td><code>{_text(finding.get('severity'))}</code></td>"
                f"<td><code>{_text(path)}</code></td>"
                "</tr>"
            )
    if not rows:
        return (
            "<section><h2>Findings</h2><p>No findings are available in this result.</p></section>"
        )
    return (
        "<section><h2>Findings</h2><table><thead><tr><th>Finding</th><th>Category</th>"
        "<th>Rule</th><th>Severity</th><th>Location</th></tr></thead>"
        f"<tbody>{rows}</tbody></table></section>"
    )


def _comparison_section(comparison: object) -> str:
    if not isinstance(comparison, dict):
        return ""
    items = f"<li>Comparable: <code>{_text(comparison.get('comparable'))}</code></li>"
    for key in ("new", "resolved", "unchanged"):
        entries = comparison.get(key)
        items += f"<li>{_text(key)}: {_text(len(entries) if isinstance(entries, list) else 0)}</li>"
    return f"<section><h2>Comparison</h2><ul>{items}</ul></section>"


def _limitations_section(status: dict[str, object]) -> str:
    items = (
        f"<li>Outcome: <code>{_text(status.get('outcome'))}</code></li>"
        f"<li>Stage: <code>{_text(status.get('stage'))}</code></li>"
        f"<li>Explanation: {_text(status.get('explanation'))}</li>"
    )
    domains = status.get("domains")
    if isinstance(domains, list):
        for domain in domains:
            if not isinstance(domain, dict):
                continue
            reason = f" — {_text(domain.get('reason'))}" if domain.get("reason") else ""
            items += (
                f"<li>Area <code>{_text(domain.get('area'))}</code>: "
                f"<code>{_text(domain.get('state'))}</code>{reason}</li>"
            )
    limitations = status.get("limitations")
    if isinstance(limitations, list) and limitations:
        items += "<li>Recorded limitations:<ul>"
        for limitation in limitations:
            if isinstance(limitation, dict):
                items += f"<li><code>{_text(_inline(limitation))}</code></li>"
        items += "</ul></li>"
    else:
        items += "<li>No limitations recorded.</li>"
    return f"<section><h2>Limitations / Warnings</h2><ul>{items}</ul></section>"


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


def _text(value: object) -> str:
    """Escape repository-derived text as inert data."""
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    return html.escape(str(value), quote=True)


def _inline(value: object) -> str:
    if value is None:
        return "null"
    try:
        return json.dumps(value, sort_keys=True, default=str)
    except (TypeError, ValueError):
        return str(value)
