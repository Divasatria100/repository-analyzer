"""Markdown report rendering (docs/13 §18, docs/17 §4.6).

Derived strictly from the canonical analysis result: no re-analysis, no
recomputation, no information absent from the result. Area states and
limitations are always visible; null sections render as not available with
their state and reason; evidence appears exactly as persisted (inside code
blocks, never unmasked); no score is produced anywhere.

Repository-derived strings are untrusted data. Inline values are rendered
inside safe code spans (fence adapts to embedded backticks), evidence uses
safe fenced blocks (fence adapts to embedded fence-like sequences), table
cells escape pipes, and multi-line prose has its line-start markers escaped
so repository content cannot fabricate trusted report headings or structure.
"""

from __future__ import annotations

import json
import re


def render_markdown(result: dict[str, object]) -> str:
    """Render the canonical result as a Markdown report."""
    lines: list[str] = []
    analysis = _mapping(result, "analysis")
    repository = _mapping(result, "repository")
    status = _mapping(result, "status")
    lines.append(
        f"# Analysis Report: {_single(repository.get('owner'))}/{_single(repository.get('name'))}"
    )
    lines.append("")
    lines.append("## Repository")
    lines.append(f"- URL: {_span(repository.get('url'))}")
    lines.append(f"- Owner: {_span(repository.get('owner'))}")
    lines.append(f"- Name: {_span(repository.get('name'))}")
    lines.append("")
    lines.append("## Analysis Context")
    lines.append(f"- Analysis ID: {_span(analysis.get('analysis_id'))}")
    lines.append(f"- Timestamp: {_span(analysis.get('timestamp'))}")
    lines.append(f"- Analyzer version: {_span(analysis.get('analyzer_version'))}")
    lines.append(f"- Rule-set version: {_span(analysis.get('rule_set_version'))}")
    lines.append(f"- Configuration: {_span(_inline(analysis.get('configuration')))}")
    lines.append(f"- Advisory data: {_span(_inline(analysis.get('advisory_data')))}")
    analyzed = _mapping(repository, "analyzed_state")
    lines.append(f"- Branch: {_span(_inline(analyzed.get('branch')))}")
    lines.append(f"- Commit: {_span(_inline(analyzed.get('commit')))}")
    lines.append("")
    lines.append("## Summary")
    summary = result.get("summary")
    if isinstance(summary, dict):
        for area in ("security", "architecture", "dependencies", "code_structure"):
            entry = summary.get(area)
            if isinstance(entry, dict):
                lines.append(
                    f"- {area}: state {_span(entry.get('state'))}, "
                    f"findings {_span(_inline(entry.get('findings')))}"
                )
        files_summary = summary.get("files")
        languages = summary.get("languages")
        lines.append(f"- Files: {_span(_inline(files_summary))}")
        lines.append(f"- Languages: {_span(_inline(languages))}")
    else:
        lines.append("Summary is not available for this analysis state.")
    lines.append("")
    for area, key, title in (
        ("security", "security", "Security"),
        ("architecture", "architecture", "Architecture"),
        ("dependency", "dependencies", "Dependencies"),
        ("code_structure", "code_structure", "Code Structure"),
    ):
        lines.append(f"## {title}")
        lines.extend(_area_lines(area, result.get(key), status))
        lines.append("")
    lines.append("## Files")
    files = result.get("files")
    if isinstance(files, list):
        for entry in files:
            if not isinstance(entry, dict):
                continue
            lines.append(
                f"- {_span(entry.get('path'))} ({_single(entry.get('file_type'))}, "
                f"{_single(entry.get('support'))}, "
                f"parse {_span(entry.get('parse_result'))}, "
                f"findings {_single(entry.get('finding_count'))})"
            )
    else:
        lines.append("Files are not available for this analysis state.")
    lines.append("")
    lines.append("## Findings")
    lines.extend(_findings_index(result))
    lines.append("")
    comparison = result.get("comparison")
    if isinstance(comparison, dict):
        lines.append("## Comparison")
        lines.append(f"- Comparable: {_span(comparison.get('comparable'))}")
        for key in ("new", "resolved", "unchanged"):
            entries = comparison.get(key)
            count = len(entries) if isinstance(entries, list) else 0
            lines.append(f"- {key}: {count}")
        lines.append("")
    lines.append("## Limitations / Warnings")
    lines.extend(_limitations_lines(status))
    lines.append("")
    lines.append(
        "Findings are static-analysis indicators to be validated by manual review. "
        "Static analysis cannot prove exploitability or the absence of issues; "
        "the recorded limitations above qualify how far these results can be trusted."
    )
    lines.append("")
    return "\n".join(lines)


def _area_lines(area: str, section: object, status: dict[str, object]) -> list[str]:
    """Render one area section with its state always visible."""
    lines: list[str] = []
    state, reason = _domain_state(status, area)
    rendered = "null" if state is None else state
    lines.append(f"State: {_span(rendered)}" + (f" — {_prose(reason)}" if reason else ""))
    if not isinstance(section, dict):
        lines.append("This section is not available for this analysis state.")
        return lines
    if area == "architecture":
        graph = section.get("graph")
        if isinstance(graph, dict):
            nodes = graph.get("nodes")
            edges = graph.get("edges")
            lines.append(
                f"Modules: {len(nodes) if isinstance(nodes, list) else 0}, "
                f"relationships: {len(edges) if isinstance(edges, list) else 0}."
            )
            if isinstance(nodes, list):
                lines.append("")
                lines.append("| Module | Layer | Partially represented | Findings |")
                lines.append("| --- | --- | --- | --- |")
                for node in nodes:
                    if not isinstance(node, dict):
                        continue
                    finding_ids = node.get("finding_ids")
                    lines.append(
                        f"| {_cell(node.get('node_id'))} | {_cell(node.get('layer'))} | "
                        f"{_cell(node.get('partially_represented'))} | "
                        f"{_cell(len(finding_ids) if isinstance(finding_ids, list) else 0)} |"
                    )
        cycles = section.get("cycles")
        if isinstance(cycles, list) and cycles:
            lines.append("")
            lines.append("Cycles:")
            for cycle in cycles:
                if isinstance(cycle, dict):
                    lines.append(
                        f"- {_span(cycle.get('finding_id'))}: "
                        f"{_span(_inline(cycle.get('node_ids')))}"
                    )
    if area == "dependency":
        items = section.get("items")
        if isinstance(items, list):
            lines.append(f"Dependency occurrences: {len(items)}.")
    findings = section.get("findings")
    if isinstance(findings, list):
        lines.append("")
        lines.append(f"Findings: {len(findings)}.")
        for finding in findings:
            if not isinstance(finding, dict):
                continue
            lines.append("")
            lines.append(
                f"### {_span(finding.get('finding_id'))} {_single(finding.get('rule_id'))}"
            )
            lines.append(f"- Severity: {_span(finding.get('severity'))}")
            lines.append(f"- Confidence: {_span(finding.get('confidence'))}")
            lines.append(f"- Explanation: {_prose(finding.get('explanation'))}")
            if finding.get("impact") is not None:
                lines.append(f"- Impact: {_prose(finding.get('impact'))}")
            lines.append(f"- Recommendation: {_prose(finding.get('recommendation'))}")
            evidence = finding.get("evidence")
            if isinstance(evidence, dict):
                context = evidence.get("source_context")
                if isinstance(context, dict) and context.get("text") is not None:
                    lines.append(
                        f"- Evidence (redacted: {_span(evidence.get('redacted'))}, "
                        f"lines {_single(context.get('start_line'))}–"
                        f"{_single(context.get('end_line'))}):"
                    )
                    lines.extend(_fenced_block(str(context.get("text"))))
    return lines


def _findings_index(result: dict[str, object]) -> list[str]:
    """Cross-area finding index grouped by category (no combined measure)."""
    sections = {
        "security": "security",
        "architecture": "architecture",
        "dependency": "dependencies",
        "code_structure": "code_structure",
    }
    lines = [
        "| Finding | Category | Rule | Severity | Location |",
        "| --- | --- | --- | --- | --- |",
    ]
    empty = True
    for area, key in sections.items():
        section = result.get(key)
        if not isinstance(section, dict):
            continue
        findings = section.get("findings")
        if not isinstance(findings, list):
            continue
        for finding in findings:
            if not isinstance(finding, dict):
                continue
            empty = False
            subject = finding.get("subject")
            locations = subject.get("locations") if isinstance(subject, dict) else None
            first = locations[0] if isinstance(locations, list) and locations else {}
            path = first.get("path") if isinstance(first, dict) else None
            lines.append(
                f"| {_cell(finding.get('finding_id'))} | {_cell(area)} | "
                f"{_cell(finding.get('rule_id'))} | "
                f"{_cell(finding.get('severity'))} | {_cell(path)} |"
            )
    if empty:
        lines.append("No findings are available in this result.")
    return lines


def _limitations_lines(status: dict[str, object]) -> list[str]:
    """Limitations block: outcome, domains, and recorded limitations."""
    lines = [
        f"- Outcome: {_span(status.get('outcome'))}",
        f"- Stage: {_span(status.get('stage'))}",
        f"- Explanation: {_prose(status.get('explanation'))}",
    ]
    domains = status.get("domains")
    if isinstance(domains, list):
        for domain in domains:
            if not isinstance(domain, dict):
                continue
            reason = f" — {_prose(domain.get('reason'))}" if domain.get("reason") else ""
            lines.append(
                f"- Area {_span(domain.get('area'))}: {_span(domain.get('state'))}{reason}"
            )
    limitations = status.get("limitations")
    if isinstance(limitations, list) and limitations:
        lines.append("- Recorded limitations:")
        for limitation in limitations:
            if isinstance(limitation, dict):
                lines.append(f"  - {_span(_inline(limitation))}")
    else:
        lines.append("- No limitations recorded.")
    return lines


def _domain_state(status: dict[str, object], area: str) -> tuple[object, object]:
    """Look up one area's state and reason from the status domains."""
    domains = status.get("domains")
    if isinstance(domains, list):
        for domain in domains:
            if isinstance(domain, dict) and domain.get("area") == area:
                return domain.get("state"), domain.get("reason")
    return "Analysis unavailable", "No domain state recorded."


def _mapping(payload: object, key: str) -> dict[str, object]:
    """Narrow an untyped mapping member to a dict (empty when absent)."""
    if isinstance(payload, dict):
        member = payload.get(key)
        if isinstance(member, dict):
            return member
    return {}


def _scalar(value: object) -> str:
    """Plain string form of a scalar (None/bool keep JSON spelling)."""
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


def _single(value: object) -> str:
    """Single-line prose: newlines collapse so structure cannot be spoofed."""
    return re.sub(r"\s+", " ", _scalar(value)).strip()


def _span(value: object) -> str:
    """Safe inline code span for an untrusted value.

    The fence grows past any backtick run inside the value, and values
    starting or ending with a backtick are space-padded, so embedded
    backticks can never close the span early. Pipes are escaped so table
    cells cannot break out of their column.
    """
    text = _single(value).replace("|", "\\|")
    runs = re.findall(r"`+", text)
    fence = "`" * (max((len(run) for run in runs), default=0) + 1)
    if text.startswith("`") or text.endswith("`"):
        return f"{fence} {text} {fence}"
    return f"{fence}{text}{fence}"


def _cell(value: object) -> str:
    """Safe table cell (inline code span with pipe escaping)."""
    return _span(value)


def _prose(value: object) -> str:
    """Safe prose for free-text fields possibly containing newlines.

    Continuation lines have leading Markdown structure markers escaped so
    embedded headings, lists, quotes, or tables remain visible as data
    rather than becoming trusted report structure.
    """
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    text = str(value).replace("\r\n", "\n").replace("\r", "\n")
    safe: list[str] = []
    for line in text.split("\n"):
        stripped = line.lstrip()
        prefix_len = len(line) - len(stripped)
        prefix = line[:prefix_len]
        if re.match(r"(#{1,6}\s|#{1,6}$|[-*+>]\s|\|\s?|\d+[.)]\s|```)", stripped):
            safe.append(prefix + "\\" + stripped)
        else:
            safe.append(line)
    return "\n".join(safe)


def _fenced_block(text: str) -> list[str]:
    """Safe fenced code block preserving evidence bytes verbatim.

    The fence grows past any backtick run inside the evidence so
    fence-like content can never close the block early; no evidence
    characters are removed in the process.
    """
    runs = re.findall(r"`+", text)
    fence = "`" * max(3, max((len(run) for run in runs), default=0) + 1)
    return [fence, text, fence]


def _inline(value: object) -> str:
    """Compact inline rendering of a JSON-compatible value."""
    if value is None:
        return "null"
    try:
        return json.dumps(value, sort_keys=True, default=str)
    except (TypeError, ValueError):
        return str(value)
