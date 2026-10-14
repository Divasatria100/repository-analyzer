"""Markdown report rendering (docs/13 §18, docs/17 §4.6).

Derived strictly from the canonical analysis result: no re-analysis, no
recomputation, no information absent from the result. Area states and
limitations are always visible; null sections render as not available with
their state and reason; evidence appears exactly as persisted (inside code
blocks, never unmasked); no score is produced anywhere.
"""

from __future__ import annotations


def render_markdown(result: dict[str, object]) -> str:
    """Render the canonical result as a Markdown report."""
    lines: list[str] = []
    analysis = _mapping(result, "analysis")
    repository = _mapping(result, "repository")
    status = _mapping(result, "status")
    lines.append(f"# Analysis Report: {repository.get('owner')}/{repository.get('name')}")
    lines.append("")
    lines.append("## Repository")
    lines.append(f"- URL: `{repository.get('url')}`")
    lines.append(f"- Owner: `{repository.get('owner')}`")
    lines.append(f"- Name: `{repository.get('name')}`")
    lines.append("")
    lines.append("## Analysis Context")
    lines.append(f"- Analysis ID: `{analysis.get('analysis_id')}`")
    lines.append(f"- Timestamp: `{analysis.get('timestamp')}`")
    lines.append(f"- Analyzer version: `{analysis.get('analyzer_version')}`")
    lines.append(f"- Rule-set version: `{analysis.get('rule_set_version')}`")
    lines.append(f"- Configuration: `{_inline(analysis.get('configuration'))}`")
    lines.append(f"- Advisory data: `{_inline(analysis.get('advisory_data'))}`")
    analyzed = _mapping(repository, "analyzed_state")
    lines.append(f"- Branch: `{_inline(analyzed.get('branch'))}`")
    lines.append(f"- Commit: `{_inline(analyzed.get('commit'))}`")
    lines.append("")
    lines.append("## Summary")
    summary = result.get("summary")
    if isinstance(summary, dict):
        for area in ("security", "architecture", "dependencies", "code_structure"):
            entry = summary.get(area)
            if isinstance(entry, dict):
                lines.append(
                    f"- {area}: state `{entry.get('state')}`, "
                    f"findings `{_inline(entry.get('findings'))}`"
                )
        files_summary = summary.get("files")
        languages = summary.get("languages")
        lines.append(f"- Files: `{_inline(files_summary)}`")
        lines.append(f"- Languages: `{_inline(languages)}`")
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
                f"- `{entry.get('path')}` ({entry.get('file_type')}, {entry.get('support')}, "
                f"parse `{entry.get('parse_result')}`, findings {entry.get('finding_count')})"
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
        lines.append(f"- Comparable: `{comparison.get('comparable')}`")
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
    lines.append(f"State: `{rendered}`" + (f" — {reason}" if reason else ""))
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
                        f"| `{node.get('node_id')}` | `{node.get('layer')}` | "
                        f"`{node.get('partially_represented')}` | "
                        f"`{len(finding_ids) if isinstance(finding_ids, list) else 0}` |"
                    )
        cycles = section.get("cycles")
        if isinstance(cycles, list) and cycles:
            lines.append("")
            lines.append("Cycles:")
            for cycle in cycles:
                if isinstance(cycle, dict):
                    lines.append(
                        f"- `{cycle.get('finding_id')}`: `{_inline(cycle.get('node_ids'))}`"
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
            lines.append(f"### `{finding.get('finding_id')}` {finding.get('rule_id')}")
            lines.append(f"- Severity: `{finding.get('severity')}`")
            lines.append(f"- Confidence: `{finding.get('confidence')}`")
            lines.append(f"- Explanation: {finding.get('explanation')}")
            if finding.get("impact") is not None:
                lines.append(f"- Impact: {finding.get('impact')}")
            lines.append(f"- Recommendation: {finding.get('recommendation')}")
            evidence = finding.get("evidence")
            if isinstance(evidence, dict):
                context = evidence.get("source_context")
                if isinstance(context, dict) and context.get("text") is not None:
                    lines.append(
                        f"- Evidence (redacted: `{evidence.get('redacted')}`, "
                        f"lines {context.get('start_line')}–{context.get('end_line')}):"
                    )
                    lines.append("```")
                    lines.append(str(context.get("text")))
                    lines.append("```")
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
                f"| `{finding.get('finding_id')}` | `{area}` | `{finding.get('rule_id')}` | "
                f"`{finding.get('severity')}` | `{path}` |"
            )
    if empty:
        lines.append("No findings are available in this result.")
    return lines


def _limitations_lines(status: dict[str, object]) -> list[str]:
    """Limitations block: outcome, domains, and recorded limitations."""
    lines = [
        f"- Outcome: `{status.get('outcome')}`",
        f"- Stage: `{status.get('stage')}`",
        f"- Explanation: {status.get('explanation')}",
    ]
    domains = status.get("domains")
    if isinstance(domains, list):
        for domain in domains:
            if not isinstance(domain, dict):
                continue
            reason = f" — {domain.get('reason')}" if domain.get("reason") else ""
            lines.append(f"- Area `{domain.get('area')}`: `{domain.get('state')}`{reason}")
    limitations = status.get("limitations")
    if isinstance(limitations, list) and limitations:
        lines.append("- Recorded limitations:")
        for limitation in limitations:
            if isinstance(limitation, dict):
                lines.append(f"  - `{_inline(limitation)}`")
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


def _inline(value: object) -> str:
    """Compact inline rendering of a JSON-compatible value."""
    import json

    if value is None:
        return "null"
    try:
        return json.dumps(value, sort_keys=True, default=str)
    except (TypeError, ValueError):
        return str(value)
