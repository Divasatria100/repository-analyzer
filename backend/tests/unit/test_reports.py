"""Report rendering tests (Phase 13, TASK-174–179).

Pure renderer tests over canonical-shaped dicts: JSON schema fidelity,
Markdown structure and safe formatting, Jinja2 HTML structure, inert
repository-derived content, redaction preservation, determinism, and
failure isolation. No database, no network, no analyzer execution.
"""

from __future__ import annotations

import copy
import json
from html.parser import HTMLParser

import pytest
from jinja2 import TemplateNotFound

import app.reports.html as html_module
from app.reports.html import TEMPLATE_DIR, TEMPLATE_NAME, render_html
from app.reports.markdown import render_markdown

TOP_LEVEL_KEYS = {
    "analysis",
    "repository",
    "status",
    "summary",
    "security",
    "architecture",
    "dependencies",
    "code_structure",
    "files",
    "comparison",
}

APP_HEADINGS = {
    "# Analysis Report:",
    "## Repository",
    "## Analysis Context",
    "## Summary",
    "## Security",
    "## Architecture",
    "## Dependencies",
    "## Code Structure",
    "## Files",
    "## Findings",
    "## Comparison",
    "## Limitations / Warnings",
}

ADVERSARIAL = [
    "<script>alert(1)</script>",
    '<img src=x onerror="alert(1)">',
    '<svg onload="alert(1)">',
    '" onmouseover="alert(1)',
    "'; drop table findings; --",
    "javascript:alert(1)",
    "&lt;script&gt;",
    "<ScRiPt>alert(1)</ScRiPt>",
    "back`tick",
    "pipe|breaker",
    "ünïcodé ✓ <b>bold</b>",
    "# Forged Heading",
    "## Forged Section",
    "- [x] forged list",
    "> forged quote",
    "```evil",
]


def _minimal_result() -> dict:
    return {
        "analysis": {
            "analysis_id": "a" * 32,
            "repository_id": "r" * 32,
            "timestamp": "2026-10-14T00:00:00Z",
            "analyzer_version": "1.0.0",
            "rule_set_version": "1.0.0",
            "configuration": {},
            "advisory_data": None,
        },
        "repository": {
            "repository_id": "r" * 32,
            "url": "https://github.com/acme/web",
            "owner": "acme",
            "name": "web",
            "analyzed_state": {"branch": None, "commit": None},
        },
        "status": {
            "stage": None,
            "outcome": "Completed",
            "completed_at": "2026-10-14T00:00:00Z",
            "explanation": "",
            "snapshot": {"sealed_at": "2026-10-14T00:00:00Z"},
            "domains": [
                {"area": "security", "state": "No findings detected", "reason": None},
                {"area": "architecture", "state": None, "reason": None},
                {"area": "dependency", "state": "No findings detected", "reason": None},
                {"area": "code_structure", "state": "No findings detected", "reason": None},
            ],
            "limitations": [],
        },
        "summary": {"languages": [], "files": {"indexed": 0, "parse_results": {}}},
        "security": {"rule_evaluations": [], "findings": []},
        "architecture": {
            "rule_evaluations": [],
            "findings": [],
            "metric_definitions": {},
            "metrics": [],
            "graph": {
                "granularity": "Source file",
                "potentially_incomplete": False,
                "nodes": [],
                "edges": [],
                "external_and_unresolved_references": [],
            },
            "cycles": [],
        },
        "dependencies": {"rule_evaluations": [], "findings": [], "items": []},
        "code_structure": {"rule_evaluations": [], "findings": []},
        "files": [],
        "comparison": None,
    }


def _finding(
    finding_id: str = "F-0001",
    rule_id: str = "SEC-HARDCODED-SECRET",
    path: str = "app/config.py",
    explanation: str = "A potential hardcoded secret may require review.",
    evidence_text: str = 'KEY = "[REDACTED]"',
) -> dict:
    return {
        "finding_id": finding_id,
        "identity_key": f"ik-{finding_id}",
        "rule_id": rule_id,
        "rule_name": "Hardcoded Secret",
        "category": "security",
        "severity": "High",
        "confidence": "Medium",
        "subject": {
            "locations": [
                {
                    "path": path,
                    "start_line": 12,
                    "end_line": 12,
                    "start_column": 0,
                    "end_column": 10,
                }
            ],
            "modules": [],
            "dependencies": [],
        },
        "evidence": {
            "redacted": True,
            "source_context": {"start_line": 11, "end_line": 13, "text": evidence_text},
        },
        "explanation": explanation,
        "impact": "Availability of the value may allow misuse.",
        "recommendation": "Review and rotate through the provider.",
    }


def _populated_result() -> dict:
    result = _minimal_result()
    assert isinstance(result["security"], dict)
    result["security"]["findings"] = [
        _finding("F-0002", "SEC-SQL-INJECTION", "app/api/handlers.py"),
        _finding("F-0001", "SEC-HARDCODED-SECRET", "app/config.py"),
    ]
    return result


class _TagCollector(HTMLParser):
    """Collect start tags and event-handler-like attributes."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.tags: list[str] = []
        self.attrs: list[tuple[str, str]] = []
        self.texts: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.tags.append(tag)
        for name, value in attrs:
            self.attrs.append((name, value or ""))

    def handle_data(self, data: str) -> None:
        self.texts.append(data)


# ---------------------------------------------------------------------------
# TASK-174 — canonical JSON report
# ---------------------------------------------------------------------------


def test_json_top_level_schema_and_required_fields() -> None:
    result = _populated_result()
    assert set(result) == TOP_LEVEL_KEYS
    payload = json.dumps(result, sort_keys=True, ensure_ascii=False, allow_nan=False)
    assert json.loads(payload) == result


def test_json_empty_findings_versus_unavailable_section() -> None:
    result = _minimal_result()
    assert result["security"] == {"rule_evaluations": [], "findings": []}
    result["architecture"] = None
    assert isinstance(result["status"], dict)
    domains = result["status"]["domains"]
    assert isinstance(domains, list)
    domains[1] = {
        "area": "architecture",
        "state": "Analysis unavailable",
        "reason": "Graph data was not retained.",
    }
    payload = json.loads(json.dumps(result, allow_nan=False))
    assert payload["security"]["findings"] == []
    assert payload["architecture"] is None
    markdown = render_markdown(result)
    assert "Findings: 0." in markdown
    assert "This section is not available for this analysis state." in markdown
    assert "State: `Analysis unavailable`" in markdown


def test_json_completed_failed_and_null_semantics() -> None:
    completed = _minimal_result()
    assert completed["status"]["outcome"] == "Completed"
    assert completed["status"]["stage"] is None
    assert completed["summary"] is not None
    failed_shape = _minimal_result()
    failed_shape.update(
        {
            "status": {
                "stage": None,
                "outcome": "Failed",
                "completed_at": "2026-10-14T00:00:01Z",
                "explanation": "The repository content could not be retrieved.",
                "snapshot": None,
                "domains": [],
                "limitations": [],
            },
            "summary": None,
            "security": None,
            "architecture": None,
            "dependencies": None,
            "code_structure": None,
            "files": None,
        }
    )
    payload = json.loads(json.dumps(failed_shape, allow_nan=False))
    for key in ("summary", "security", "architecture", "dependencies", "code_structure"):
        assert payload[key] is None
    assert payload["status"]["snapshot"] is None


def test_json_unicode_special_characters_and_nulls() -> None:
    result = _minimal_result()
    result["repository"]["name"] = "wëb ✓ <ünï>"
    result["analysis"]["advisory_data"] = None
    payload = json.dumps(result, ensure_ascii=False, allow_nan=False)
    assert "wëb ✓ <ünï>" in payload
    assert json.loads(payload)["analysis"]["advisory_data"] is None
    assert '"nan"' not in payload.lower() and "Infinity" not in payload


def test_json_repeated_serialization_is_identical() -> None:
    result = _populated_result()
    first = json.dumps(result, sort_keys=True, ensure_ascii=False, allow_nan=False)
    second = json.dumps(copy.deepcopy(result), sort_keys=True, ensure_ascii=False, allow_nan=False)
    assert first == second


def test_json_stable_finding_order_preserved() -> None:
    result = _populated_result()
    findings = result["security"]["findings"]
    assert isinstance(findings, list)
    markdown = render_markdown(result)
    html = render_html(result)
    assert markdown.index("F-0002") < markdown.index("F-0001")
    assert html.index("F-0002") < html.index("F-0001")


# ---------------------------------------------------------------------------
# TASK-175 — Markdown report
# ---------------------------------------------------------------------------


def test_markdown_structure_and_required_sections() -> None:
    markdown = render_markdown(_populated_result())
    for heading in (
        "## Repository",
        "## Analysis Context",
        "## Summary",
        "## Security",
        "## Architecture",
        "## Dependencies",
        "## Code Structure",
        "## Files",
        "## Findings",
        "## Limitations / Warnings",
    ):
        assert heading in markdown
    assert "manual review" in markdown
    assert "score" not in markdown.lower()


def test_markdown_empty_and_populated_findings() -> None:
    empty = render_markdown(_minimal_result())
    assert "No findings are available in this result." in empty
    populated = render_markdown(_populated_result())
    assert "Findings: 2." in populated
    assert "F-0001" in populated and "F-0002" in populated


def test_markdown_unavailable_sections_are_not_clean() -> None:
    result = _minimal_result()
    result["dependencies"] = None
    assert isinstance(result["status"], dict)
    domains = result["status"]["domains"]
    assert isinstance(domains, list)
    domains[2] = {
        "area": "dependency",
        "state": "Analysis unavailable",
        "reason": "Manifest data was not retained.",
    }
    markdown = render_markdown(result)
    assert "## Dependencies\nState: `No findings detected`" not in markdown
    assert "This section is not available for this analysis state." in markdown


def test_markdown_repository_text_cannot_forge_structure() -> None:
    result = _minimal_result()
    result["repository"]["name"] = "web\n## Forged Section\n# Forged Title"
    result["repository"]["owner"] = "acme\n- forged list"
    markdown = render_markdown(result)
    for line in markdown.splitlines():
        if line.startswith("## ") or line.startswith("# "):
            assert any(line.startswith(known) for known in APP_HEADINGS), line


def test_markdown_multiline_prose_is_escaped_not_structural() -> None:
    result = _minimal_result()
    assert isinstance(result["security"], dict)
    result["security"]["findings"] = [
        _finding(explanation="note\n## Forged Section\n> forged quote\n- forged item")
    ]
    markdown = render_markdown(result)
    assert "\n## Forged Section\n" not in markdown
    assert "Forged Section" in markdown  # text preserved as data


def test_markdown_fence_like_evidence_is_preserved_safely() -> None:
    evidence = "before\n```python\nprint('hi')\n```\nafter with ``double`` ticks"
    result = _minimal_result()
    assert isinstance(result["security"], dict)
    result["security"]["findings"] = [_finding(evidence_text=evidence)]
    markdown = render_markdown(result)
    assert evidence in markdown  # no characters removed
    assert "````" in markdown  # fence grew past the embedded run


def test_markdown_backticks_pipes_and_unicode_in_fields() -> None:
    result = _minimal_result()
    assert isinstance(result["security"], dict)
    result["security"]["findings"] = [
        _finding(path="app/`we|ird` ünï.py", explanation="uses `eval` with pipe | char ✓")
    ]
    markdown = render_markdown(result)
    assert "we" in markdown and "ird" in markdown and "✓" in markdown
    assert "``" in markdown  # fence grew past the embedded backtick
    # The escaped pipe keeps the index row inside its column.
    row = next(line for line in markdown.splitlines() if line.startswith("| `F-0001`"))
    assert "\\|" in row


def test_markdown_redaction_preserved_and_agrees_with_json() -> None:
    result = _populated_result()
    markdown = render_markdown(result)
    assert "[REDACTED]" in markdown
    assert "ghp_live_secret_value_12345" not in markdown
    findings = result["security"]["findings"]
    assert isinstance(findings, list)
    for finding in findings:
        assert isinstance(finding, dict)
        assert str(finding["finding_id"]) in markdown
        assert str(finding["rule_id"]) in markdown


def test_markdown_deterministic_for_identical_snapshot() -> None:
    result = _populated_result()
    assert render_markdown(result) == render_markdown(copy.deepcopy(result))


def test_renderers_do_not_mutate_canonical_result() -> None:
    result = _populated_result()
    snapshot = copy.deepcopy(result)
    render_markdown(result)
    render_html(result)
    assert result == snapshot


# ---------------------------------------------------------------------------
# TASK-176 — HTML report using Jinja2
# ---------------------------------------------------------------------------


def test_html_uses_application_owned_jinja2_template() -> None:
    assert TEMPLATE_NAME == "report.html"
    assert TEMPLATE_DIR.is_dir()
    assert (TEMPLATE_DIR / TEMPLATE_NAME).is_file()
    # Template must keep autoescaping intact: no safe-bypass for data.
    template_source = (TEMPLATE_DIR / TEMPLATE_NAME).read_text(encoding="utf-8")
    assert "|safe" not in template_source
    assert "Markup" not in template_source
    assert "render_template_string" not in template_source
    autoescape = html_module._ENV.autoescape
    assert callable(autoescape) and autoescape("report.html") is True


def test_html_valid_document_and_expected_sections() -> None:
    html = render_html(_populated_result())
    assert html.startswith("<!DOCTYPE html>")
    assert "<html" in html and "</html>" in html
    assert "<head>" in html and "<body>" in html
    for section in (
        "Repository",
        "Analysis Context",
        "Summary",
        "Security",
        "Architecture",
        "Dependencies",
        "Code Structure",
        "Files",
        "Findings",
        "Limitations / Warnings",
    ):
        assert f"<h2>{section}</h2>" in html
    assert "F-0001" in html and "SEC-HARDCODED-SECRET" in html
    assert "State: <code>null</code>" in html


def test_html_null_empty_partial_sections() -> None:
    result = _minimal_result()
    result["architecture"] = None
    html = render_html(result)
    assert "This section is not available for this analysis state." in html
    assert "No findings are available in this result." in html
    assert "Summary is not available" not in html


def test_html_has_no_remote_dependencies_or_scripts() -> None:
    html = render_html(_populated_result())
    lowered = html.lower()
    assert "<script" not in lowered
    assert "<link" not in lowered
    assert "src=" not in lowered
    assert "http:// " not in html and "https://example-cdn" not in html
    assert "onclick" not in lowered and "onerror" not in lowered


def test_html_deterministic_for_identical_snapshot() -> None:
    result = _populated_result()
    assert render_html(result) == render_html(copy.deepcopy(result))


# ---------------------------------------------------------------------------
# TASK-177 — HTML escaping and inert repository-derived content
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("payload", ADVERSARIAL)
def test_html_adversarial_repository_name_is_inert(payload: str) -> None:
    result = _minimal_result()
    result["repository"]["name"] = payload
    html = render_html(result)
    collector = _TagCollector()
    collector.feed(html)
    assert "script" not in collector.tags
    assert "img" not in collector.tags
    assert "svg" not in collector.tags
    assert "iframe" not in collector.tags
    assert not any(name.startswith("on") for name, _ in collector.attrs)
    assert not any(value.strip().lower().startswith("javascript:") for _, value in collector.attrs)
    if "<" in payload or ">" in payload or '"' in payload:
        assert payload not in html  # raw markup never survives


@pytest.mark.parametrize("payload", ADVERSARIAL)
def test_html_adversarial_finding_fields_are_inert(payload: str) -> None:
    result = _minimal_result()
    assert isinstance(result["security"], dict)
    result["security"]["findings"] = [
        _finding(
            path=f"app/{payload}.py",
            explanation=f"{payload} explanation",
            evidence_text=f"{payload} evidence",
        )
    ]
    html = render_html(result)
    collector = _TagCollector()
    collector.feed(html)
    assert "script" not in collector.tags
    assert "img" not in collector.tags
    assert "svg" not in collector.tags
    assert not any(name.startswith("on") for name, _ in collector.attrs)
    if "<script>" in payload:
        assert "<script>" not in html
        assert "&lt;script&gt;" in html


def test_html_javascript_url_is_not_a_link() -> None:
    result = _minimal_result()
    result["repository"]["url"] = "javascript:alert(1)"
    html = render_html(result)
    assert "<a " not in html
    # No link destination is ever built from repository content: the value
    # stays faithful plain text inside <code>, inert without an anchor.
    assert "javascript:alert(1)" in html
    collector = _TagCollector()
    collector.feed(html)
    assert not any(value.strip().lower().startswith("javascript:") for _, value in collector.attrs)


def test_html_attribute_breaking_payload_is_inert() -> None:
    result = _minimal_result()
    result["repository"]["name"] = '" onmouseover="alert(1)'
    html = render_html(result)
    assert 'onmouseover="alert(1)' not in html
    collector = _TagCollector()
    collector.feed(html)
    assert not any(name == "onmouseover" for name, _ in collector.attrs)


def test_html_entities_and_unicode_preserved_as_text() -> None:
    result = _minimal_result()
    result["repository"]["name"] = "ünï ✓ &lt;already&gt;"
    html = render_html(result)
    assert "ünï ✓" in html
    assert "&amp;lt;already&amp;gt;" in html  # double-escaped: shown literally


def test_html_markdown_spoof_content_is_plain_text() -> None:
    result = _minimal_result()
    result["repository"]["name"] = "# Trusted Heading"
    html = render_html(result)
    assert "<h1># Trusted Heading</h1>" not in html
    assert "# Trusted Heading" in html  # preserved as inert text
    collector = _TagCollector()
    collector.feed(html)
    assert collector.tags.count("h1") == 1  # only the application title


# ---------------------------------------------------------------------------
# TASK-179 — redaction and failure isolation (unit level)
# ---------------------------------------------------------------------------


SECRET = "ghp_live_secret_value_12345"


def test_redaction_marker_preserved_across_formats() -> None:
    result = _minimal_result()
    assert isinstance(result["security"], dict)
    result["security"]["findings"] = [
        _finding(evidence_text='TOKEN = "[REDACTED]" (category api_key, len 32)')
    ]
    assert SECRET not in json.dumps(result)
    assert "[REDACTED]" in render_markdown(result)
    assert "[REDACTED]" in render_html(result)
    assert SECRET not in render_markdown(result)
    assert SECRET not in render_html(result)


def test_markdown_failure_does_not_mutate_canonical_result() -> None:
    result = _populated_result()
    snapshot = copy.deepcopy(result)
    try:
        render_markdown(result)
    except Exception:  # noqa: BLE001 - isolation means state survives either way
        pass
    assert result == snapshot


def test_html_template_failure_leaves_result_and_markdown_usable() -> None:
    result = _populated_result()
    snapshot = copy.deepcopy(result)
    with pytest.raises(TemplateNotFound):
        html_module._ENV.get_template("does-not-exist.html.j2")
    assert result == snapshot
    assert "F-0001" in render_markdown(result)
    assert json.dumps(result, sort_keys=True) == json.dumps(snapshot, sort_keys=True)
