"""Layer inference and violation tests (TASK-129).

Layers come only from directory/module-name keywords with documented
precedence. Unknown layers never produce violations; naming-only evidence
never yields High confidence.
"""

from app.analyzers.architecture.layers import (
    APPLICATION,
    DOMAIN,
    INFRASTRUCTURE,
    PRESENTATION,
    UNKNOWN,
    find_violations,
    infer_layer,
    infer_layers,
)
from tests.fixtures.helpers.architecture_helpers import graph_for


def test_directory_keywords_assign_layers() -> None:
    assert infer_layer("services/billing.py").layer == APPLICATION
    assert infer_layer("domain/orders.py").layer == DOMAIN
    assert infer_layer("infrastructure/db.py").layer == INFRASTRUCTURE
    assert infer_layer("web/views.py").layer == PRESENTATION


def test_deepest_component_wins() -> None:
    assert infer_layer("services/domain_helper.py").layer == DOMAIN
    assert infer_layer("app/services/api.py").layer == APPLICATION


def test_unknown_without_keywords() -> None:
    assignment = infer_layer("utils/helpers.py")
    assert assignment.layer == UNKNOWN
    assert "no layer keyword" in assignment.evidence


def test_upward_edge_is_violation() -> None:
    """domain -> services runs against the downward convention."""
    report = graph_for(
        {
            "domain/orders.py": "from services import billing\n",
            "services/billing.py": "X = 1\n",
            "services/__init__.py": "",
        }
    )
    assignments = infer_layers(sorted(report.graph.nodes))
    violations, identifiable = find_violations(report.graph, assignments)
    assert identifiable is True
    assert len(violations) == 1
    (violation,) = violations
    assert (violation.source, violation.target) == ("domain/orders.py", "services/billing.py")
    assert (violation.source_layer, violation.target_layer) == (DOMAIN, APPLICATION)


def test_downward_edge_is_not_violation() -> None:
    report = graph_for(
        {
            "services/billing.py": "from domain import orders\n",
            "domain/orders.py": "X = 1\n",
            "domain/__init__.py": "",
        }
    )
    assignments = infer_layers(sorted(report.graph.nodes))
    violations, identifiable = find_violations(report.graph, assignments)
    assert identifiable is True
    assert violations == []


def test_unknown_layers_never_violate() -> None:
    report = graph_for({"a.py": "import b\n", "b.py": "X = 1\n"})
    assignments = infer_layers(sorted(report.graph.nodes))
    violations, identifiable = find_violations(report.graph, assignments)
    assert identifiable is False
    assert violations == []


def test_single_layer_is_not_identifiable() -> None:
    report = graph_for({"services/a.py": "from services import b\n", "services/b.py": "X = 1\n"})
    _, identifiable = find_violations(report.graph, infer_layers(sorted(report.graph.nodes)))
    assert identifiable is False


def test_ambiguous_names_stay_deterministic() -> None:
    first = infer_layers(["x/api_models.py", "y/service_hub.py"])
    second = infer_layers(["y/service_hub.py", "x/api_models.py"])
    assert first == second
    # Within one component the alphabetically first keyword wins (documented).
    assert first["x/api_models.py"].layer == APPLICATION
    assert first["y/service_hub.py"].layer == APPLICATION


def test_violation_finding_confidence_never_high() -> None:
    from tests.fixtures.helpers.architecture_helpers import analyze_arch, rule_result

    result, _, _ = analyze_arch(
        {
            "domain/orders.py": "from services import billing\n",
            "services/billing.py": "X = 1\n",
            "services/__init__.py": "",
        }
    )
    findings = rule_result(result, "ARCH-LAYER-VIOLATION").findings
    assert len(findings) == 1
    assert findings[0].confidence.value in ("Medium", "Low")
    assert findings[0].severity.value in ("Low", "Medium")
