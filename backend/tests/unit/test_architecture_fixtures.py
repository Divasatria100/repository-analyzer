"""Repository fixture coverage (TASK-134).

Every file under ``fixtures/architecture/`` plus the malformed area is
consumed as data. Fixtures must parse, extract, and contribute as their
shapes promise (non-vacuous: an empty graph where edges are expected fails).
"""

from pathlib import Path

from app.analyzers.architecture.cycles import find_cycles
from app.analyzers.architecture.graph import build_graph
from app.ncm import NcmRepository
from app.parsers.base import ParserInput
from app.parsers.registry import get_adapter

FIXTURES_ROOT = Path(__file__).resolve().parents[3] / "fixtures" / "architecture"
MALFORMED_ROOT = Path(__file__).resolve().parents[3] / "fixtures" / "malformed"


def _parse_to_ncm(files: dict[str, str]) -> NcmRepository:
    from app.ncm import NcmFileEntry

    adapter = get_adapter("python")
    assert adapter is not None
    entries = []
    for path in sorted(files):
        result = adapter.parse(
            ParserInput(path, "python", files[path].encode("utf-8"), 30.0, 1_000_000)
        )
        entries.append(
            NcmFileEntry(
                path=path, language="python", parse_state=result.state.value, module=result.ncm
            )
        )
    return NcmRepository(analysis_id="analysis-1", files=entries)


def _read_area(root: Path) -> dict[str, str]:
    return {
        path.name: path.read_text(encoding="utf-8")
        for path in sorted(root.iterdir())
        if path.is_file() and path.suffix == ".py"
    }


def test_circular_fixtures_form_a_cycle() -> None:
    files = _read_area(FIXTURES_ROOT)
    assert {"circular_alpha.py", "circular_beta.py"} <= set(files)
    pair = {name: files[name] for name in ("circular_alpha.py", "circular_beta.py")}
    report = build_graph(_parse_to_ncm(pair))
    assert len(report.graph.nodes) == 2
    assert len(report.graph.edges) == 2
    groups = find_cycles(report.graph)
    assert len(groups) == 1
    assert groups[0].members == ("circular_alpha.py", "circular_beta.py")


def test_fanout_fixture_extracts_below_threshold() -> None:
    files = _read_area(FIXTURES_ROOT)
    report = build_graph(_parse_to_ncm({"hub_fanout.py": files["hub_fanout.py"]}))
    # Six imports, all external/unresolved names: no internal edges, no finding.
    assert report.graph.edges == {}
    assert len(report.unresolved) == 6


def test_layered_fixture_has_no_internal_edges() -> None:
    files = _read_area(FIXTURES_ROOT)
    report = build_graph(_parse_to_ncm({"simple_orders.py": files["simple_orders.py"]}))
    assert report.graph.edges == {}
    assert len(report.unresolved) == 2  # architecture_simple_* are not in the repo


def test_malformed_fixture_is_failed_not_clean() -> None:
    candidates = [
        path for path in MALFORMED_ROOT.iterdir() if path.is_file() and path.suffix == ".py"
    ]
    assert candidates, "malformed fixture area is empty"
    path = sorted(candidates)[0]
    report = build_graph(_parse_to_ncm({path.name: path.read_text(encoding="utf-8")}))
    assert report.graph.nodes == {}
    assert report.failed_files == (path.name,)
    assert report.limited is True
