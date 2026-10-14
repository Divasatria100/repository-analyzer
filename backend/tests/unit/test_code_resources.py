"""Resource bounds, coverage states, and determinism (TASK-138/145, §16)."""

from app.analyzers.code_structure.duplicates import MAX_BODY_TOKENS, group_candidates
from tests.fixtures.helpers.code_structure_helpers import analyze_code, rule_result


def _distinct_bodies(count: int) -> list[tuple[str, str, int, int, tuple[str, ...]]]:
    """Bodies with disjoint token alphabets: no shared windows possible."""
    bodies = []
    for index in range(count):
        tokens = tuple(f"u{index}_{part}" for part in range(60))
        bodies.append((f"m{index}.py", "f", 1, 9, tokens))
    return bodies


def test_no_pairwise_work_without_shared_windows() -> None:
    """Structural proof: grouping hashes windows; LCS runs only on matches."""
    groups, stats = group_candidates(_distinct_bodies(30), 50)
    assert groups == []
    assert stats["pairs_used"] == 0


def test_body_budget_caps_with_limitation() -> None:
    """Only the first MAX_DUPLICATE_BODIES (sorted) enter comparison."""
    import app.analyzers.code_structure.duplicates as duplicates
    from app.analyzers.code_structure.analyzer import _tokenize_bodies
    from tests.fixtures.helpers.security_helpers import parse_files

    files = {f"m{i}.py": "def f():\n    x = 1\n" for i in range(6)}
    holder = parse_files(files)
    modules = {entry.path: entry.module for entry in holder.files if entry.module}
    old, duplicates.MAX_DUPLICATE_BODIES = duplicates.MAX_DUPLICATE_BODIES, 4
    try:
        bodies, reasons, skipped, _oversized = _tokenize_bodies(modules, {}, 50)
    finally:
        duplicates.MAX_DUPLICATE_BODIES = old
    assert bodies == []  # no source lines available in this probe
    assert skipped == 6  # 2 over budget + 4 without source
    assert any("budget" in reason for reason in reasons)


def test_duplicate_body_budget_records_skipped() -> None:
    """Analyzer-level: over-budget functions surface as limitations."""
    import app.analyzers.code_structure.duplicates as duplicates

    files = {f"m{i}.py": "def f():\n    x = 1\n" for i in range(6)}
    old, duplicates.MAX_DUPLICATE_BODIES = duplicates.MAX_DUPLICATE_BODIES, 4
    try:
        result, _, _ = analyze_code(files)
    finally:
        duplicates.MAX_DUPLICATE_BODIES = old
    outcome = rule_result(result, "CODE-DUPLICATE-CANDIDATE")
    assert any("budget" in item.reason for item in outcome.limitations)


def test_oversized_body_skipped_with_limitation() -> None:
    """Bodies above MAX_BODY_TOKENS never enter comparison."""
    lines = ["    step = 1"] * (MAX_BODY_TOKENS + 100)
    source = "def huge():\n" + "\n".join(lines) + "\n"
    result, _, _ = analyze_code({"big.py": source, "small.py": "def s():\n    x = 1\n"})
    outcome = rule_result(result, "CODE-DUPLICATE-CANDIDATE")
    assert outcome.findings == ()
    assert any("tokenization budget" in item.reason for item in outcome.limitations)


def test_coverage_partially_covered_on_partial_module() -> None:
    from app.analyzers.code_structure.analyzer import CodeStructureAnalyzer
    from app.analyzers.security.source import DictSourceProvider
    from app.ncm import NcmFileEntry, NcmRepository
    from tests.fixtures.helpers.analyzer_helpers import make_context, make_module

    module = make_module("half.py", completeness="partially")
    ncm = NcmRepository(
        analysis_id="analysis-1",
        files=[
            NcmFileEntry(path="half.py", language="python", parse_state="parsed", module=module)
        ],
    )
    context = make_context(ncm=ncm)
    analyzer = CodeStructureAnalyzer(DictSourceProvider({}))
    rows = {item.rule_id: item.status.value for item in analyzer.coverage(ncm)}
    assert rows["CODE-HIGH-COMPLEXITY"] == "partially_covered"
    assert rows["CODE-DUPLICATE-CANDIDATE"] == "partially_covered"
    _ = context


def test_coverage_unsupported_without_python() -> None:
    from app.analyzers.code_structure.analyzer import CodeStructureAnalyzer
    from app.analyzers.security.source import DictSourceProvider
    from app.ncm import NcmRepository
    from tests.fixtures.helpers.analyzer_helpers import make_context

    context = make_context(ncm=NcmRepository(analysis_id="analysis-1", files=[]))
    analyzer = CodeStructureAnalyzer(DictSourceProvider({}))
    rows = {item.rule_id: item.status.value for item in analyzer.coverage(context.ncm)}
    assert set(rows.values()) == {"unsupported"}


def test_partial_module_finding_carries_limitation() -> None:
    """A firing rule on a partial module attaches the partial limitation."""
    import dataclasses

    from app.analyzers.code_structure.analyzer import CodeStructureAnalyzer
    from app.analyzers.security.source import DictSourceProvider
    from app.ncm import NcmFileEntry, NcmRepository
    from tests.fixtures.helpers.analyzer_helpers import make_context
    from tests.fixtures.helpers.security_helpers import parse_files

    source = "def work(a, b, c, d, e, f):\n    pass\n"
    ncm = parse_files({"half.py": source})
    (module,) = ncm.modules
    partial = dataclasses.replace(module, completeness="partially")
    ncm_partial = NcmRepository(
        analysis_id="analysis-1",
        files=[
            NcmFileEntry(path="half.py", language="python", parse_state="parsed", module=partial)
        ],
    )
    context = make_context(ncm=ncm_partial)
    analyzer = CodeStructureAnalyzer(DictSourceProvider({"half.py": source}))
    result = analyzer.analyze(context)
    (finding,) = [item for item in result.findings if item.rule_id == "CODE-HIGH-PARAMETER-COUNT"]
    assert any("partially represented" in item.reason for item in finding.limitations)


def test_duplicate_determinism_under_reordered_source() -> None:
    body = "".join(f"    step_{i} = {i}\n" for i in range(20))
    files = {"a.py": f"def f():\n{body}", "b.py": f"def g():\n{body}"}
    first, _, _ = analyze_code(files)
    second, _, _ = analyze_code(dict(reversed(list(files.items()))))
    first_findings = rule_result(first, "CODE-DUPLICATE-CANDIDATE").findings
    second_findings = rule_result(second, "CODE-DUPLICATE-CANDIDATE").findings
    assert len(first_findings) == len(second_findings) == 1
    assert first_findings[0].description == second_findings[0].description
    assert first_findings[0].identity_key == second_findings[0].identity_key


def test_hotspot_determinism_under_reordered_source() -> None:
    first, context_first, analyzer_first = analyze_code(
        {
            "b.py": "def f(a, b, c, d, e, f):\n    pass\n",
            "a.py": "def g(a, b, c, d, e, f):\n    pass\n",
        }
    )
    hotspots_first = analyzer_first.hotspots(context_first)
    _ = first
    from tests.fixtures.helpers.code_structure_helpers import analyze_code as analyze_again

    _second, context_second, analyzer_second = analyze_again(
        {
            "a.py": "def g(a, b, c, d, e, f):\n    pass\n",
            "b.py": "def f(a, b, c, d, e, f):\n    pass\n",
        }
    )
    hotspots_second = analyzer_second.hotspots(context_second)
    assert [(item.path, item.symbol) for item in hotspots_first] == [
        (item.path, item.symbol) for item in hotspots_second
    ]
