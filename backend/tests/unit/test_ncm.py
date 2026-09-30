"""NCM contract tests: repository container, completeness, relationships.

These tests define the analyzer-facing contract (docs/12 §11.4): what
analyzers receive, how completeness is observed, and what is never
fabricated. No parser internals appear here beyond building fixtures.
"""

import pytest

from app.ncm import (
    NcmFileEntry,
    NcmRepository,
    NormalizedModule,
    ParseState,
    Relationship,
    derive_relationships,
    repository_from_dict,
    repository_to_dict,
)
from app.parsers.base import ParserInput
from app.parsers.python_ast import PythonAstAdapter
from app.parsers.tree_sitter import TreeSitterAdapter


def _sample_source() -> bytes:
    """Deterministic sample source for determinism checks."""
    from tests.fixtures.helpers.paths import read_fixture_bytes

    return read_fixture_bytes("parsing", "sample_module.py")


pytestmark = pytest.mark.security


def _parse(source: bytes, path: str = "m.py"):
    return PythonAstAdapter().parse(ParserInput(path, "python", source, 30.0, 1_000_000))


def _entry(path: str, state: str, module=None) -> NcmFileEntry:
    return NcmFileEntry(path=path, language="python", parse_state=state, module=module)


def test_repository_maps_files_to_modules() -> None:
    """Repository → files → modules with analysis-scoped identity."""
    result = _parse(b"import os\n\nX = 1\n", "pkg/mod.py")
    assert result.state == ParseState.PARSED
    assert result.ncm is not None
    repo = NcmRepository(
        analysis_id="a1",
        files=[NcmFileEntry("pkg/mod.py", "python", "parsed", result.ncm)],
    )
    assert repo.modules == [result.ncm]
    assert repo.completeness == "complete"
    assert repo.incomplete_reasons == []
    assert repo.fully_represented_modules == [result.ncm]
    # Identity is path + kind + location based, never object identity.
    assert result.ncm.module.id == "pkg/mod.py"
    assert result.ncm.imports[0].module_id == "pkg/mod.py"


def test_completeness_matrix() -> None:
    """complete/partial/failed/unsupported/unresolved stay distinct."""
    good = _parse(b"x = 1\n", "good.py")
    assert good.ncm is not None
    partial_module = NormalizedModule(
        file_path="part.py",
        language="python",
        module=good.ncm.module,
        completeness="partially",
        parser="python-ast",
        parser_version="x",
    )
    repo = NcmRepository(
        analysis_id="a1",
        files=[
            NcmFileEntry("good.py", "python", "parsed", good.ncm),
            NcmFileEntry("part.py", "python", "parsed_with_diagnostics", partial_module),
            NcmFileEntry("broken.py", "python", "failed", None),
            NcmFileEntry("notes.md", None, "unsupported", None),
        ],
    )
    assert repo.completeness == "incomplete"
    assert repo.incomplete_reasons == [
        "failed: broken.py",
        "unsupported: notes.md",
        "partial: part.py",
    ]
    # Fully-represented view excludes the partial module.
    assert repo.fully_represented_modules == [good.ncm]
    # An empty file set is vacuously complete (nothing unrepresented).
    assert NcmRepository(analysis_id="a1", files=[]).completeness == "complete"


def test_failed_file_contributes_no_module() -> None:
    """Failed parses map to nothing: no empty NCM masquerading as clean."""
    result = _parse(b"def broken(:\n", "broken.py")
    assert result.state == ParseState.FAILED
    assert result.ncm is None
    repo = NcmRepository(
        analysis_id="a1", files=[NcmFileEntry("broken.py", "python", "failed", None)]
    )
    assert repo.modules == []
    assert repo.completeness == "incomplete"
    assert repo.incomplete_reasons == ["failed: broken.py"]


def test_relationships_mirror_concepts_without_duplication() -> None:
    """Unified edges derive from ImportRef/CallSite; bases stay names-only."""
    result = _parse(
        b"import os\nfrom . import mod\n\n"
        b"class Svc(Base):\n    def run(self):\n        return helper(1)\n",
        "svc.py",
    )
    assert result.ncm is not None
    relationships = derive_relationships(result.ncm)
    by_kind: dict[str, list[Relationship]] = {}
    for relationship in relationships:
        by_kind.setdefault(relationship.kind, []).append(relationship)
    assert {r.target_text for r in by_kind["import"]} == {"os", ".mod"}
    assert {r.resolution for r in by_kind["import"]} == {"external", "internal"}
    assert all(r.source_id == "svc.py" for r in by_kind["import"])
    assert [r.target_text for r in by_kind["call"]] == ["helper"]
    assert all(r.resolution == "unresolved" for r in by_kind["call"])
    # Base classes are recorded as names, never fabricated into edges.
    assert result.ncm.classes[0].base_names == ("Base",)
    assert not [r for r in relationships if r.target_text == "Base"]
    # Deterministic order: imports in encounter order, then calls.
    assert [r.kind for r in relationships] == ["import", "import", "call"]


def test_unresolved_reference_recorded_not_fabricated() -> None:
    """Third-party imports stay unresolved with location intact."""
    result = _parse(b"import requests_xyz\n", "m.py")
    assert result.ncm is not None
    (imp,) = result.ncm.imports
    assert imp.resolution == "unresolved"
    (relationship,) = derive_relationships(result.ncm)
    assert relationship.resolution == "unresolved"
    assert relationship.location is not None
    assert relationship.location.start_line == 1


def test_circular_pair_records_no_fabricated_targets() -> None:
    """Resolution test on the circular fixtures (data only, never executed)."""
    from tests.fixtures.helpers.paths import read_fixture_bytes

    modules = {}
    for name in ("circular_alpha.py", "circular_beta.py"):
        source = read_fixture_bytes("architecture", name)
        result = TreeSitterAdapter().parse(ParserInput(name, "python", source, 30.0, 1_000_000))
        assert result.state == ParseState.PARSED
        assert result.ncm is not None
        modules[name] = result.ncm
    alpha_imports = {i.target_text: i.resolution for i in modules["circular_alpha.py"].imports}
    beta_imports = {i.target_text: i.resolution for i in modules["circular_beta.py"].imports}
    # Full reference text as written; both adapters agree on this form.
    assert alpha_imports == {"circular_beta.current_session": "unresolved"}
    assert beta_imports == {"circular_alpha.current_user": "unresolved"}
    # Unresolved is honest per-file state: targets are not fabricated even
    # though both files exist in the repository (resolution is graph scope).
    assert all(
        r.resolution == "unresolved" for r in derive_relationships(modules["circular_alpha.py"])
    )


def test_layer_defaults_unknown_never_invented() -> None:
    """Parsers never assign architectural layers (ARCH-REQ-065)."""
    result = _parse(b"def f():\n    return 1\n", "src/domain/service.py")
    assert result.ncm is not None
    assert result.ncm.module.layer == "unknown"


def test_repository_roundtrip_preserves_everything() -> None:
    """Serialize → deserialize keeps identity, refs, locations, states."""
    result = _parse(b"import os\n\ndef f(a):\n    return g(a)\n", "m.py")
    assert result.ncm is not None
    repo = NcmRepository(
        analysis_id="a1",
        files=[
            NcmFileEntry("m.py", "python", "parsed", result.ncm),
            NcmFileEntry("broken.py", "python", "failed", None),
        ],
    )
    rebuilt = repository_from_dict(repository_to_dict(repo))
    assert rebuilt.analysis_id == "a1"
    assert rebuilt.completeness == "incomplete"
    assert rebuilt.incomplete_reasons == ["failed: broken.py"]
    (module,) = rebuilt.modules
    assert module.module.id == "m.py"
    assert module.functions[0].qualified_name == "m.f"
    assert module.functions[0].location.start_line == 3
    assert module.imports[0].resolution == "external"
    assert module.calls[0].callee_text == "g"


def test_ncm_determinism_across_runs() -> None:
    """Same bytes twice → identical serialized representation."""
    from app.ncm import ncm_to_dict

    source = _sample_source()
    first = _parse(source, "m.py").ncm
    second = _parse(source, "m.py").ncm
    assert first is not None and second is not None
    assert ncm_to_dict(first) == ncm_to_dict(second)


def test_ncm_determinism_across_worker_processes() -> None:
    """Separate worker processes agree on content (duration_ms excluded).

    Wall-clock duration is telemetry, not model data: it is the only
    field allowed to differ between identical runs.
    """
    from app.parsers.runner import run_adapter

    source = _sample_source()
    first = run_adapter("python-ast", "python", "m.py", source, 60.0).to_dict()
    second = run_adapter("python-ast", "python", "m.py", source, 60.0).to_dict()
    assert first["state"] == "parsed" and second["state"] == "parsed"
    first.pop("duration_ms")
    second.pop("duration_ms")
    assert first == second


def test_failure_propagation_distinguishes_unrepresented() -> None:
    """Analyzer-side view: no-finding vs never-represented stay distinct."""
    good = _parse(b"def ok():\n    return 1\n", "good.py")
    assert good.ncm is not None
    repo = NcmRepository(
        analysis_id="a1",
        files=[
            NcmFileEntry("good.py", "python", "parsed", good.ncm),
            NcmFileEntry("broken.py", "python", "failed", None),
        ],
    )
    # A consumer filtering to fully represented modules sees only good.py;
    # the failed file is absent AND the repository is flagged incomplete,
    # so "zero findings here" can never read as "clean repository".
    assert [m.file_path for m in repo.fully_represented_modules] == ["good.py"]
    assert repo.completeness == "incomplete"
    assert repo.incomplete_reasons == ["failed: broken.py"]
    # An empty fully-represented module is still observable as analyzed.
    assert repo.modules[0].functions[0].qualified_name == "good.ok"


def test_partial_module_marks_reduced_completeness() -> None:
    """Partial NCM is usable but explicitly not fully complete."""
    from app.parsers.tree_sitter import TreeSitterAdapter

    source = read_partial_source()
    result = TreeSitterAdapter().parse(ParserInput("part.py", "python", source, 30.0, 1_000_000))
    assert result.state.value == "parsed_with_diagnostics"
    assert result.ncm is not None
    assert result.ncm.completeness == "partially"
    assert result.ncm.module.partially_represented is True
    repo = NcmRepository(
        analysis_id="a1",
        files=[NcmFileEntry("part.py", "python", "parsed_with_diagnostics", result.ncm)],
    )
    assert repo.completeness == "incomplete"
    assert repo.incomplete_reasons == ["partial: part.py"]
    # Usable content survives: recovered functions remain observable.
    assert any(f.qualified_name.endswith("first") for f in result.ncm.functions)


def read_partial_source() -> bytes:
    """Trailing-garbage fixture recovered partially by Tree-sitter."""
    from tests.fixtures.helpers.paths import read_fixture_bytes

    return read_fixture_bytes("parsing", "partial_recovery.py")


def test_unsupported_file_yields_no_module() -> None:
    """Unsupported means no parser attempted, no NCM fabricated."""
    repo = NcmRepository(
        analysis_id="a1",
        files=[NcmFileEntry("app.go", "go", "unsupported", None)],
    )
    assert repo.modules == []
    assert repo.completeness == "incomplete"
    assert repo.incomplete_reasons == ["unsupported: app.go"]
