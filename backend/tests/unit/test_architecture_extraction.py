"""Architecture extraction tests (TASK-123).

Modules come from parsed Python NCM entries keyed by repository-relative
path. Failed/unsupported/non-Python entries never become modules; every
gap is an explicit diagnostic.
"""

from app.analyzers.architecture.modules import extract_modules
from tests.fixtures.helpers.security_helpers import parse_files


def test_empty_repository_extracts_nothing() -> None:
    modules, diagnostics = extract_modules(parse_files({}))
    assert modules == {}
    assert diagnostics.failed_files == []
    assert diagnostics.incomplete is False


def test_single_module_repository() -> None:
    modules, diagnostics = extract_modules(parse_files({"solo.py": "VALUE = 1\n"}))
    assert list(modules) == ["solo.py"]
    assert modules["solo.py"].id == "solo.py"
    assert diagnostics.incomplete is False


def test_duplicate_basenames_stay_distinct() -> None:
    modules, _ = extract_modules(
        parse_files({"pkg/a/utils.py": "X = 1\n", "pkg/b/utils.py": "Y = 2\n"})
    )
    assert sorted(modules) == ["pkg/a/utils.py", "pkg/b/utils.py"]
    assert modules["pkg/a/utils.py"].id != modules["pkg/b/utils.py"].id


def test_extraction_is_deterministic() -> None:
    files = {"b.py": "import a\n", "a.py": "X = 1\n", "pkg/c.py": "import a\n"}
    first, _ = extract_modules(parse_files(files))
    second, _ = extract_modules(parse_files(dict(reversed(list(files.items())))))
    assert list(first) == list(second) == ["a.py", "b.py", "pkg/c.py"]


def test_unresolved_imports_do_not_become_modules() -> None:
    modules, _ = extract_modules(parse_files({"app.py": "import missing_lib\n"}))
    assert list(modules) == ["app.py"]


def test_failed_files_become_diagnostics_not_modules() -> None:
    modules, diagnostics = extract_modules(parse_files({"broken.py": "def broken(:\n"}))
    assert modules == {}
    assert diagnostics.failed_files == ["broken.py"]
    assert diagnostics.incomplete is True
    assert any("broken.py" in reason for reason in diagnostics.reasons())


def test_unsupported_language_is_recorded() -> None:
    from app.ncm import NcmFileEntry, NcmRepository

    ncm = NcmRepository(
        analysis_id="analysis-1",
        files=[
            NcmFileEntry(
                path="app.js", language="javascript", parse_state="unsupported", module=None
            )
        ],
    )
    modules, diagnostics = extract_modules(ncm)
    assert modules == {}
    assert diagnostics.unsupported_files == ["app.js"]
    assert any("not treated as clean" in reason for reason in diagnostics.reasons())


def test_package_initializer_is_its_own_module() -> None:
    modules, _ = extract_modules(
        parse_files(
            {"pkg/__init__.py": "from .core import run\n", "pkg/core.py": "def run(): ...\n"}
        )
    )
    assert sorted(modules) == ["pkg/__init__.py", "pkg/core.py"]


def test_partial_modules_flagged() -> None:
    from app.ncm import NcmFileEntry, NcmRepository
    from tests.fixtures.helpers.analyzer_helpers import make_module

    module = make_module("half.py", completeness="partially")
    ncm = NcmRepository(
        analysis_id="analysis-1",
        files=[
            NcmFileEntry(path="half.py", language="python", parse_state="parsed", module=module)
        ],
    )
    modules, diagnostics = extract_modules(ncm)
    assert modules["half.py"].partially_represented is True
    assert diagnostics.partial_modules == ["half.py"]
    assert diagnostics.incomplete is True
