"""Language detection tests: recognition matrix + support states (TASK-061/062).

Classification only — files are never executed or imported. Support set is
Python-only per docs/09 §10.2; every other recognized language is recorded
as unsupported, never as clean and never as a parse failure.
"""

from pathlib import Path

import pytest

from app.repository.indexing import (
    SUPPORTED_LANGUAGES,
    detect_language,
    walk_workspace,
)

pytestmark = pytest.mark.security


@pytest.mark.parametrize(
    ("filename", "expected"),
    [
        ("main.py", "python"),
        ("MAIN.PY", "python"),
        ("App.Py", "python"),
        ("app.js", "javascript"),
        ("app.jsx", "javascript"),
        ("app.ts", "typescript"),
        ("app.tsx", "typescript"),
        ("Main.java", "java"),
        ("index.php", "php"),
        ("main.go", "go"),
        ("lib.rs", "rust"),
        ("app.rb", "ruby"),
        ("app.dart", "dart"),
        ("main.c", "c"),
        ("util.h", "c"),
        ("x.cpp", "cpp"),
        ("x.cs", "csharp"),
        ("x.swift", "swift"),
        ("x.kt", "kotlin"),
        ("run.sh", "shell"),
        ("q.sql", "sql"),
        ("doc.xml", "xml"),
        ("a.css", "css"),
        ("a.html", "html"),
        ("a.json", "json"),
        ("a.yaml", "yaml"),
        ("a.yml", "yaml"),
        ("a.toml", "toml"),
        ("a.ini", "ini"),
        ("a.md", "markdown"),
        ("a.rst", "rst"),
    ],
)
def test_extension_matrix(filename: str, expected: str) -> None:
    assert detect_language(filename) == expected


@pytest.mark.parametrize("filename", ["archive.xyz", "noextension", ".hidden", "a"])
def test_unknown_extensions_unrecognized(filename: str) -> None:
    assert detect_language(filename) is None


def test_support_set_is_python_only() -> None:
    assert SUPPORTED_LANGUAGES == frozenset({"python"})


def test_support_states_end_to_end(tmp_path: Path) -> None:
    from app.repository.indexing import classify_file

    root = tmp_path / "ws"
    (root / "sub").mkdir(parents=True)
    (root / "a.py").write_text("x = 1\n", encoding="utf-8")
    (root / "b.js").write_text("var x = 1;\n", encoding="utf-8")
    (root / "c.xyz").write_text("???\n", encoding="utf-8")
    (root / "d.bin").write_bytes(b"\x00\x01\x02binary")
    (root / "e.PY").write_text("y = 2\n", encoding="utf-8")
    (root / "Dockerfile").write_text("FROM x\n", encoding="utf-8")
    (root / "pkg.json").write_text("{}\n", encoding="utf-8")
    (root / "notes.md").write_text("# hi\n", encoding="utf-8")
    (root / "req.txt").write_text("a==1\n", encoding="utf-8")
    entries, limitations, complete = walk_workspace(root, max_files=20000, max_depth=32)
    assert complete is True
    assert limitations == []
    by_path = {
        entry.relative_path: classify_file(root, entry, file_max_bytes=1_000_000)
        for entry in entries
    }
    assert by_path["a.py"].support_status == "supported"
    assert by_path["a.py"].language == "python"
    assert by_path["a.py"].eligibility == "eligible"
    assert by_path["e.PY"].support_status == "supported"
    assert by_path["b.js"].support_status == "unsupported"
    assert by_path["b.js"].language == "javascript"
    assert by_path["b.js"].eligibility == "not_eligible"
    assert by_path["c.xyz"].support_status == "unrecognized"
    assert by_path["c.xyz"].language is None
    assert by_path["d.bin"].support_status == "binary"
    assert by_path["d.bin"].is_binary is True
    assert by_path["d.bin"].eligibility == "not_eligible"
    assert by_path["Dockerfile"].file_type == "configuration"
    assert by_path["Dockerfile"].support_status == "unsupported"
    assert by_path["pkg.json"].file_type == "configuration"
    assert by_path["notes.md"].file_type == "documentation"
    assert by_path["req.txt"].file_type == "documentation"


def test_manifest_roles_and_generated_flag(tmp_path: Path) -> None:
    from app.repository.indexing import classify_file

    root = tmp_path / "ws"
    root.mkdir()
    (root / "requirements.txt").write_text("a==1\n", encoding="utf-8")
    (root / "package.json").write_text("{}\n", encoding="utf-8")
    (root / "app.min.js").write_text("var x=1\n", encoding="utf-8")
    (root / "plain.js").write_text("var y=2\n", encoding="utf-8")
    (root / "gen_util.py").write_text("z = 3\n", encoding="utf-8")
    (root / "made_generated.py").write_text("w = 4\n", encoding="utf-8")
    entries, _, _ = walk_workspace(root, max_files=20000, max_depth=32)
    by_path = {
        entry.relative_path: classify_file(root, entry, file_max_bytes=1_000_000)
        for entry in entries
    }
    assert by_path["requirements.txt"].file_type == "manifest"
    assert by_path["requirements.txt"].eligibility == "not_eligible"
    assert "dependency analysis" in by_path["requirements.txt"].eligibility_reason
    assert by_path["package.json"].file_type == "manifest"
    assert by_path["app.min.js"].is_generated is True
    # Unsupported language takes precedence: generated but not parser-eligible.
    assert by_path["app.min.js"].eligibility == "not_eligible"
    assert by_path["plain.js"].is_generated is False
    # Generated Python stays eligible with the treatment recorded in the reason.
    assert by_path["made_generated.py"].is_generated is True
    assert by_path["made_generated.py"].eligibility == "eligible"
    assert "generated" in by_path["made_generated.py"].eligibility_reason
    assert by_path["gen_util.py"].is_generated is False


def test_binary_python_extension_never_supported(tmp_path: Path) -> None:
    from app.repository.indexing import classify_file

    root = tmp_path / "ws"
    root.mkdir()
    (root / "evil.py").write_bytes(b"\x00\x01potentially hostile")
    entries, _, _ = walk_workspace(root, max_files=20000, max_depth=32)
    record = classify_file(root, entries[0], file_max_bytes=1_000_000)
    assert record.support_status == "binary"
    assert record.eligibility == "not_eligible"
