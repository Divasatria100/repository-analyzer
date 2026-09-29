"""Archive extraction tests: containment + incremental caps (no git needed).

Tarballs are built in-memory; extraction must reject escapes/symlinks and
enforce per-file, total, count, and depth limits without silent truncation.
"""

import io
import tarfile
from collections.abc import Sequence
from pathlib import Path

import pytest

from app.repository.errors import RetrievalSizeLimitError
from app.repository.retrieval import ExtractionLimits, extract_tar_stream

pytestmark = pytest.mark.security


def _limits(
    max_total_bytes: int = 1_000_000,
    max_file_bytes: int = 100_000,
    max_files: int = 100,
    max_depth: int = 8,
) -> ExtractionLimits:
    return ExtractionLimits(
        max_total_bytes=max_total_bytes,
        max_file_bytes=max_file_bytes,
        max_files=max_files,
        max_depth=max_depth,
    )


def _tar(members: Sequence[tuple[str, bytes | None, str]]) -> io.BytesIO:
    """Build a tar: (name, data|None, kind=file|symlink|dir)."""
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w") as archive:
        for name, data, kind in members:
            info = tarfile.TarInfo(name)
            if kind == "dir":
                info.type = tarfile.DIRTYPE
                archive.addfile(info)
            elif kind == "symlink":
                info.type = tarfile.SYMTYPE
                info.linkname = "target.py"
                archive.addfile(info)
            else:
                payload = data or b""
                info.size = len(payload)
                archive.addfile(info, io.BytesIO(payload))
    stream.seek(0)
    return stream


def test_clean_tree_extracts(tmp_path: Path) -> None:
    dest = tmp_path / "ws"
    dest.mkdir()
    report = extract_tar_stream(
        _tar([("pkg/", None, "dir"), ("pkg/mod.py", b"x = 1\n", "file")]),
        dest,
        _limits(),
    )
    assert report.files_extracted == 1
    assert (dest / "pkg" / "mod.py").read_text(encoding="utf-8") == "x = 1\n"


@pytest.mark.parametrize(
    "name",
    ["../evil.py", "/absolute.py", "C:/win.py", "\\\\unc\\share.py", "a/../../b.py"],
)
def test_escape_paths_skipped_never_written(tmp_path: Path, name: str) -> None:
    dest = tmp_path / "ws"
    dest.mkdir()
    report = extract_tar_stream(_tar([(name, b"evil", "file")]), dest, _limits())
    assert report.files_extracted == 0
    assert report.skipped_entries == [name]
    assert (tmp_path / "evil.py").exists() is False


def test_symlinks_recorded_never_created(tmp_path: Path) -> None:
    dest = tmp_path / "ws"
    dest.mkdir()
    report = extract_tar_stream(_tar([("link.py", None, "symlink")]), dest, _limits())
    assert report.files_extracted == 0
    assert (dest / "link.py").exists() is False
    assert report.skipped_entries == ["link.py"]


def test_per_file_limit_enforced(tmp_path: Path) -> None:
    dest = tmp_path / "ws"
    dest.mkdir()
    with pytest.raises(RetrievalSizeLimitError):
        extract_tar_stream(_tar([("big.bin", b"x" * 200_000, "file")]), dest, _limits())
    assert (dest / "big.bin").exists() is False or (dest / "big.bin").stat().st_size <= 100_000


def test_total_bytes_limit_enforced(tmp_path: Path) -> None:
    dest = tmp_path / "ws"
    dest.mkdir()
    members = [(f"f{i}.txt", b"x" * 10_000, "file") for i in range(5)]
    with pytest.raises(RetrievalSizeLimitError):
        extract_tar_stream(_tar(members), dest, _limits(max_total_bytes=25_000))


def test_file_count_limit_enforced(tmp_path: Path) -> None:
    dest = tmp_path / "ws"
    dest.mkdir()
    members = [(f"f{i}.txt", b"x", "file") for i in range(5)]
    with pytest.raises(RetrievalSizeLimitError):
        extract_tar_stream(_tar(members), dest, _limits(max_files=3))


def test_depth_limit_enforced(tmp_path: Path) -> None:
    dest = tmp_path / "ws"
    dest.mkdir()
    deep = "/".join(["d"] * 10 + ["deep.py"])
    report = extract_tar_stream(_tar([(deep, b"x", "file")]), dest, _limits(max_depth=8))
    assert report.files_extracted == 0
    assert report.skipped_entries == [deep]


def test_gitmodules_flags_submodules(tmp_path: Path) -> None:
    dest = tmp_path / "ws"
    dest.mkdir()
    report = extract_tar_stream(_tar([(".gitmodules", b"[submodule]\n", "file")]), dest, _limits())
    assert report.submodules_present is True
    assert report.files_extracted == 1
