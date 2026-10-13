"""Architecture module extraction from NCM (TASK-123).

Pure transformation: successfully parsed Python file entries become
source units keyed by repository-relative path. Failed, unsupported, and
non-Python entries never become modules; they are reported through
diagnostics so absence of information is never confused with absence of
structure (ARCH-REQ-108/109/111).
"""

from __future__ import annotations

from app.analyzers.architecture.models import ArchModule
from app.ncm import NcmRepository, NormalizedModule

#: The only language architecture analysis supports in V1.0 (docs/08 §10.1).
SUPPORTED_LANGUAGE = "python"


def extract_modules(ncm: NcmRepository) -> tuple[dict[str, ArchModule], ExtractionDiagnostics]:
    """Build path-keyed architecture modules plus extraction diagnostics."""
    modules: dict[str, ArchModule] = {}
    diagnostics = ExtractionDiagnostics()
    for entry in sorted(ncm.files, key=lambda item: item.path):
        language = (entry.language or "").lower()
        state = entry.parse_state
        module = entry.module
        if module is None or language != SUPPORTED_LANGUAGE:
            if state == "failed":
                diagnostics.failed_files.append(entry.path)
            elif state in ("unsupported",):
                diagnostics.unsupported_files.append(entry.path)
            elif module is None and language != SUPPORTED_LANGUAGE:
                diagnostics.unsupported_files.append(entry.path)
            else:
                diagnostics.skipped_files.append(entry.path)
            continue
        if entry.path in modules:
            diagnostics.duplicate_paths.append(entry.path)
            continue
        partial = module.completeness != "fully"
        modules[entry.path] = ArchModule(
            id=entry.path,
            path=entry.path,
            language=language,
            partially_represented=partial,
        )
        if partial:
            diagnostics.partial_modules.append(entry.path)
    diagnostics.sort()
    return modules, diagnostics


class ExtractionDiagnostics:
    """Mutable collection of extraction-time observations (sorted on use)."""

    def __init__(self) -> None:
        self.failed_files: list[str] = []
        self.unsupported_files: list[str] = []
        self.skipped_files: list[str] = []
        self.partial_modules: list[str] = []
        self.duplicate_paths: list[str] = []

    def sort(self) -> None:
        """Deterministic order for every diagnostic list."""
        self.failed_files.sort()
        self.unsupported_files.sort()
        self.skipped_files.sort()
        self.partial_modules.sort()
        self.duplicate_paths.sort()

    @property
    def incomplete(self) -> bool:
        """True when any file could not contribute a full module."""
        return bool(self.failed_files or self.partial_modules)

    def reasons(self) -> list[str]:
        """Human-readable limitation reasons in stable order."""
        self.sort()
        reasons: list[str] = []
        for path in self.failed_files:
            reasons.append(f"{path}: file failed to parse; not represented as a module")
        for path in self.partial_modules:
            reasons.append(f"{path}: module is only partially represented")
        for path in self.unsupported_files:
            reasons.append(f"{path}: unsupported for architecture analysis; not treated as clean")
        for path in self.skipped_files:
            reasons.append(f"{path}: skipped during extraction; not treated as clean")
        for path in self.duplicate_paths:
            reasons.append(f"{path}: duplicate module path encountered once")
        return reasons


def module_for_predicate(module: NormalizedModule) -> bool:
    """True when an NCM module is eligible as an architecture source unit."""
    return (module.language or "").lower() == SUPPORTED_LANGUAGE
