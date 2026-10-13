"""Dependency analysis domain (Phase 8, TASK-112–121).

Static manifest/lockfile analysis: discovery, ecosystem detection,
normalized occurrences, direct/transitive classification, local detections
(duplicate versions, high count, unused candidates), OSV advisory matching,
and normalized findings through the common Finding model. Manifests are
data — never installed, executed, imported, or resolved.
"""

from app.analyzers.dependency.analyzer import (
    DependencyAnalyzer,
    DictManifestProvider,
    ManifestProvider,
    WorkspaceManifestProvider,
    build_inventory,
    dependency_provider_from_workspace,
)

__all__ = [
    "DependencyAnalyzer",
    "DictManifestProvider",
    "ManifestProvider",
    "WorkspaceManifestProvider",
    "build_inventory",
    "dependency_provider_from_workspace",
]
