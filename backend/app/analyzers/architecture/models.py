"""Architecture analysis value objects (Phase 9, TASK-123/124/133).

Pure data over the Normalized Code Model: source-unit extraction products,
the directed architecture dependency graph, metrics, and serialization
records. No parsers, no I/O, no network — deterministic transformations of
NCM input only.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class ArchModule:
    """One architecture source unit: a parsed Python file (ARCH-REQ-009–011).

    Identity is the repository-relative file path (never the bare basename,
    which collides across directories). Only successfully parsed Python
    modules become nodes; failed/unsupported files never do.
    """

    id: str  # == path; stable, collision-safe module identity
    path: str  # repository-relative file path
    language: str = "python"
    partially_represented: bool = False


@dataclass(frozen=True)
class ArchEdge:
    """One directed module dependency: importer → imported (ARCH-REQ-013/019).

    Deduplicated per ordered pair (ARCH-REQ-016); every establishing import
    site is preserved as evidence locations (sorted, stable).
    """

    source: str  # importing module id (dependent)
    target: str  # imported module id (dependency)
    locations: tuple[tuple[str, int, int], ...] = ()  # (path, line, column) evidence
    conditional: bool = False  # any establishing import is conditional
    deferred: bool = False  # any establishing import is deferred


@dataclass(frozen=True)
class UnresolvedImport:
    """An import that could not become an internal edge (ARCH-REQ-015)."""

    path: str  # importing file
    target_text: str  # import as written
    reason: str  # external | unresolved | unmapped-internal
    line: int
    column: int = 0


@dataclass
class ArchGraph:
    """Directed architecture graph: modules plus internal edges.

    Adjacency is served from a frozen index once :meth:`freeze_index` runs
    (called at the end of graph construction), giving O(1) neighbor lookups
    without per-node full-edge scans. Before freezing, neighbor sets are
    derived on demand exactly as before, so directly constructed graphs keep
    working. Iteration order is always path-sorted so results never depend
    on insertion order. Self-loops are preserved as edges but excluded from
    neighbor sets used by fan/coupling metrics (documented in metrics.py).
    """

    nodes: dict[str, ArchModule] = field(default_factory=dict)
    edges: dict[tuple[str, str], ArchEdge] = field(default_factory=dict)
    truncated: bool = False
    truncation_reason: str = ""
    _successor_index: dict[str, tuple[str, ...]] | None = field(
        default=None, repr=False, compare=False
    )
    _predecessor_index: dict[str, tuple[str, ...]] | None = field(
        default=None, repr=False, compare=False
    )

    def freeze_index(self) -> None:
        """Build the shared adjacency index in one O(V + E) pass.

        Idempotent: rebuilding an already-frozen graph yields the same index.
        Must be called after the edge collection is final; later edge
        mutations are not reflected (construction freezes before analysis).
        """
        successors: dict[str, set[str]] = {}
        predecessors: dict[str, set[str]] = {}
        for source, target in self.edges:
            if source != target:
                successors.setdefault(source, set()).add(target)
                predecessors.setdefault(target, set()).add(source)
        self._successor_index = {
            node: tuple(sorted(neighbors)) for node, neighbors in successors.items()
        }
        self._predecessor_index = {
            node: tuple(sorted(neighbors)) for node, neighbors in predecessors.items()
        }

    @property
    def index_frozen(self) -> bool:
        """True when neighbor lookups are served from the shared index."""
        return self._successor_index is not None and self._predecessor_index is not None

    def successors(self, node: str) -> tuple[str, ...]:
        """Distinct internal modules ``node`` depends on (self excluded)."""
        if self._successor_index is not None:
            return self._successor_index.get(node, ())
        return tuple(
            sorted({target for (source, target) in self.edges if source == node and target != node})
        )

    def predecessors(self, node: str) -> tuple[str, ...]:
        """Distinct internal modules depending on ``node`` (self excluded)."""
        if self._predecessor_index is not None:
            return self._predecessor_index.get(node, ())
        return tuple(
            sorted({source for (source, target) in self.edges if target == node and source != node})
        )

    def has_self_loop(self, node: str) -> bool:
        """True when the module statically imports itself."""
        return (node, node) in self.edges

    def sorted_nodes(self) -> list[ArchModule]:
        """Nodes in stable path order."""
        return [self.nodes[key] for key in sorted(self.nodes)]

    def sorted_edges(self) -> list[ArchEdge]:
        """Edges in stable (source, target) order."""
        return [self.edges[key] for key in sorted(self.edges)]


@dataclass(frozen=True)
class MetricValue:
    """One computed metric with availability and completeness tracking."""

    name: str
    subject: str  # module id, qualified class/function name, or repository
    value: int | None  # None means unavailable (ARCH-REQ-027: never zero)
    potentially_incomplete: bool = False
    basis: str = ""  # documented counting basis (ARCH-REQ-025/034)


@dataclass(frozen=True)
class ExtractionReport:
    """Extraction outcome: graph plus explicit diagnostics (TASK-123)."""

    graph: ArchGraph
    unresolved: tuple[UnresolvedImport, ...] = ()
    external_count: int = 0
    skipped_files: tuple[str, ...] = ()
    partial_modules: tuple[str, ...] = ()
    failed_files: tuple[str, ...] = ()
    unsupported_files: tuple[str, ...] = ()
    limited: bool = False
    limitation_reasons: tuple[str, ...] = ()
