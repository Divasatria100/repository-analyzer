"""Circular dependency detection over the architecture graph (TASK-128).

Deterministic iterative Tarjan strongly-connected-components: each SCC of
size > 1 is one circular-dependency group (ARCH-REQ-040: unrelated cycles
are never merged); a self-loop is a single-node cycle reported distinctly.
No enumeration of all simple cycles (bounded output by construction).

For each group exactly one demonstrative closed path is produced
(ARCH-REQ-041): a deterministic depth-first walk from the smallest member
following smallest-successor order, rotated to start at the smallest
member. Rotations of one cycle therefore never become separate findings.
"""

from __future__ import annotations

from dataclasses import dataclass

from app.analyzers.architecture.models import ArchGraph


@dataclass(frozen=True)
class CycleGroup:
    """One circular-dependency group with a demonstrative closed path."""

    members: tuple[str, ...]  # sorted participating module ids
    path: tuple[str, ...]  # closed walk, first == last, canonical rotation
    self_loop: bool = False
    edge_count: int = 0  # internal edges inside the group (bounded context)


def strongly_connected_components(graph: ArchGraph) -> list[list[str]]:
    """Iterative Tarjan SCCs; each component sorted, order deterministic."""
    index_of: dict[str, int] = {}
    lowlink: dict[str, int] = {}
    on_stack: set[str] = set()
    stack: list[str] = []
    components: list[list[str]] = []
    counter = 0
    successors = {node: graph.successors(node) for node in sorted(graph.nodes)}

    for root in sorted(graph.nodes):
        if root in index_of:
            continue
        work: list[tuple[str, int]] = [(root, 0)]
        while work:
            node, child_pos = work[-1]
            if child_pos == 0 and node not in index_of:
                index_of[node] = lowlink[node] = counter
                counter += 1
                stack.append(node)
                on_stack.add(node)
            advanced = False
            children = successors[node]
            for pos in range(child_pos, len(children)):
                child = children[pos]
                if child not in index_of:
                    work[-1] = (node, pos + 1)
                    work.append((child, 0))
                    advanced = True
                    break
                if child in on_stack and index_of[child] < lowlink[node]:
                    lowlink[node] = index_of[child]
            if advanced:
                continue
            work.pop()
            if work:
                parent = work[-1][0]
                if lowlink[node] < lowlink[parent]:
                    lowlink[parent] = lowlink[node]
            if lowlink[node] == index_of[node]:
                component: list[str] = []
                while True:
                    member = stack.pop()
                    on_stack.discard(member)
                    component.append(member)
                    if member == node:
                        break
                components.append(sorted(component))
    components.sort()
    return components


def _closed_path(graph: ArchGraph, members: list[str]) -> tuple[str, ...]:
    """One deterministic closed walk through every member, canonically rotated."""
    inside = set(members)
    start = members[0]
    # Greedy walk covering all members: always the smallest unvisited
    # reachable member, else the smallest successor; deterministic.
    walk = [start]
    visited = {start}
    current = start
    guard = len(members) * len(members) + len(members) + 1
    while len(visited) < len(inside) and guard > 0:
        guard -= 1
        options = sorted(target for target in graph.successors(current) if target in inside)
        if not options:
            break
        unvisited = [item for item in options if item not in visited]
        current = unvisited[0] if unvisited else options[0]
        walk.append(current)
        visited.add(current)
    # Close the walk back to the start through member edges.
    guard = len(members) + 1
    while walk[-1] != start and guard > 0:
        guard -= 1
        options = sorted(target for target in graph.successors(walk[-1]) if target in inside)
        if not options:
            break
        current = start if start in options else options[0]
        walk.append(current)
    if walk[-1] != start:
        walk.append(start)
    return tuple(walk)


def find_cycles(graph: ArchGraph) -> list[CycleGroup]:
    """Detect circular-dependency groups (SCC size > 1 plus self-loops)."""
    groups: list[CycleGroup] = []
    for component in strongly_connected_components(graph):
        if len(component) > 1:
            internal = sum(
                1
                for source in component
                for target in graph.successors(source)
                if target in set(component)
            )
            groups.append(
                CycleGroup(
                    members=tuple(component),
                    path=_closed_path(graph, component),
                    self_loop=False,
                    edge_count=internal,
                )
            )
    for node in sorted(graph.nodes):
        if graph.has_self_loop(node):
            groups.append(
                CycleGroup(
                    members=(node,),
                    path=(node, node),
                    self_loop=True,
                    edge_count=1,
                )
            )
    groups.sort(key=lambda group: (group.members, group.path))
    return groups
