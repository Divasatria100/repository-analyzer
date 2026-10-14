"""Duplicate-candidate detection over normalized body token streams (TASK-138).

Comparison units are function/method bodies located by NCM; token streams
come from :mod:`app.analyzers.code_structure.tokens`. A candidate group is
a set of bodies sharing an identical normalized contiguous run of at least
``minimum_tokens`` tokens (contract: ``>= minimum``, V1.0 default 50 —
docs/10 §5.14A CODE-REQ-004; this differs deliberately from the strict-``
>`` used by every other threshold, and the difference is recorded on every
finding via the applied threshold basis).

Algorithm (deterministic, bounded — no naive all-pairs token comparison):

* bodies shorter than the minimum, trivial bodies (empty/``pass``/``...``),
  and untokenizable bodies are excluded up front (with counts, never silent
  when they affect coverage);
* sliding windows of ``minimum_tokens`` tokens are hashed (SHA-256 over the
  joined sequence; the hash is an index only, never the reported length);
* each distinct window shared by ≥2 bodies yields one candidate member set;
  identical member sets from different windows merge into a single group —
  every group therefore shares at least one full window, and no finding
  ever rests on transitive-only linkage;
* the reported matched length per member is the exact longest common
  contiguous run against the primary, computed with a bounded budget;
  members beyond the budget report the ``>= minimum`` lower bound with an
  explicit flag instead of a fabricated exact length;
* the number of groups is capped (sorted first-N) with a recorded
  limitation when the cap binds.

Resource guards (module constants, asserted in tests): at most
``MAX_DUPLICATE_BODIES`` bodies enter comparison (sorted first-N; the rest
are skipped with a recorded limitation), bodies above ``MAX_BODY_TOKENS``
tokens are skipped likewise, and exact-length computation stops after
``MAX_LCS_PAIRS`` pairs / ``MAX_LCS_CELLS`` DP cells.
"""

from __future__ import annotations

import hashlib

from app.analyzers.code_structure.models import DuplicateGroup, DuplicateLocation

#: Minimum shared run length comes from the centralized threshold
#: (``ThresholdSet.duplicate_tokens``); the comparison is ``>=`` per
#: CODE-REQ-004, unlike every other strict-``>`` threshold in the set.
#: Maximum bodies entering comparison (sorted first-N; rest limited).
MAX_DUPLICATE_BODIES = 2000
#: Bodies larger than this are skipped with a recorded limitation.
MAX_BODY_TOKENS = 10000
#: Exact-length pair budget and DP-cell budget for longest-run computation.
MAX_LCS_PAIRS = 200
MAX_LCS_CELLS = 100000
#: Maximum candidate groups reported (sorted first-N; rest limited).
MAX_DUPLICATE_GROUPS = 50


def window_hashes(tokens: tuple[str, ...], width: int) -> set[str]:
    """SHA-256 of every contiguous ``width``-token window (index only)."""
    hashes: set[str] = set()
    if width <= 0 or len(tokens) < width:
        return hashes
    for start in range(len(tokens) - width + 1):
        digest = hashlib.sha256("\x00".join(tokens[start : start + width]).encode()).hexdigest()
        hashes.add(digest)
    return hashes


def longest_common_run(first: tuple[str, ...], second: tuple[str, ...]) -> int:
    """Length of the longest common contiguous token run (bounded DP)."""
    if not first or not second:
        return 0
    if len(first) * len(second) > MAX_LCS_CELLS:
        return -1  # over budget: caller reports the lower bound instead
    shorter, longer = (first, second) if len(first) <= len(second) else (second, first)
    previous = [0] * (len(shorter) + 1)
    best = 0
    for token in longer:
        current = [0] * (len(shorter) + 1)
        for position, other in enumerate(shorter, start=1):
            if token == other:
                current[position] = previous[position - 1] + 1
                if current[position] > best:
                    best = current[position]
        previous = current
    return best


def group_candidates(
    bodies: list[tuple[str, str, int, int, tuple[str, ...]]],
    minimum_tokens: int,
) -> tuple[list[DuplicateGroup], dict[str, object]]:
    """Group bodies sharing a ``minimum_tokens`` normalized run.

    ``bodies`` entries are ``(path, qualified_name, start_line, end_line,
    tokens)`` in any order; output groups are deterministic. Returns
    ``(groups, stats)`` where stats carries counts for coverage reporting.
    """
    ordered = sorted(bodies, key=lambda item: (item[0], item[2], item[1]))
    owners: dict[str, set[int]] = {}
    for position, (_path, _name, _start, _end, tokens) in enumerate(ordered):
        for digest in window_hashes(tokens, minimum_tokens):
            owners.setdefault(digest, set()).add(position)
    member_sets: dict[frozenset[int], None] = {}
    for digest in sorted(owners):
        positions = owners[digest]
        if len(positions) >= 2:
            member_sets.setdefault(frozenset(positions), None)
    ordered_sets = sorted(member_sets, key=lambda item: sorted(item))
    groups: list[DuplicateGroup] = []
    pairs_used = 0
    capped = False
    groups_capped = False
    for member_set in ordered_sets:
        if len(groups) >= MAX_DUPLICATE_GROUPS:
            groups_capped = True
            break
        members = sorted(member_set)
        primary_tokens = ordered[members[0]][4]
        locations: list[DuplicateLocation] = []
        exact = True
        for position in members[1:]:
            path, name, start, end, tokens = ordered[position]
            if pairs_used >= MAX_LCS_PAIRS:
                exact = False
                capped = True
                length = None
            else:
                pairs_used += 1
                run = longest_common_run(primary_tokens, tokens)
                if run < 0:
                    exact = False
                    capped = True
                    length = None
                else:
                    length = run
            locations.append(
                DuplicateLocation(
                    path=path,
                    qualified_name=name,
                    start_line=start,
                    end_line=end,
                    matched_tokens=length,
                )
            )
        known_lengths = [
            item.matched_tokens for item in locations if item.matched_tokens is not None
        ]
        # Every listed member shares a full window with the primary, so each
        # computed length is at least the minimum; the group length is the
        # smallest of them (never inflated by an unrelated longer run).
        primary_length: int | None = min(known_lengths) if known_lengths else None
        if primary_length is None:
            exact = False
        first = ordered[members[0]]
        locations.insert(
            0,
            DuplicateLocation(
                path=first[0],
                qualified_name=first[1],
                start_line=first[2],
                end_line=first[3],
                matched_tokens=primary_length,
            ),
        )
        matched = primary_length if primary_length is not None else minimum_tokens
        groups.append(
            DuplicateGroup(
                members=tuple(locations),
                matched_tokens=matched,
                exact=exact,
            )
        )
    groups.sort(key=lambda group: [(item.path, item.start_line) for item in group.members])
    stats: dict[str, object] = {
        "pairs_used": pairs_used,
        "capped": capped,
        "groups_capped": groups_capped,
    }
    return groups, stats
