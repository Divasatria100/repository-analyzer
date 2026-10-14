"""Token normalization and duplicate grouping tests (TASK-138)."""

from app.analyzers.code_structure.duplicates import (
    group_candidates,
    longest_common_run,
    window_hashes,
)
from app.analyzers.code_structure.tokens import (
    body_text,
    is_trivial_sequence,
    normalize_body_tokens,
)


def test_normalization_strips_comments_and_whitespace() -> None:
    locals_ = frozenset({"x", "y"})
    first = normalize_body_tokens("x = 1  # comment\n\ny = 2\n", local_names=locals_)
    second = normalize_body_tokens("x=1\ny=2\n", local_names=locals_)
    assert first is not None and second is not None
    assert first == second


def test_local_names_become_positional_placeholders() -> None:
    tokens = normalize_body_tokens(
        "alpha = 1\nbeta = alpha + 2\n", local_names=frozenset({"alpha", "beta"})
    )
    assert tokens is not None
    assert tokens[0] == "VAR0"
    assert "alpha" not in tokens and "beta" not in tokens
    renamed = normalize_body_tokens(
        "gamma = 1\ndelta = gamma + 2\n", local_names=frozenset({"gamma", "delta"})
    )
    assert renamed == tokens


def test_unlisted_names_stay_literal() -> None:
    """Names not positively identified as local are never force-matched."""
    tokens = normalize_body_tokens("alpha = 1\n", local_names=frozenset())
    assert tokens is not None
    assert tokens[0] == "alpha"
    other = normalize_body_tokens("beta = 1\n", local_names=frozenset())
    assert other is not None
    assert other[0] == "beta"
    assert tokens != other


def test_keywords_attributes_literals_preserved() -> None:
    tokens = normalize_body_tokens(
        'if x:\n    obj.attr = "hi"\n    return 42\n', local_names=frozenset({"x", "obj"})
    )
    assert tokens is not None
    assert "if" in tokens and "return" in tokens
    assert "attr" in tokens
    assert '"hi"' in tokens
    assert "42" in tokens
    assert "x" not in tokens and "obj" not in tokens


def test_loop_variables_stay_literal_without_ncm_evidence() -> None:
    """`for`-targets are not recorded in NCM: they must not be normalized."""
    first = normalize_body_tokens(
        "for i in range(3):\n    show(i)\n", local_names=frozenset({"show"})
    )
    second = normalize_body_tokens(
        "for j in range(3):\n    show(j)\n", local_names=frozenset({"show"})
    )
    assert first is not None and second is not None
    assert "i" in first and "j" in second
    assert first != second


def test_trivial_bodies_excluded() -> None:
    assert is_trivial_sequence(())
    assert is_trivial_sequence(normalize_body_tokens("pass\n", local_names=frozenset()) or ())
    assert is_trivial_sequence(normalize_body_tokens("...\n", local_names=frozenset()) or ())
    assert not is_trivial_sequence(normalize_body_tokens("x = 1\n", local_names=frozenset()) or ())


def test_untokenizable_returns_none() -> None:
    assert normalize_body_tokens("def broken(:\n", local_names=frozenset({"x"})) is None


def test_body_text_slicing() -> None:
    lines = ("def work():", "    x = 1", "    return x")
    assert body_text(lines, 2, 3) == "    x = 1\n    return x"
    assert body_text(lines, 0, 3) == ""
    assert body_text(lines, 2, 9) == ""


def test_window_hashes_are_deterministic_sets() -> None:
    tokens = tuple(f"t{i}" for i in range(60))
    first = window_hashes(tokens, 50)
    assert len(first) == 11
    assert first == window_hashes(tuple(f"t{i}" for i in range(60)), 50)
    assert window_hashes(tuple(f"x{i}" for i in range(49)), 50) == set()


def test_longest_common_run_exact() -> None:
    assert longest_common_run(("a", "b", "c"), ("x", "b", "c", "y")) == 2
    assert longest_common_run(("a",), ("b",)) == 0
    assert longest_common_run((), ("a",)) == 0
    assert longest_common_run(tuple("a" * 500), tuple("b" * 500)) == -1  # over budget


def _assigned(text: str) -> frozenset[str]:
    """Names assigned in a body (mirrors what NCM records for real functions)."""
    import re

    return frozenset(re.findall(r"([A-Za-z_][A-Za-z0-9_]*)\s*=", text))


def _body(
    path: str, name: str, start: int, text: str, locals_: frozenset[str] | None = None
) -> tuple[str, str, int, int, tuple[str, ...]]:
    tokens = normalize_body_tokens(
        text, local_names=_assigned(text) if locals_ is None else locals_
    )
    assert tokens is not None
    lines = text.count("\n") + 1
    return (path, name, start, start + lines - 1, tokens)


def _fifty_plus(extra: str = "") -> str:
    base = "".join(f"    step_{i} = {i}\n" for i in range(20))
    return base + extra


def test_below_minimum_produces_no_group() -> None:
    short = normalize_body_tokens("x = 1\ny = 2\n", local_names=frozenset({"x", "y"}))
    assert short is not None and len(short) < 50
    bodies = [
        ("a.py", "f", 1, 2, short),
        ("b.py", "g", 1, 2, short),
    ]
    groups, _stats = group_candidates(bodies, 50)
    assert groups == []


def test_exactly_50_shared_tokens_groups() -> None:
    """Contract uses >= minimum: a 50-token shared run qualifies."""
    text = _fifty_plus()
    tokens = normalize_body_tokens(text, local_names=_assigned(text))
    assert tokens is not None and len(tokens) >= 50
    first = tokens[:50]
    bodies = [("a.py", "f", 1, 9, first), ("b.py", "g", 1, 9, first)]
    groups, _stats = group_candidates(bodies, 50)
    assert len(groups) == 1
    assert groups[0].matched_tokens == 50
    assert groups[0].exact is True
    assert [item.path for item in groups[0].members] == ["a.py", "b.py"]


def test_49_shared_tokens_silent_51_groups() -> None:
    """Boundary through the production grouping path: 49 silent, 51 groups."""
    text = _fifty_plus()
    tokens = normalize_body_tokens(text, local_names=_assigned(text))
    assert tokens is not None
    short = tokens[:49]
    assert group_candidates([("a.py", "f", 1, 9, short), ("b.py", "g", 1, 9, short)], 50)[0] == []
    long = tokens[:51]
    (group,) = group_candidates([("a.py", "f", 1, 9, long), ("b.py", "g", 1, 9, long)], 50)[0]
    assert group.matched_tokens == 51


def test_different_literals_break_runs() -> None:
    """Literals are preserved: 60× `x = 1` vs 60× `x = 2` share no run."""
    first = normalize_body_tokens(
        "".join("    x = 1\n" for _ in range(60)), local_names=frozenset({"x"})
    )
    second = normalize_body_tokens(
        "".join("    x = 2\n" for _ in range(60)), local_names=frozenset({"x"})
    )
    assert first is not None and second is not None
    bodies = [("a.py", "f", 1, 60, first), ("b.py", "g", 1, 60, second)]
    assert group_candidates(bodies, 50)[0] == []


def test_identical_bodies_form_one_group() -> None:
    text = _fifty_plus()
    bodies = [
        _body("a.py", "f", 1, text),
        _body("b.py", "g", 10, text),
        _body("c.py", "h", 20, text),
    ]
    groups, _stats = group_candidates(bodies, 50)
    assert len(groups) == 1
    assert len(groups[0].members) == 3
    assert groups[0].members[0].path == "a.py"  # primary first


def test_different_bodies_form_no_group() -> None:
    bodies = [
        _body("a.py", "f", 1, _fifty_plus()),
        _body("b.py", "g", 1, "".join(f"    show(item_{i})\n" for i in range(20))),
    ]
    groups, _stats = group_candidates(bodies, 50)
    assert groups == []


def test_renamed_identifiers_still_match() -> None:
    first = _fifty_plus()
    second = first.replace("step_", "phase_")
    bodies = [_body("a.py", "f", 1, first), _body("b.py", "g", 1, second)]
    groups, _stats = group_candidates(bodies, 50)
    assert len(groups) == 1


def test_self_pairing_impossible_and_reverse_deduped() -> None:
    text = _fifty_plus()
    bodies = [_body("a.py", "f", 1, text), _body("b.py", "g", 1, text)]
    forward, _ = group_candidates(bodies, 50)
    backward, _ = group_candidates(list(reversed(bodies)), 50)
    assert len(forward) == len(backward) == 1
    assert forward[0].members == backward[0].members


def test_short_repeated_sequences_ignored() -> None:
    bodies = [_body("a.py", "f", 1, "x = 1\n"), _body("b.py", "g", 1, "x = 1\n")]
    groups, _stats = group_candidates(bodies, 50)
    assert groups == []


def test_unmappable_locations_never_invented() -> None:
    """Grouping consumes caller-supplied locations verbatim."""
    text = _fifty_plus()
    bodies = [_body("a.py", "f", 3, text), _body("b.py", "g", 7, text)]
    (group,) = group_candidates(bodies, 50)[0]
    assert [(item.path, item.start_line) for item in group.members] == [("a.py", 3), ("b.py", 7)]


def test_many_locations_all_listed_with_primary_first() -> None:
    text = _fifty_plus()
    bodies = [_body(f"m{i}.py", "f", 1, text) for i in range(5)]
    (group,) = group_candidates(bodies, 50)[0]
    assert len(group.members) == 5
    assert [item.path for item in group.members] == [f"m{i}.py" for i in range(5)]


def test_group_cap_records_limitation() -> None:
    import app.analyzers.code_structure.duplicates as duplicates

    first = _fifty_plus()
    # Calls (parentheses) guarantee no shared 50-window with assignments.
    second = "".join(f"    show(item_{i})\n" for i in range(20))
    bodies = [
        _body("a.py", "f", 1, first),
        _body("b.py", "g", 1, first),
        _body("c.py", "h", 1, second),
        _body("d.py", "i", 1, second),
    ]
    old, duplicates.MAX_DUPLICATE_GROUPS = duplicates.MAX_DUPLICATE_GROUPS, 1
    try:
        groups, stats = group_candidates(bodies, 50)
    finally:
        duplicates.MAX_DUPLICATE_GROUPS = old
    assert len(groups) == 1
    assert stats["groups_capped"] is True
