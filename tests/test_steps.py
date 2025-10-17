import pytest

from e2e_v import steps


def test_step5_process_simple_counts():
    ballots = [{"choice": "Alice"}, {"choice": "Bob"}, {"choice": "Alice"}]
    tally = steps.step5_process(ballots)
    assert tally["Alice"] == 2
    assert tally["Bob"] == 1
    assert "__invalid__" not in tally


def test_step5_process_with_invalids():
    ballots = [{}, {"choice": None}, {"choice": "Carol"}]
    tally = steps.step5_process(ballots)
    assert tally["Carol"] == 1
    assert tally["__invalid__"] == 2


def test_step6_analyze_matching():
    ballots = [{"choice": "X"}, {"choice": "Y"}, {"choice": "X"}]
    published = {"X": 2, "Y": 1}
    ok, details = steps.step6_analyze(published, ballots)
    assert ok is True
    assert details["diffs"] == {}


def test_step6_analyze_mismatch():
    ballots = [{"choice": "X"}, {"choice": "Y"}, {"choice": "X"}]
    published = {"X": 1, "Y": 2}
    ok, details = steps.step6_analyze(published, ballots)
    assert ok is False
    assert "X" in details["diffs"]
    assert details["diffs"]["X"]["published"] == 1
    assert details["diffs"]["X"]["recomputed"] == 2
