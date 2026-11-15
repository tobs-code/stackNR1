"""Statusmaschine (Rev. 7 §3): reine Mengenprüfung, keine DB."""
import pytest

from control_stack.contracts import ALLOWED, PAIRS, is_allowed, transition


def test_rev7_edges_are_allowed():
    for old, new in [
        ("authorized", "outcome_unknown"),
        ("authorized", "quarantined"),
        ("executing", "quarantined"),
        ("committed", "quarantined"),
    ]:
        assert is_allowed(old, new), (old, new)
        assert (old, new) in PAIRS


def test_failed_is_reserved_without_outgoing_edges():
    assert "failed" in ALLOWED
    assert ALLOWED["failed"] == frozenset()


def test_committed_only_allows_integrity_override():
    assert ALLOWED["committed"] == frozenset({"quarantined"})


def test_terminal_states_have_no_outgoing_edges():
    for state in ("quarantined", "rejected", "denied"):
        assert ALLOWED[state] == frozenset(), state


def test_pairs_are_derived_from_allowed():
    assert PAIRS == frozenset(
        (old, new) for old, news in ALLOWED.items() for new in news
    )


def test_illegal_pairs_still_fail_closed():
    for old, new in [
        ("proposed", "authorized"),
        ("validated", "executing"),
        ("authorized", "committed"),
        ("committed", "executing"),
        ("quarantined", "executing"),
        ("bogus", "executing"),
    ]:
        assert not is_allowed(old, new), (old, new)
        with pytest.raises(ValueError):
            transition(old, new)
