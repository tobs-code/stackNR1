"""Statusmaschine als reine Funktion (Rev. 4 §3). Fail closed."""
from __future__ import annotations

ALLOWED: dict[str, frozenset[str]] = {
    "proposed": frozenset({"validated", "rejected"}),
    "validated": frozenset({"authorized", "denied", "rejected"}),
    "authorized": frozenset({"executing"}),
    "executing": frozenset({"confirmed", "failed", "outcome_unknown"}),
    "outcome_unknown": frozenset({"executing", "quarantined"}),
    "confirmed": frozenset({"committed"}),
    "failed": frozenset(),
    "committed": frozenset(),
    "quarantined": frozenset(),
    "rejected": frozenset(),
    "denied": frozenset(),
}


def is_allowed(old: str, new: str) -> bool:
    return new in ALLOWED.get(old, frozenset())


def transition(old: str, new: str) -> str:
    if not is_allowed(old, new):
        raise ValueError(f"illegal transition {old!r} -> {new!r}")
    return new
