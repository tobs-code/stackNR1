"""Statusmaschine als reine Funktion (Rev. 7 §3). Fail closed.

`PAIRS` ist die kanonische Menge aller erlaubten (old, new)-Paare. Sie ist
Spiegel des DB-Pair-CHECKs (Migration 010) und wird von einem Test gegen die
Datenbank verglichen. Änderungen immer in beiden Stellen.
"""
from __future__ import annotations

ALLOWED: dict[str, frozenset[str]] = {
    "proposed": frozenset({"validated", "rejected"}),
    "validated": frozenset({"authorized", "denied", "rejected"}),
    "authorized": frozenset({"executing", "outcome_unknown", "quarantined"}),
    "executing": frozenset({"confirmed", "failed", "outcome_unknown", "quarantined"}),
    "outcome_unknown": frozenset({"executing", "quarantined"}),
    "confirmed": frozenset({"committed"}),
    # in v0.1 reserviert: definiert, aber von keinem Produktionspfad erzeugt
    "failed": frozenset(),
    # fachlich terminal; quarantined nur als Integritäts-Übersteuerung (F4)
    "committed": frozenset({"quarantined"}),
    "quarantined": frozenset(),
    "rejected": frozenset(),
    "denied": frozenset(),
}

PAIRS: frozenset[tuple[str, str]] = frozenset(
    (old, new) for old, news in ALLOWED.items() for new in news
)


def is_allowed(old: str, new: str) -> bool:
    return new in ALLOWED.get(old, frozenset())


def transition(old: str, new: str) -> str:
    if not is_allowed(old, new):
        raise ValueError(f"illegal transition {old!r} -> {new!r}")
    return new
