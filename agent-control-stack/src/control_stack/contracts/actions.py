"""Action contracts — Pydantic, extra=forbid. Status: STUB, nicht implementiert."""
from __future__ import annotations

RAISES_ON_USE = "NOT IMPLEMENTED: contracts stub — kein Schutz aktiv"


def _missing(*a, **k):
    raise NotImplementedError(RAISES_ON_USE)
