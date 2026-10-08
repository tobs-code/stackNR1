"""Gate-Validierung: Proposal-Schema + Capability. Rein, seiteneffektfrei."""
from __future__ import annotations

from ..contracts import ActionProposal
from .capabilities import is_capable


class GateRejected(Exception):
    pass


def validate_proposal(raw: dict) -> ActionProposal:
    try:
        p = ActionProposal.model_validate(raw)
        p.validated_arguments()
    except Exception as e:
        raise GateRejected(f"schema/capability verletzt: {e}") from e
    if not is_capable(p.action):
        raise GateRejected(f"unbekannte action: {p.action}")
    return p
