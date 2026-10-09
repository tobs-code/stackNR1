"""Gate-Validierung: Proposal-Schema + Capability. Rein, seiteneffektfrei."""
from __future__ import annotations

from ..contracts import ActionProposal
from .capabilities import is_capable


class GateRejected(Exception):
    pass


def validate_proposal(raw: dict) -> ActionProposal:
    try:
        p = ActionProposal.model_validate(raw)
        args = p.validated_arguments()
    except Exception as e:
        raise GateRejected(f"schema/capability verletzt: {e}") from e
    if not is_capable(p.action):
        raise GateRejected(f"unbekannte action: {p.action}")
    # F1: genau ein kanonisches Ziel — autorisiertes target und
    # arguments.record_id müssen identisch sein, sonst kein Record.
    if args.record_id != p.target:
        raise GateRejected(
            f"zielbindung verletzt: target={p.target!r} != record_id={args.record_id!r}")
    return p
