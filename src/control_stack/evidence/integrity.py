"""Hash-Kette: kanonisches Eventformat, Kette pro Run nach sequence.

Gehashte Felder (fix, keine stillen Ergänzungen):
  {event_id, event_type, action_id, run_id, sequence, resource_version,
   payload_hash, prev_hash}
prev_hash = event_hash des Vorgängers (sequence-1) oder GENESIS.
Serialisierung: contracts.canon (JCS-ähnlich, enger Typbereich erzwungen).

Grenze (Rev. 4 §4): Kette erkennt Änderung/Lücke/Abschneiden NUR gegen einen
unabhängig geschützten Checkpoint; Neuberechnung durch privilegierten
Angreifer (Owner) ist ausserhalb des Modells.
"""
from __future__ import annotations

from ..contracts import canon, sha256_hex

GENESIS = "GENESIS:" + "0" * 56

CHAIN_FIELDS = ("event_id", "event_type", "action_id", "run_id", "sequence",
                "resource_version", "payload_hash", "prev_hash")


def event_hash(*, event_id: str, event_type: str, action_id: str | None,
               run_id: str, sequence: int, resource_version: int,
               payload_hash: str, prev_hash: str) -> str:
    doc = {"event_id": event_id, "event_type": event_type,
           "action_id": action_id, "run_id": run_id, "sequence": sequence,
           "resource_version": resource_version,
           "payload_hash": payload_hash, "prev_hash": prev_hash}
    return sha256_hex(canon(doc))
