"""Idempotency-Keys: serverseitig gebildet, an (run_id, action_id) gebunden."""
from __future__ import annotations


def key_for(run_id: str, action_id: str) -> str:
    return f"{run_id}:{action_id}"
