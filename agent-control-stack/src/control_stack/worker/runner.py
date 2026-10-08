"""Worker-Runner: Request → broker.execute. Keine Gate-Imports."""
from __future__ import annotations

from ..execution.broker import execute
from ..state.repository import IdempotencyReplay


def run_execute(dsn: str, req: dict) -> dict:
    for f in ("action_id", "arguments", "actor_id"):
        if f not in req:
            raise ValueError(f"fehlendes Feld: {f}")
    if not isinstance(req["arguments"], dict):
        raise ValueError("arguments muss Objekt sein")
    out = execute(dsn, req["action_id"], req["arguments"], req["actor_id"],
                  event_id=req.get("event_id"),
                  run_sequence=int(req.get("run_sequence", 1)),
                  prev_event_hash=req.get("prev_event_hash", "0" * 64))
    if isinstance(out, IdempotencyReplay):
        return {"replay": out.result}
    return out
