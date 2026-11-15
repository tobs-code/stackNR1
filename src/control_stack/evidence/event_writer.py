"""Event-Writer: committed Outbox-Events → Ledger. Idempotent, pro Run serialisiert.

- Verarbeitet bereits committed Events (bestätigt nichts nachträglich).
- pro-Run-Advisory-Lock verhindert Chain-Forks bei konkurrierenden Writern.
- Ledger-Write nur über fn_ledger_append (Owner-Kontext): direkter
  Ledger-Zugriff per Runtime-Credentials ist entzogen (F7).
- Doppelverarbeitung: vorhandener Hash wird verglichen; divergierender
  Hash bei gleicher event_id ⇒ TamperError (kein stilles Überschreiben).
- Fehler ⇒ Rollback, Event bleibt ausstehend (Ledger-Zeile fehlt).
"""
from __future__ import annotations

import psycopg
from psycopg import errors as _pgerrors

from .integrity import GENESIS, event_hash
from .outbox import claim_next


class TamperError(Exception):
    pass


def process_next(dsn: str) -> str | None:
    """Verarbeitet genau ein ausstehendes Event. Gibt event_id zurück oder None."""
    with psycopg.connect(dsn, autocommit=False) as c, \
            c.cursor(row_factory=psycopg.rows.dict_row) as cur:
        # Globales Writer-Lock: ersetzt FOR UPDATE (kein UPDATE-Recht auf
        # Outbox per Grant). Ledger-PK bleibt Rückfallnetz bei Lock-Fehlern.
        cur.execute("SELECT pg_advisory_xact_lock(424242)")
        row = claim_next(cur)
        if row is None:
            c.rollback()
            return None
        cur.execute("SELECT pg_advisory_xact_lock(hashtext(%s))", (row["run_id"],))
        cur.execute(
            "SELECT event_hash FROM evidence_ledger WHERE run_id=%s"
            " ORDER BY sequence DESC LIMIT 1", (row["run_id"],))
        head = cur.fetchone()
        prev = head["event_hash"] if head else GENESIS
        h = event_hash(event_id=row["event_id"], event_type=row["event_type"],
                       action_id=row["action_id"], run_id=row["run_id"],
                       sequence=row["sequence"],
                       resource_version=row["resource_version"],
                       payload_hash=row["payload_hash"], prev_hash=prev)
        try:
            cur.execute("SELECT fn_ledger_append(%s,%s,%s,%s,%s)",
                        (row["event_id"], row["run_id"], row["sequence"], h, prev))
        except _pgerrors.RaiseException as e:
            if str(e).startswith("ledger_divergence"):
                raise TamperError(f"Ledger-Divergenz bei {row['event_id']}") from e
            raise
        return row["event_id"]


def process_all(dsn: str, limit: int = 1000) -> list[str]:
    done: list[str] = []
    for _ in range(limit):
        eid = process_next(dsn)
        if eid is None:
            break
        done.append(eid)
    return done
