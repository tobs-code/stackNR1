"""Verifier: liest Outbox + Ledger neu ein, rechnet Kette pro Run nach.

Prüft: lückenlose Sequenzen, Hash-Verkettung, Übereinstimmung mit Outbox,
optional Head gegen unabhängigen Checkpoint. Reine Reads (+ eigene Verbindung).
"""
from __future__ import annotations

import psycopg

from .integrity import GENESIS, event_hash


class VerificationError(Exception):
    pass


def verify_run(dsn: str, run_id: str, checkpoint: str | None = None) -> int:
    """Gibt Anzahl geprüfter Events zurück. Wirft VerificationError bei Befund."""
    with psycopg.connect(dsn, autocommit=True) as c, \
            c.cursor(row_factory=psycopg.rows.dict_row) as cur:
        cur.execute("SELECT * FROM outbox_events WHERE run_id=%s ORDER BY sequence",
                    (run_id,))
        events = cur.fetchall()
        cur.execute("SELECT * FROM evidence_ledger WHERE run_id=%s ORDER BY sequence",
                    (run_id,))
        ledger = {r["sequence"]: r for r in cur.fetchall()}
        if len(ledger) != len(events):
            raise VerificationError(
                f"Ledger unvollständig: {len(ledger)} von {len(events)} Events")
        prev = GENESIS
        for e in events:
            seq = e["sequence"]
            if seq not in ledger:
                raise VerificationError(f"Sequenzlücke: {seq} fehlt im Ledger")
            L = ledger[seq]
            if L["event_id"] != e["event_id"]:
                raise VerificationError(f"Reihenfolge/ID-Bruch bei Sequenz {seq}")
            # Re-Hash über die AKTUELLEN Outbox-Werte: nachträgliche Änderung
            # an Outbox ODER Ledger bricht den Vergleich.
            expect = event_hash(event_id=e["event_id"], event_type=e["event_type"],
                                action_id=e["action_id"], run_id=run_id,
                                sequence=seq,
                                resource_version=e["resource_version"],
                                payload_hash=e["payload_hash"], prev_hash=prev)
            if L["event_hash"] != expect:
                raise VerificationError(f"Hash-Bruch bei {e['event_id']}")
            if L["prev_hash"] != prev:
                raise VerificationError(f"Vorgänger-Bruch bei {e['event_id']}")
            prev = expect
        if checkpoint is not None and prev != checkpoint:
            raise VerificationError("Head weicht vom Checkpoint ab (Abschneiden?)")
        return len(events)


def write_checkpoint(dsn: str, run_id: str, head_hash: str) -> None:
    """Getrennter Schreiber (Recovery-Rolle), nicht der Writer."""
    with psycopg.connect(dsn, autocommit=True) as c:
        c.execute(
            "INSERT INTO evidence_checkpoints (run_id, head_hash) VALUES (%s,%s)"
            " ON CONFLICT (run_id) DO UPDATE SET head_hash=EXCLUDED.head_hash,"
            " created_at=now()", (run_id, head_hash))


def read_checkpoint(dsn: str, run_id: str) -> str | None:
    with psycopg.connect(dsn, autocommit=True) as c, c.cursor() as cur:
        cur.execute("SELECT head_hash FROM evidence_checkpoints WHERE run_id=%s",
                    (run_id,))
        r = cur.fetchone()
        return r[0] if r else None
