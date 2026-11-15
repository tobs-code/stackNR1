"""Verifier: liest Outbox + Ledger neu ein, rechnet Kette pro Run nach.

Prüft: lückenlose Sequenz ab 1 (beidseitig), Hash-Verkettung, Übereinstimmung
mit Outbox, Vorgängerzeiger, und den Anker.

F8: Der Checkpoint wird aus der DB gelesen — nie vom Aufrufer übergeben (ein
Aufrufer-Parameter wäre derselbe Fehler wie der ungeprüfte Vorgänger-Hash).
Er ist standardmäßig Pflicht: ohne Anker ist Abschneiden prinzipiell nicht
erkennbar. Die Checkpoint-Historie wird selbst auf Abstammung geprüft, damit
ein nachträglich gesetzter Head auffällt.

Reine Reads (+ eigene Verbindung). Schreibt nie.
"""
from __future__ import annotations

import psycopg

from .integrity import GENESIS, event_hash

MAX_CHAIN_WALK = 1_000_000


class VerificationError(Exception):
    pass


def verify_run(dsn: str, run_id: str, *,
               require_checkpoint: bool = True) -> int:
    """Gibt Anzahl geprüfter Events zurück. Wirft VerificationError bei Befund.

    `require_checkpoint=False` ist nur für laufende Runs gedacht: dann ist
    Abschneiden nicht entscheidbar und das Ergebnis deckt nur die vorhandene
    Kette ab.
    """
    with psycopg.connect(dsn, autocommit=True) as c, \
            c.cursor(row_factory=psycopg.rows.dict_row) as cur:
        cur.execute("SELECT * FROM outbox_events WHERE run_id=%s ORDER BY sequence",
                    (run_id,))
        events = cur.fetchall()
        cur.execute("SELECT * FROM evidence_ledger WHERE run_id=%s ORDER BY sequence",
                    (run_id,))
        ledger_rows = cur.fetchall()
        ledger = {r["sequence"]: r for r in ledger_rows}
        if len(ledger) != len(events):
            raise VerificationError(
                f"Ledger unvollständig: {len(ledger)} von {len(events)} Events")
        _require_contiguous(events, ledger, run_id)

        prev = GENESIS
        prev_id: str | None = None
        for e in events:
            seq = e["sequence"]
            L = ledger[seq]
            if L["event_id"] != e["event_id"]:
                raise VerificationError(f"Reihenfolge/ID-Bruch bei Sequenz {seq}")
            if e["prev_event_id"] != prev_id:
                raise VerificationError(
                    f"Vorgängerzeiger von {e['event_id']} zeigt auf"
                    f" {e['prev_event_id']!r}, erwartet {prev_id!r}")
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
            prev_id = e["event_id"]

        checkpoints = _read_checkpoints(cur, run_id)
        if not checkpoints:
            if require_checkpoint:
                raise VerificationError(
                    "kein Checkpoint: Abschneiden ist ohne Anker nicht erkennbar")
            return len(events)
        if checkpoints[-1]["head_hash"] != prev:
            raise VerificationError("Head weicht vom Checkpoint ab (Abschneiden?)")
        _verify_checkpoint_history(cur, checkpoints, run_id)
        return len(events)


def _require_contiguous(events: list[dict], ledger: dict[int, dict],
                        run_id: str) -> None:
    """Sequenzen müssen ab 1 lückenlos sein — in Outbox UND Ledger."""
    expected = list(range(1, len(events) + 1))
    got = [e["sequence"] for e in events]
    if got != expected:
        raise VerificationError(
            f"Sequenzlücke in der Outbox von {run_id}: {got} (erwartet {expected})")
    if sorted(ledger) != expected:
        raise VerificationError(
            f"Sequenzlücke im Ledger von {run_id}: {sorted(ledger)}"
            f" (erwartet {expected})")


def _read_checkpoints(cur: psycopg.Cursor, run_id: str) -> list[dict]:
    cur.execute("SELECT checkpoint_id, head_hash FROM evidence_checkpoints"
                " WHERE run_id=%s ORDER BY checkpoint_id", (run_id,))
    return list(cur.fetchall())


def _verify_checkpoint_history(cur: psycopg.Cursor,
                               checkpoints: list[dict],
                               run_id: str) -> None:
    """Jeder Checkpoint-Head muss Nachfahre des vorherigen sein (F8)."""
    for old, new in zip(checkpoints, checkpoints[1:]):
        if old["head_hash"] == new["head_hash"]:
            continue
        if not _is_descendant(cur, run_id, new["head_hash"], old["head_hash"]):
            raise VerificationError(
                f"Checkpoint-Historie gebrochen: {new['head_hash'][:16]}… ist kein"
                f" Nachfahre von {old['head_hash'][:16]}…")


def _is_descendant(cur: psycopg.Cursor, run_id: str, head: str,
                   ancestor: str) -> bool:
    current = head
    for _ in range(MAX_CHAIN_WALK):
        cur.execute("SELECT prev_hash FROM evidence_ledger"
                    " WHERE run_id=%s AND event_hash=%s", (run_id, current))
        row = cur.fetchone()
        if row is None:
            return False
        if row["prev_hash"] == ancestor:
            return True
        if row["prev_hash"] == GENESIS or row["prev_hash"] == current:
            return False
        current = row["prev_hash"]
    return False


def write_checkpoint(dsn: str, run_id: str, head_hash: str) -> None:
    """Getrennter Schreiber (Recovery-Rolle), nicht der Writer.

    Die Abstammungsprüfung liegt in `fn_write_checkpoint`; die Rolle hat kein
    direktes INSERT/UPDATE mehr auf der Tabelle.
    """
    with psycopg.connect(dsn, autocommit=True) as c:
        c.execute("SELECT fn_write_checkpoint(%s,%s)", (run_id, head_hash))


def read_checkpoint(dsn: str, run_id: str) -> str | None:
    with psycopg.connect(dsn, autocommit=True) as c, c.cursor() as cur:
        cur.execute("SELECT head_hash FROM evidence_checkpoints WHERE run_id=%s"
                    " ORDER BY checkpoint_id DESC LIMIT 1", (run_id,))
        r = cur.fetchone()
        return r[0] if r else None
