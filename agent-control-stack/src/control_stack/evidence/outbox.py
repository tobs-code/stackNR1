"""Outbox-Claim: plain SELECT. Serialisierung via Advisory-Lock im Writer
(kein FOR UPDATE — Writer hat absichtlich kein UPDATE-Recht auf Outbox).
Rückfallnetz: evidence_ledger-PK + Hash-Vergleich im Writer.
"""
from __future__ import annotations

import psycopg


def claim_next(cur: psycopg.Cursor) -> dict | None:
    cur.execute(
        "SELECT * FROM outbox_events WHERE event_id NOT IN"
        " (SELECT event_id FROM evidence_ledger)"
        " ORDER BY run_id, sequence LIMIT 1")
    return cur.fetchone()
