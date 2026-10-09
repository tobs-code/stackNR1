"""Recovery-Controller: OutcomeUnknown auflösen, Quarantäne verhängen.

reconcile() liest den Zustand neu ein (neue Verbindung) und handelt:
- replayed      → gespeichertes Ergebnis, kein Effect
- retry_allowed → Action auf outcome_unknown + Recovery-Job, genau EIN
                  erneuter execute()-Versuch durch den Aufrufer
- quarantined   → Recovery-Job + Action-Status quarantined, kein Retry
"""
from __future__ import annotations

import uuid

import psycopg

from .reconciliation import Inspection, inspect_action


class RecoveryError(Exception):
    pass


def reconcile(dsn: str, action_id: str, run_id: str) -> Inspection:
    with psycopg.connect(dsn, autocommit=False) as c, \
            c.cursor(row_factory=psycopg.rows.dict_row) as cur:
        insp = inspect_action(cur, action_id)
        if insp.outcome == "replayed":
            c.rollback()
            return insp
        if insp.reason == "action unbekannt":
            # Nichts zu verhängen (keine Action-Zeile für FK) — reine Meldung.
            c.rollback()
            return insp
        job_id = str(uuid.uuid4())
        if insp.outcome == "retry_allowed":
            cur.execute(
                "UPDATE actions SET status='outcome_unknown' WHERE action_id=%s"
                " AND status NOT IN ('committed','quarantined')", (action_id,))
            cur.execute(
                "INSERT INTO action_transitions (action_id, old_status, new_status)"
                " SELECT %s, status, 'outcome_unknown' FROM actions WHERE action_id=%s"
                " AND status NOT IN ('committed','quarantined')",
                (action_id, action_id))
            cur.execute(
                "INSERT INTO recovery_jobs (job_id, run_id, action_id, kind)"
                " VALUES (%s,%s,%s,'reconcile')", (job_id, run_id, action_id))
            c.commit()
            return insp
        # quarantined — auch für inkonsistente committed-Zeilen (F4): ein
        # Status-Snapshot ohne Effektnachweis darf nicht 'committed' bleiben.
        # Echte Commits erreichen diesen Pfad nie (→ 'replayed').
        cur.execute(
            "UPDATE actions SET status='quarantined' WHERE action_id=%s", (action_id,))
        cur.execute(
            "INSERT INTO recovery_jobs (job_id, run_id, action_id, kind)"
            " VALUES (%s,%s,%s,'quarantine')", (job_id, run_id, action_id))
        c.commit()
        return insp
