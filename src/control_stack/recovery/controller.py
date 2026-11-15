"""Recovery-Controller: OutcomeUnknown auflösen, Quarantäne verhängen.

reconcile() liest den Zustand neu ein (neue Verbindung) und handelt:
- replayed      → gespeichertes Ergebnis, kein Effect
- retry_allowed → Action auf outcome_unknown + Recovery-Job, genau EIN
                  erneuter execute()-Versuch durch den Aufrufer
- quarantined   → Recovery-Job + Action-Status quarantined, kein Retry

Statuswechsel laufen ausschliesslich über `fn_recovery_transition`
(Migration 010). Der Controller schreibt weder `actions.status` noch
`action_transitions` direkt; die Rolle `stack_recovery` hat dafür keine
Rechte mehr.
"""
from __future__ import annotations

import uuid

import psycopg
from psycopg import errors as _pgerrors

from .reconciliation import Inspection, inspect_action

# Zustände, aus denen Spec Rev. 7 §3 eine Quarantäne-Kante kennt.
QUARANTINE_LEGAL_SOURCES = frozenset(
    {"authorized", "executing", "outcome_unknown", "committed"}
)


class RecoveryError(Exception):
    pass


def reconcile(dsn: str, action_id: str, run_id: str) -> Inspection:
    for attempt in (1, 2):
        try:
            return _reconcile_once(dsn, action_id, run_id)
        except _pgerrors.RaiseException as e:
            # Konkurrierender Writer (z. B. Worker) hat den Status zwischen
            # Inspektion und Übergang geändert: einmal neu einlesen.
            if attempt == 1 and "lifecycle_conflict" in str(e):
                continue
            raise RecoveryError(str(e)) from e
    raise RecoveryError("reconcile: unauflösbarer Statuskonflikt")


def _reconcile_once(dsn: str, action_id: str, run_id: str) -> Inspection:
    with psycopg.connect(dsn, autocommit=False) as c, \
            c.cursor(row_factory=psycopg.rows.dict_row) as cur:
        # Serialisiert parallele Reconciles je Action. Die Rolle hat kein
        # UPDATE-Recht mehr auf actions und kann daher kein SELECT FOR UPDATE
        # nutzen; der eigentliche Statuswechsel ist in der Funktion gelockt.
        cur.execute("SELECT pg_advisory_xact_lock(hashtextextended(%s, 0))",
                    (action_id,))
        insp = inspect_action(cur, action_id)
        if insp.outcome == "replayed" or insp.reason == "action unbekannt":
            c.rollback()
            return insp

        cur.execute("SELECT status FROM actions WHERE action_id=%s", (action_id,))
        row = cur.fetchone()
        status = row["status"] if row else None
        job_id = str(uuid.uuid4())

        if insp.outcome == "retry_allowed":
            # Wiederholtes Reconcile darf keine zweite Kante
            # outcome_unknown→outcome_unknown erzeugen (F3).
            if status != "outcome_unknown":
                cur.execute("SELECT fn_recovery_transition(%s,'outcome_unknown')",
                            (action_id,))
            _ensure_job(cur, job_id, run_id, action_id, "reconcile")
            c.commit()
            return insp

        # quarantined — auch für inkonsistente committed-Zeilen (F4): ein
        # Status-Snapshot ohne Effektnachweis darf nicht 'committed' bleiben.
        # Echte Commits erreichen diesen Pfad nie (→ 'replayed').
        if status in QUARANTINE_LEGAL_SOURCES:
            cur.execute("SELECT fn_recovery_transition(%s,'quarantined')",
                        (action_id,))
        _ensure_job(cur, job_id, run_id, action_id, "quarantine")
        c.commit()
        return insp


def _ensure_job(cur: psycopg.Cursor, job_id: str, run_id: str,
                action_id: str, kind: str) -> None:
    """Legt höchstens einen offenen Job je (Action, Kind) an (F3-Race)."""
    cur.execute(
        "SELECT 1 FROM recovery_jobs WHERE action_id=%s AND kind=%s"
        " AND status IN ('open','in_progress') LIMIT 1", (action_id, kind))
    if cur.fetchone() is not None:
        return
    cur.execute(
        "INSERT INTO recovery_jobs (job_id, run_id, action_id, kind)"
        " VALUES (%s,%s,%s,%s)", (job_id, run_id, action_id, kind))
