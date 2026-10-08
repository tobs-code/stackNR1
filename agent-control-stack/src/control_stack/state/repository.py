"""State-Repository: Transaktionen, CAS, Lifecycle, Idempotenz, Outbox.

Fehlersemantik (keine stillen Retries, keine generischen Fehler):
- StaleVersionError: CAS rowcount=0 (Konflikt oder Ziel fehlt; Ursache im Feld).
- IdempotencyConflictError: gleicher Key, anderer Payload.
- IdempotencyReplay: KEIN Fehler — dataclass mit gespeichertem Ergebnis.
- IllegalTransitionError: contracts.transition schlägt fehl.
Jede commit_*-Methode läuft in EINER Transaktion; Fehler ⇒ Rollback.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

import psycopg

from ..contracts import canonical_hash, record_fields, transition


class StaleVersionError(Exception):
    def __init__(self, record_id: str, expected: int, found: str = "conflict-or-missing"):
        super().__init__(f"stale version: {record_id} expected={expected} ({found})")
        self.record_id = record_id
        self.expected = expected
        self.found = found


class IdempotencyConflictError(Exception):
    pass


class IllegalTransitionError(ValueError):
    pass


@dataclass(frozen=True)
class IdempotencyReplay:
    result: dict


@dataclass
class Repository:
    dsn: str

    def _conn(self) -> psycopg.Connection:
        return psycopg.connect(self.dsn, autocommit=False)

    # -- Reads ---------------------------------------------------------
    def load_action(self, action_id: str) -> dict | None:
        with self._conn() as c, c.cursor(row_factory=psycopg.rows.dict_row) as cur:
            cur.execute("SELECT * FROM actions WHERE action_id=%s", (action_id,))
            return cur.fetchone()

    def load_authorization_record(self, action_id: str) -> dict | None:
        with self._conn() as c, c.cursor(row_factory=psycopg.rows.dict_row) as cur:
            cur.execute("SELECT * FROM authorization_records WHERE action_id=%s", (action_id,))
            return cur.fetchone()

    # -- Lifecycle ------------------------------------------------------
    def create_action(self, *, action_id: str, run_id: str, action: str,
                      target: str, args_hash: str, idempotency_key: str,
                      payload_hash: str, expected_resource_version: int) -> None:
        """Proposed-Anlage + Idempotency-Claim in einer Transaktion."""
        with self._conn() as c, c.cursor() as cur:
            cur.execute(
                "INSERT INTO actions (action_id, run_id, action, target, args_hash,"
                " idempotency_key, idempotency_payload_hash, status,"
                " expected_resource_version)"
                " VALUES (%s,%s,%s,%s,%s,%s,%s,'proposed',%s)",
                (action_id, run_id, action, target, args_hash,
                 idempotency_key, payload_hash, expected_resource_version),
            )
            cur.execute(
                "INSERT INTO action_transitions (action_id, old_status, new_status)"
                " VALUES (%s,'proposed','proposed')", (action_id,),
            )

    def transition_action(self, action_id: str, old: str, new: str) -> None:
        try:
            transition(old, new)
        except ValueError as e:
            raise IllegalTransitionError(str(e)) from e
        with self._conn() as c, c.cursor() as cur:
            cur.execute(
                "UPDATE actions SET status=%s WHERE action_id=%s AND status=%s",
                (new, action_id, old),
            )
            if cur.rowcount != 1:
                raise IllegalTransitionError(
                    f"action {action_id}: status ist nicht {old!r}")
            cur.execute(
                "INSERT INTO action_transitions (action_id, old_status, new_status)"
                " VALUES (%s,%s,%s)", (action_id, old, new),
            )

    # -- Atomarer Demo-Write (Rev. 4 §4) --------------------------------
    def commit_demo_update(self, *, run_id: str, action_id: str,
                           record_id: str, new_status: str,
                           expected_version: int, idempotency_key: str,
                           payload_hash: str, event_id: str,
                           run_sequence: int,
                           prev_event_hash: str) -> dict | IdempotencyReplay:
        """Claim + CAS + Effect + Transitionen + Result + Outbox, eine Transaktion.

        Replay-Fall: Key existiert mit gleichem Payload und result gesetzt ⇒
        IdempotencyReplay ohne Effect. Anderer Payload ⇒ Conflict.
        """
        with self._conn() as c, c.cursor(row_factory=psycopg.rows.dict_row) as cur:
            cur.execute(
                "SELECT idempotency_payload_hash, result, status FROM actions"
                " WHERE idempotency_key=%s FOR UPDATE", (idempotency_key,))
            row = cur.fetchone()
            if row is not None and row["idempotency_payload_hash"] != payload_hash:
                raise IdempotencyConflictError(
                    f"key {idempotency_key}: anderer Payload")
            if row is not None and row["result"] is not None:
                return IdempotencyReplay(result=row["result"])
            if row is None:
                cur.execute(
                    "INSERT INTO actions (action_id, run_id, action, target,"
                    " args_hash, idempotency_key, idempotency_payload_hash,"
                    " status, expected_resource_version)"
                    " VALUES (%s,%s,'demo_update_record',%s,%s,%s,%s,"
                    " 'executing',%s)",
                    (action_id, run_id, record_id, payload_hash,
                     idempotency_key, payload_hash, expected_version),
                )
            # CAS: genau eine Zeile oder Stale
            cur.execute(
                "UPDATE records SET status=%s, version=version+1"
                " WHERE record_id=%s AND version=%s"
                " RETURNING version", (new_status, record_id, expected_version))
            cas = cur.fetchone()
            if cas is None:
                cur.execute("SELECT version FROM records WHERE record_id=%s",
                            (record_id,))
                found = cur.fetchone()
                raise StaleVersionError(
                    record_id, expected_version,
                    "missing" if found is None else f"found={found['version']}")
            new_version = cas["version"]
            assert new_version == expected_version + 1
            result = {"record_id": record_id, "old_version": expected_version,
                      "new_version": new_version, "status": new_status}
            cur.execute(
                "UPDATE actions SET status='committed', result=%s::jsonb,"
                " result_written_at=now() WHERE action_id=%s",
                (json.dumps(result), action_id))
            cur.execute(
                "INSERT INTO action_transitions (action_id, old_status, new_status)"
                " VALUES (%s,'executing','confirmed'),(%s,'confirmed','committed')",
                (action_id, action_id))
            cur.execute(
                "INSERT INTO state_transitions (run_id, action_id, record_id,"
                " old_version, new_version) VALUES (%s,%s,%s,%s,%s)",
                (run_id, action_id, record_id, expected_version, new_version))
            cur.execute(
                "INSERT INTO outbox_events (event_id, run_id, action_id, sequence,"
                " event_type, resource_version, payload_hash, previous_event_hash)"
                " VALUES (%s,%s,%s,%s,'state_committed',%s,%s,%s)",
                (event_id, run_id, action_id, run_sequence,
                 new_version, payload_hash, prev_event_hash))
            return result
