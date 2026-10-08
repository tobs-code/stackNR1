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


class AuthorizationMissingError(Exception):
    pass


class AuthorizationExpiredError(Exception):
    pass


class AuthorizationMismatchError(Exception):
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
                           prev_event_hash: str,
                           guard_arguments: dict | None = None,
                           guard_actor_id: str | None = None,
                           _test_hook: str | None = None) -> dict | IdempotencyReplay:
        """Claim + CAS + Effect + Transitionen + Result + Outbox, eine Transaktion.

        Replay-Fall: Key existiert mit gleichem Payload und result gesetzt ⇒
        IdempotencyReplay ohne Effect. Anderer Payload ⇒ Conflict.

        Guard (execution-Pfad): wenn guard_arguments/actor gesetzt, wird
        IN derselben Transaktion der Authorization Record (FOR UPDATE)
        geladen, Ablauf gegen clock_timestamp() (nicht now()!) geprüft und
        der Hash neu rekonstruiert. Abgelaufen/manipuliert/fehlend ⇒
        kein Effect, Rollback.
        """
        with self._conn() as c, c.cursor(row_factory=psycopg.rows.dict_row) as cur:
            cur.execute(
                "SELECT action_id, idempotency_payload_hash, result, status FROM actions"
                " WHERE idempotency_key=%s FOR UPDATE", (idempotency_key,))
            row = cur.fetchone()
            if row is not None and row["idempotency_payload_hash"] != payload_hash:
                raise IdempotencyConflictError(
                    f"key {idempotency_key}: anderer Payload")
            if row is not None and row["result"] is not None:
                return IdempotencyReplay(result=row["result"])
            guarded = guard_arguments is not None or guard_actor_id is not None
            if guarded:
                self._enforce_guard(cur, action_id, guard_arguments or {},
                                    guard_actor_id or "")
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
            if _test_hook == "kill_mid_tx":
                # TEST-ONLY: echter Backend-Tod in offener Tx (nach CAS, vor
                # Result). Verbindung stirbt, Commit-Ausgang unbekannt.
                cur.execute("SELECT pg_terminate_backend(pg_backend_pid())")
                raise AssertionError("unreachable: backend terminated")
            result = {"record_id": record_id, "old_version": expected_version,
                      "new_version": new_version, "status": new_status}
            cur.execute(
                "UPDATE actions SET status='committed', result=%s::jsonb,"
                " result_written_at=now() WHERE action_id=%s",
                (json.dumps(result), action_id))
            if guarded:
                # Gate hat proposed→validated→authorized geschrieben; der
                # Übergang authorized→executing gehört in dieselbe Tx, zuerst.
                cur.execute(
                    "INSERT INTO action_transitions (action_id, old_status, new_status)"
                    " VALUES (%s,'authorized','executing')", (action_id,))
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

    # -- Read-Pfad (Rev. 5): effect-frei, kein CAS, keine Ressourcen-Transition,
    # kein Outbox-Event. Lifecycle endet terminal bei confirmed; das
    # Leseergebnis wird als result persistiert (CHECK + Replay).
    def execute_read(self, *, action_id: str, record_id: str,
                     guard_arguments: dict, guard_actor_id: str) -> dict:
        with self._conn() as c, c.cursor(row_factory=psycopg.rows.dict_row) as cur:
            cur.execute("SELECT * FROM actions WHERE action_id=%s FOR UPDATE",
                        (action_id,))
            action = cur.fetchone()
            if action is None or action["action"] != "demo_read":
                raise AuthorizationMissingError(f"keine lesbare Action: {action_id}")
            self._enforce_guard(cur, action_id, guard_arguments, guard_actor_id)
            cur.execute("SELECT record_id, status, version FROM records WHERE record_id=%s",
                        (record_id,))
            rec = cur.fetchone()
            if rec is None:
                raise StaleVersionError(record_id, -1, "missing")
            result = {"record_id": rec["record_id"], "status": rec["status"],
                      "version": rec["version"]}
            cur.execute("UPDATE actions SET status='confirmed', result=%s::jsonb,"
                        " result_written_at=now() WHERE action_id=%s",
                        (json.dumps(result), action_id))
            cur.execute(
                "INSERT INTO action_transitions (action_id, old_status, new_status)"
                " VALUES (%s,'authorized','executing'),(%s,'executing','confirmed')",
                (action_id, action_id))
            return result

    @staticmethod
    def _enforce_guard(cur: Any, action_id: str, arguments: dict,
                       actor_id: str) -> None:
        """Autorisierung in-Transaktion prüfen. Wirft ohne Effect."""
        from ..contracts import AuthorizationRecord
        cur.execute(
            # Absichtlich KEIN FOR UPDATE: Worker hat (per Grant) kein
            # UPDATE-Recht auf authorization_records; Unveränderlichkeit
            # folgt aus den Rollen-Grants, nicht aus dem Zeilen-Lock.
            "SELECT * FROM authorization_records WHERE action_id=%s",
            (action_id,))
        rec = cur.fetchone()
        if rec is None:
            raise AuthorizationMissingError(f"kein Authorization Record: {action_id}")
        cur.execute("SELECT clock_timestamp() > %s AS expired",
                    (rec["expires_at"],))
        if cur.fetchone()["expired"]:
            raise AuthorizationExpiredError(f"Record abgelaufen: {action_id}")
        try:
            record = AuthorizationRecord(
                action_id=rec["action_id"], canonical_hash=rec["canonical_hash"],
                action=rec["action"], target=rec["target"],
                args_hash=rec["args_hash"], actor_id=rec["actor_id"],
                permissions=list(rec["permissions"]),
                expected_resource_version=rec["expected_resource_version"],
                preconditions=dict(rec["preconditions"]),
                policy_version=rec["policy_version"],
                context_hash=rec["context_hash"], expires_at=rec["expires_at"])
        except Exception as e:
            raise AuthorizationMismatchError(f"Record ungültig: {e}") from e
        if record.actor_id != actor_id:
            raise AuthorizationMismatchError("actor weicht ab")
        if not record.verify(arguments):
            raise AuthorizationMismatchError("Record-Verify fehlgeschlagen")
