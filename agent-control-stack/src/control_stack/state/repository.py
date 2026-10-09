"""State-Repository: Transaktionen, CAS, Lifecycle, Idempotenz, Outbox.

Fehlersemantik (keine stillen Retries, keine generischen Fehler):
- StaleVersionError: CAS rowcount=0 (Konflikt oder Ziel fehlt; Ursache im Feld).
- IdempotencyConflictError: gleicher Key, anderer Payload.
- IdempotencyReplay: KEIN Fehler — dataclass mit gespeichertem Ergebnis.
- IllegalTransitionError: contracts.transition schlägt fehl.
Jede commit_*-Methode läuft in EINER Transaktion; Fehler ⇒ Rollback.
"""
from __future__ import annotations

from dataclasses import dataclass

import psycopg
from psycopg import errors as _pgerrors

from ..contracts import transition


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


class RunInactiveError(Exception):
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

    # -- Atomarer Demo-Write (Phase 1: DB-erzwungene Grenze, ADR-001) ----
    def commit_demo_update(self, *, run_id: str, action_id: str,
                           record_id: str, new_status: str,
                           expected_version: int, idempotency_key: str,
                           payload_hash: str, event_id: str,
                           run_sequence: int,
                           prev_event_hash: str,
                           guard_arguments: dict | None = None,
                           guard_actor_id: str | None = None,
                           _test_hook: str | None = None) -> dict | IdempotencyReplay:
        """Geschützter Write ausschliesslich über fn_execute_write (Owner-Kontext).

        Die Funktion prüft in EINER Transaktion: Auth-Record (Existenz, Ablauf,
        Actor, Feldgleichheit), F1-Zielbindung (record == autorisiertes target),
        Payload-Bindung, Idempotenz, F2-Run-Status (Zeile gesperrt), CAS.
        Direkte DML-Umgehung per Runtime-Credentials scheitert an den Grants.
        Replay-Fall: IdempotencyReplay ohne Effect. _test_hook='kill_mid_tx'
        (TEST-ONLY) beendet das eigene Backend in offener Tx.
        """
        hook = _test_hook if _test_hook == "kill_mid_tx" else None
        with self._conn() as c, c.cursor(row_factory=psycopg.rows.dict_row) as cur:
            try:
                cur.execute(
                    "SELECT fn_execute_write(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",
                    (action_id, run_id, record_id, new_status,
                     expected_version, idempotency_key, payload_hash,
                     event_id, run_sequence, prev_event_hash,
                     guard_actor_id or "", hook))
            except _pgerrors.RaiseException as e:
                raise _map_function_error(e, record_id, expected_version) from e
            payload = cur.fetchone()["fn_execute_write"]
            if isinstance(payload, dict) and "replay" in payload:
                return IdempotencyReplay(result=payload["replay"])
            return payload

    # -- Read-Pfad (Rev. 5 + Phase 1): effect-frei, aber autorisierungs- --
    # -- gebunden über fn_execute_read (Owner-Kontext). Lifecycle endet    --
    # -- terminal bei confirmed; Leseergebnis als result persistiert.      --
    def execute_read(self, *, action_id: str, record_id: str,
                     guard_arguments: dict, guard_actor_id: str) -> dict:
        from ..contracts import args_hash as _args_hash
        with self._conn() as c, c.cursor(row_factory=psycopg.rows.dict_row) as cur:
            try:
                cur.execute("SELECT fn_execute_read(%s,%s,%s)",
                            (action_id, guard_actor_id,
                             _args_hash(guard_arguments)))
            except _pgerrors.RaiseException as e:
                raise _map_function_error(e, record_id, -1) from e
            return cur.fetchone()["fn_execute_read"]


def _map_function_error(e: _pgerrors.RaiseException, record_id: str,
                        expected: int) -> Exception:
    """Funktions-Fehler (Phase-1-Grenze) → Domänen-Exceptions. Fail closed:
    Unbekannte Fehler bleiben RaiseException (kein stilles Mapping)."""
    msg = (str(e).splitlines() or [""])[0]
    if msg.startswith("auth_missing:"):
        return AuthorizationMissingError(msg)
    if msg.startswith("auth_expired:"):
        return AuthorizationExpiredError(msg)
    if msg.startswith("auth_mismatch:"):
        return AuthorizationMismatchError(msg)
    if msg.startswith("run_inactive:"):
        return RunInactiveError(msg)
    if msg.startswith("idempotency_conflict:"):
        return IdempotencyConflictError(msg)
    if msg.startswith("stale_version|"):
        parts = msg.split("|")
        try:
            exp = int(parts[2])
        except (IndexError, ValueError):
            exp = expected
        found = parts[3] if len(parts) > 3 else "conflict-or-missing"
        rid = parts[1] if len(parts) > 1 else record_id
        return StaleVersionError(rid, exp, found)
    return e
