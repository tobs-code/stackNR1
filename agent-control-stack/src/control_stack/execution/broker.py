"""Execution-Broker: Record-Reload + Verify + Guarded Write. Kein Vertrauen
in Aufrufer-Werte: action/target/args/actor kommen aus DB + verify().

Reihenfolge: laden → verify → Adapter-Params → atomarer Guarded-Write
(Expiry gegen clock_timestamp() in-Transaktion) → Ergebnis.
Verbindungsabbruch mit unbekanntem Ausgang ⇒ OutcomeUnknown (kein Retry hier).
"""
from __future__ import annotations

import uuid

import psycopg

from ..contracts import AuthorizationRecord, args_hash
from ..state.repository import (
    AuthorizationExpiredError,
    AuthorizationMismatchError,
    AuthorizationMissingError,
    IdempotencyReplay,
    Repository,
    StaleVersionError,
)
from .adapters import AdapterError, demo_update_params
from .idempotency import key_for


class ExecutionDenied(Exception):
    pass


class OutcomeUnknown(Exception):
    def __init__(self, action_id: str, reason: str):
        super().__init__(f"outcome_unknown {action_id}: {reason}")
        self.action_id = action_id


def execute(dsn: str, action_id: str, arguments: dict, actor_id: str,
            event_id: str | None = None,
            run_sequence: int = 1,
            prev_event_hash: str = "0" * 64,
            _test_hook: str | None = None) -> dict | IdempotencyReplay:
    """_test_hook (NUR Tests): 'lost_ack' wirft nach erfolgreichem Commit
    OutcomeUnknown (deterministischer ACK-Verlust); 'kill_before_commit'
    simuliert Backend-Tod vor CAS (Rollback + OutcomeUnknown)."""
    repo = Repository(dsn)
    try:
        action = repo.load_action(action_id)
        stored = repo.load_authorization_record(action_id)
    except psycopg.OperationalError as e:
        raise OutcomeUnknown(action_id, f"laden fehlgeschlagen: {e}") from e
    if action is None or stored is None:
        raise ExecutionDenied("keine persistierte Autorisierung")
    try:
        record = AuthorizationRecord(
            action_id=stored["action_id"],
            canonical_hash=stored["canonical_hash"], action=stored["action"],
            target=stored["target"], args_hash=stored["args_hash"],
            actor_id=stored["actor_id"],
            permissions=list(stored["permissions"]),
            expected_resource_version=stored["expected_resource_version"],
            preconditions=dict(stored["preconditions"]),
            policy_version=stored["policy_version"],
            context_hash=stored["context_hash"],
            expires_at=stored["expires_at"])
    except Exception as e:
        raise ExecutionDenied(f"Record ungültig: {e}") from e
    if record.actor_id != actor_id:
        raise ExecutionDenied("actor weicht ab")
    if action["action"] != record.action or action["target"] != record.target:
        raise ExecutionDenied("action/target weichen vom Record ab")
    if not record.verify(arguments):
        raise ExecutionDenied("Record-Verify fehlgeschlagen")
    if action["action"] == "demo_read":
        if set(arguments) != {"record_id"}:
            raise ExecutionDenied("demo_read: nur record_id")
        try:
            return repo.execute_read(
                action_id=action_id, record_id=record.target,
                guard_arguments=arguments, guard_actor_id=actor_id)
        except (AuthorizationMissingError, AuthorizationExpiredError,
                AuthorizationMismatchError, StaleVersionError) as e:
            raise ExecutionDenied(str(e)) from e
        except psycopg.OperationalError as e:
            raise OutcomeUnknown(action_id, str(e)) from e
    if action["action"] != "demo_update_record":
        raise ExecutionDenied(f"nicht ausführbar: {action['action']}")
    try:
        params = demo_update_params(arguments)
    except AdapterError as e:
        raise ExecutionDenied(str(e)) from e

    payload = args_hash(arguments)
    if _test_hook == "kill_before_commit":
        # Deterministischer Backend-Tod: Tx bricht ab, Ausgang unbekannt.
        raise OutcomeUnknown(action_id, "injected kill_before_commit")
    try:
        out = repo.commit_demo_update(
            run_id=action["run_id"], action_id=action_id,
            record_id=params["record_id"], new_status=params["new_status"],
            expected_version=record.expected_resource_version,
            idempotency_key=key_for(action["run_id"], action_id),
            payload_hash=payload,
            event_id=event_id or str(uuid.uuid4()),
            run_sequence=run_sequence, prev_event_hash=prev_event_hash,
            guard_arguments=arguments, guard_actor_id=actor_id)
        if _test_hook == "lost_ack":
            # Commit steht in der DB, ACK geht "verloren".
            raise OutcomeUnknown(action_id, "injected lost_ack")
        return out
    except (AuthorizationMissingError, AuthorizationExpiredError,
            AuthorizationMismatchError) as e:
        raise ExecutionDenied(str(e)) from e
    except psycopg.OperationalError as e:
        # Commit-Ausgang unbekannt (Effect evtl. doch geschrieben) ⇒
        # outcome_unknown, Reconcile statt Retry.
        raise OutcomeUnknown(action_id, str(e)) from e
