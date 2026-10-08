"""Gate-Executor: Proposal → OPA → Authorization Record. Erzeugt KEINEN Effect.

actor_id/permissions kommen aus dem authentifizierten Kontext (Parameter),
nie aus dem Proposal. Run-Status, Ressourcenversion und Preconditions werden
aus der DB gelesen. OPA-Input und Record beschreiben dieselbe Action:
action/target/args aus dem validierten Proposal, Rest aus trusted Quellen.
"""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from typing import Any

import psycopg

from ..contracts import (
    AuthorizationRecord,
    args_hash,
    canonical_hash,
    record_fields,
)
from ..policy.client import OPAClient, PolicyError
from ..policy.decision import Decision
from .validation import GateRejected, validate_proposal


class GateDenied(Exception):
    def __init__(self, reason: str, decision: Decision | None = None):
        super().__init__(reason)
        self.decision = decision


POLICY_TTL_SECONDS = 300


def authorize(dsn: str, opa: OPAClient, raw_proposal: dict,
              actor_id: str, actor_permissions: list[str],
              ttl_seconds: int = POLICY_TTL_SECONDS) -> AuthorizationRecord:
    proposal = validate_proposal(raw_proposal)
    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(seconds=ttl_seconds)

    with psycopg.connect(dsn, autocommit=False) as c, \
            c.cursor(row_factory=psycopg.rows.dict_row) as cur:
        cur.execute("SELECT status FROM runs WHERE run_id=%s",
                    (proposal.run_id,))
        run = cur.fetchone()
        if run is None:
            raise GateRejected(f"unbekannter run: {proposal.run_id}")
        cur.execute("SELECT version FROM records WHERE record_id=%s",
                    (proposal.target,))
        rec = cur.fetchone()
        resource_version = rec["version"] if rec else -1
        preconditions: dict[str, Any] = {
            "run_active": run["status"] == "active",
            "target_exists": rec is not None,
        }
        ctx_raw = {"run_status": run["status"],
                   "resource_version": resource_version}
        from ..contracts import sha256_hex, canon
        context_hash = sha256_hex(canon(ctx_raw))

        opa_input = {
            "action": proposal.action,
            "actor": {"id": actor_id, "permissions": actor_permissions},
            "run": {"status": run["status"]},
            "resource_version": resource_version,
            "expected_resource_version": proposal.expected_resource_version,
            "expired": False,
            "manual_approval": False,
            "approval_scope": "",
            "action_scope": f"{proposal.action}:{proposal.target}",
        }
        decision = opa.decide(opa_input)  # PolicyError => fail closed, nichts persistiert
        if not decision.granted:
            _persist_denied(cur, proposal, actor_id, decision, context_hash)
            c.commit()
            raise GateDenied(f"denied: allow={decision.allow} "
                             f"violations={list(decision.violations)}", decision)

        ah = args_hash(proposal.arguments)
        fields = record_fields(
            action=proposal.action, target=proposal.target,
            arguments=proposal.arguments, actor_id=actor_id,
            permissions=actor_permissions,
            expected_resource_version=proposal.expected_resource_version,
            preconditions=preconditions, policy_version=decision.policy_version,
            context_hash=context_hash, action_id=str(proposal.action_id),
            expires_at=expires_at)
        ch = canonical_hash(fields)
        key = f"{proposal.run_id}:{proposal.action_id}"
        try:
            cur.execute(
                "INSERT INTO actions (action_id, run_id, action, target, args_hash,"
                " idempotency_key, idempotency_payload_hash, status,"
                " expected_resource_version) VALUES (%s,%s,%s,%s,%s,%s,%s,"
                " 'authorized',%s)",
                (str(proposal.action_id), proposal.run_id, proposal.action,
                 proposal.target, ah, key, ah, proposal.expected_resource_version))
            cur.execute(
                "INSERT INTO authorization_records (action_id, canonical_hash, action,"
                " target, args_hash, actor_id, permissions, expected_resource_version,"
                " preconditions, policy_version, context_hash, expires_at)"
                " VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s::jsonb,%s,%s,%s)",
                (str(proposal.action_id), ch, proposal.action, proposal.target,
                 ah, actor_id, actor_permissions,
                 proposal.expected_resource_version,
                 json.dumps(preconditions), decision.policy_version,
                 context_hash, expires_at))
            cur.execute(
                "INSERT INTO policy_decisions (action_id, decision, policy_version,"
                " context_hash) VALUES (%s,'allow',%s,%s)",
                (str(proposal.action_id), decision.policy_version, context_hash))
            cur.execute(
                "INSERT INTO action_transitions (action_id, old_status, new_status)"
                " VALUES (%s,'proposed','validated'),(%s,'validated','authorized')",
                (str(proposal.action_id), str(proposal.action_id)))
        except Exception as e:
            c.rollback()
            raise GateRejected(f"record-persistenz fehlgeschlagen: {e}") from e
        c.commit()

    return AuthorizationRecord(
        action_id=proposal.action_id, canonical_hash=ch, action=proposal.action,
        target=proposal.target, args_hash=ah, actor_id=actor_id,
        permissions=list(actor_permissions),
        expected_resource_version=proposal.expected_resource_version,
        preconditions=preconditions, policy_version=decision.policy_version,
        context_hash=context_hash, expires_at=expires_at)


def _persist_denied(cur: Any, proposal: Any, actor_id: str,
                    decision: Decision, context_hash: str) -> None:
    key = f"{proposal.run_id}:{proposal.action_id}"
    ah = args_hash(proposal.arguments)
    cur.execute(
        "INSERT INTO actions (action_id, run_id, action, target, args_hash,"
        " idempotency_key, idempotency_payload_hash, status,"
        " expected_resource_version) VALUES (%s,%s,%s,%s,%s,%s,%s,'denied',%s)"
        " ON CONFLICT (action_id) DO NOTHING",
        (str(proposal.action_id), proposal.run_id, proposal.action,
         proposal.target, ah, key, ah, proposal.expected_resource_version))
    cur.execute(
        "INSERT INTO policy_decisions (action_id, decision, policy_version,"
        " context_hash) VALUES (%s,'deny',%s,%s) ON CONFLICT DO NOTHING",
        (str(proposal.action_id), decision.policy_version, context_hash))
