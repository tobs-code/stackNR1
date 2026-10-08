"""Abnahme-Closeout: demo_read-Scope, I6 deterministisch, I7 Deny-Fingerprint."""
import os
import uuid

import psycopg
import pytest

from control_stack.execution.broker import ExecutionDenied, OutcomeUnknown, execute
from control_stack.gate.executor import GateDenied, authorize
from control_stack.policy.client import OPAClient
from control_stack.recovery import reconcile

ADMIN = ("dbname=control_stack_test user=control_stack password=testpw"
         " host=127.0.0.1 port=5433 connect_timeout=5")
GATE = ("dbname=control_stack_test user=stack_gate password=testpw_gate"
        " host=127.0.0.1 port=5433 connect_timeout=5")
WORKER = ("dbname=control_stack_test user=stack_worker password=testpw_worker"
          " host=127.0.0.1 port=5433 connect_timeout=5")
OPA = os.environ.get("CONTROL_STACK_OPA_URL", "http://127.0.0.1:8181")
ACTOR = "agent-1"


def _admin():
    return psycopg.connect(ADMIN, autocommit=True)


@pytest.fixture()
def live():
    from control_stack.mig.runner import migrate
    migrate(ADMIN)
    with _admin() as c:
        for t in ("evidence_checkpoints", "evidence_ledger", "recovery_jobs",
                  "outbox_events", "state_transitions", "action_transitions",
                  "policy_decisions", "authorization_records", "actions",
                  "records", "runs"):
            c.execute(f"DELETE FROM {t}")
        rid = f"run-{uuid.uuid4().hex[:8]}"
        c.execute("INSERT INTO runs (run_id, owner) VALUES (%s,'t')", (rid,))
        c.execute("INSERT INTO records (record_id, status) VALUES ('rec-1','approved')")
    return OPAClient(OPA, policy_version="test-v1"), rid


def _read_proposal(rid):
    return {"action_id": str(uuid.uuid4()), "run_id": rid, "action": "demo_read",
            "target": "rec-1", "arguments": {"record_id": "rec-1"},
            "expected_resource_version": 0}


def test_demo_read_returns_data_no_state_change(live):
    opa, rid = live
    rec = authorize(GATE, opa, _read_proposal(rid), ACTOR, ["records.read"])
    out = execute(WORKER, str(rec.action_id), {"record_id": "rec-1"}, ACTOR)
    assert out == {"record_id": "rec-1", "status": "approved", "version": 0}
    with _admin() as c, c.cursor() as cur:
        cur.execute("SELECT version FROM records WHERE record_id='rec-1'")
        assert cur.fetchone()[0] == 0
        cur.execute("SELECT COUNT(*) FROM state_transitions")
        assert cur.fetchone()[0] == 0
        cur.execute("SELECT COUNT(*) FROM outbox_events")
        assert cur.fetchone()[0] == 0
        cur.execute("SELECT status FROM actions WHERE action_id=%s",
                    (str(rec.action_id),))
        assert cur.fetchone()[0] == "confirmed"


def test_demo_read_tamper_denied(live):
    opa, rid = live
    rec = authorize(GATE, opa, _read_proposal(rid), ACTOR, ["records.read"])
    with pytest.raises(ExecutionDenied):
        execute(WORKER, str(rec.action_id), {"record_id": "rec-2"}, ACTOR)


def test_demo_read_needs_read_permission(live):
    opa, rid = live
    with pytest.raises(Exception):
        authorize(GATE, opa, _read_proposal(rid), ACTOR, ["records.write"])


def test_lost_ack_replays_stored_result(live):
    """I6 deterministisch (a): Commit steht, ACK verloren → Replay, 1 Effect."""
    opa, rid = live
    p = {"action_id": str(uuid.uuid4()), "run_id": rid,
         "action": "demo_update_record", "target": "rec-1",
         "arguments": {"record_id": "rec-1", "status": "approved"},
         "expected_resource_version": 0}
    rec = authorize(GATE, opa, p, ACTOR, ["records.write"])
    with pytest.raises(OutcomeUnknown):
        execute(WORKER, str(rec.action_id), dict(p["arguments"]), ACTOR,
                _test_hook="lost_ack")
    insp = reconcile(ADMIN, str(rec.action_id), rid)
    assert insp.outcome == "replayed" and insp.result["new_version"] == 1
    with _admin() as c, c.cursor() as cur:
        cur.execute("SELECT version FROM records WHERE record_id='rec-1'")
        assert cur.fetchone()[0] == 1
        cur.execute("SELECT COUNT(*) FROM state_transitions WHERE action_id=%s",
                    (str(rec.action_id),))
        assert cur.fetchone()[0] == 1


def test_kill_before_commit_retries_once(live):
    """I6 deterministisch (b): Tod vor Commit → Rollback → genau 1 Retry."""
    opa, rid = live
    p = {"action_id": str(uuid.uuid4()), "run_id": rid,
         "action": "demo_update_record", "target": "rec-1",
         "arguments": {"record_id": "rec-1", "status": "approved"},
         "expected_resource_version": 0}
    rec = authorize(GATE, opa, p, ACTOR, ["records.write"])
    with pytest.raises(OutcomeUnknown):
        execute(WORKER, str(rec.action_id), dict(p["arguments"]), ACTOR,
                _test_hook="kill_before_commit")
    assert reconcile(ADMIN, str(rec.action_id), rid).outcome == "retry_allowed"
    res = execute(WORKER, str(rec.action_id), dict(p["arguments"]), ACTOR)
    assert res["new_version"] == 1
    with _admin() as c, c.cursor() as cur:
        cur.execute("SELECT version FROM records WHERE record_id='rec-1'")
        assert cur.fetchone()[0] == 1


def test_deny_fingerprint_repeat_then_changed_allows(live):
    """I7: Deny → Repeat (repeat_of) → geänderte Voraussetzung → Allow."""
    opa, rid = live
    base = {"run_id": rid, "action": "demo_update_record", "target": "rec-1",
            "arguments": {"record_id": "rec-1", "status": "approved"},
            "expected_resource_version": 0}
    with pytest.raises(GateDenied) as e1:
        authorize(GATE, opa, {**base, "action_id": str(uuid.uuid4())},
                  ACTOR, ["records.read"])
    assert "repeat_of" not in str(e1.value)
    with pytest.raises(GateDenied) as e2:
        authorize(GATE, opa, {**base, "action_id": str(uuid.uuid4())},
                  ACTOR, ["records.read"])
    assert "repeat_of" in str(e2.value)
    rec = authorize(GATE, opa, {**base, "action_id": str(uuid.uuid4())},
                    ACTOR, ["records.write"])  # geänderte Permission
    assert rec.verify(dict(base["arguments"]))
