"""Evidence-Tests: Outbox-Korrektheit UND Ketten-Integrität, getrennt."""
import os
import threading
import uuid

import psycopg
import pytest

from control_stack.evidence import (
    VerificationError,
    process_all,
    process_next,
    read_checkpoint,
    verify_run,
    write_checkpoint,
)
from control_stack.execution.broker import execute
from control_stack.gate.executor import authorize
from control_stack.policy.client import OPAClient

ADMIN = ("dbname=control_stack_test user=control_stack password=testpw"
         " host=127.0.0.1 port=5433 connect_timeout=5")
WORKER = ("dbname=control_stack_test user=stack_worker password=testpw_worker"
          " host=127.0.0.1 port=5433 connect_timeout=5")
RECOVERY = ("dbname=control_stack_test user=stack_recovery password=testpw_recovery"
            " host=127.0.0.1 port=5433 connect_timeout=5")
GATE = ("dbname=control_stack_test user=stack_gate password=testpw_gate"
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
    with _admin() as c:
        rid = f"run-{uuid.uuid4().hex[:8]}"
        c.execute("INSERT INTO runs (run_id, owner) VALUES (%s,'t')", (rid,))
        c.execute("INSERT INTO records (record_id) VALUES ('rec-1')")
        c.execute("INSERT INTO records (record_id) VALUES ('rec-2')")
    return OPAClient(OPA, policy_version="test-v1"), rid


def _do(opa, rid, target="rec-1", status="approved", seq=1):
    p = {"action_id": str(uuid.uuid4()), "run_id": rid,
         "action": "demo_update_record", "target": target,
         "arguments": {"record_id": target, "status": status},
         "expected_resource_version": 0}
    rec = authorize(GATE, opa, p, ACTOR, ["records.write"])
    execute(WORKER, str(rec.action_id), dict(p["arguments"]), ACTOR,
            run_sequence=seq, prev_event_hash="0" * 64)
    return str(rec.action_id)


def test_effect_and_outbox_atomic_and_verified(live):
    opa, rid = live
    _do(opa, rid)
    assert process_all(WORKER) != []
    assert verify_run(WORKER, rid) == 1


def test_double_processing_no_duplicates(live):
    opa, rid = live
    _do(opa, rid)
    assert len(process_all(WORKER)) == 1
    assert process_all(WORKER) == []
    with _admin() as c, c.cursor() as cur:
        cur.execute("SELECT COUNT(*) FROM evidence_ledger")
        assert cur.fetchone()[0] == 1
    assert verify_run(WORKER, rid) == 1


def test_concurrent_writers_no_loss_no_dup(live):
    opa, rid = live
    _do(opa, rid, target="rec-1", seq=1)
    _do(opa, rid, target="rec-2", seq=2)
    outs = []

    def w():
        outs.extend(process_all(WORKER))

    ts = [threading.Thread(target=w) for _ in range(4)]
    [t.start() for t in ts]
    [t.join() for t in ts]
    assert sorted(outs) == sorted(set(outs)) and len(outs) == 2
    assert verify_run(WORKER, rid) == 2


def test_tampered_outbox_payload_detected(live):
    opa, rid = live
    _do(opa, rid)
    process_all(WORKER)
    with _admin() as c:
        c.execute("UPDATE outbox_events SET payload_hash=%s", ("f" * 64,))
    with pytest.raises(VerificationError):
        verify_run(WORKER, rid)


def test_tampered_ledger_hash_detected(live):
    opa, rid = live
    _do(opa, rid)
    process_all(WORKER)
    with _admin() as c:
        c.execute("UPDATE evidence_ledger SET event_hash=%s", ("e" * 64,))
    with pytest.raises(VerificationError):
        verify_run(WORKER, rid)


def test_deleted_event_detected(live):
    opa, rid = live
    _do(opa, rid)
    process_all(WORKER)
    with _admin() as c:
        c.execute("DELETE FROM evidence_ledger")
    with pytest.raises(VerificationError):
        verify_run(WORKER, rid)


def test_truncated_chain_vs_checkpoint_detected(live):
    opa, rid = live
    _do(opa, rid, target="rec-1", seq=1)
    _do(opa, rid, target="rec-2", seq=2)
    process_all(WORKER)
    with _admin() as c, c.cursor() as cur:
        cur.execute("SELECT event_hash FROM evidence_ledger ORDER BY sequence DESC LIMIT 1")
        head = cur.fetchone()[0]
    write_checkpoint(RECOVERY, rid, head)
    assert read_checkpoint(WORKER, rid) == head
    assert verify_run(WORKER, rid, checkpoint=head) == 2
    with _admin() as c:  # Kette abschneiden (Angreifer mit Owner-Rechten)
        c.execute("DELETE FROM evidence_ledger WHERE sequence=2")
        c.execute("DELETE FROM outbox_events WHERE sequence=2")
    with pytest.raises(VerificationError):
        verify_run(WORKER, rid, checkpoint=head)


def test_writer_cannot_write_checkpoints(live):
    from psycopg import errors
    opa, rid = live
    _do(opa, rid)
    with psycopg.connect(WORKER, autocommit=True) as c:
        with pytest.raises(errors.InsufficientPrivilege):
            c.execute("INSERT INTO evidence_checkpoints (run_id, head_hash)"
                      " VALUES (%s,'x')", (rid,))
