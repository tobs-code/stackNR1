"""Execution-End-to-End: gate.authorize → broker.execute, echter DB-Zustand."""
import os
import threading
import uuid

import psycopg
import pytest

from control_stack.execution.broker import (
    ExecutionDenied,
    OutcomeUnknown,
    execute,
)
from control_stack.gate.executor import GateDenied, authorize
from control_stack.policy.client import OPAClient
from control_stack.state.repository import IdempotencyReplay

DSN = os.environ.get(
    "CONTROL_STACK_TEST_DSN",
    "dbname=control_stack user=control_stack password=testpw host=127.0.0.1 port=5433 connect_timeout=5",
)
OPA = os.environ.get("CONTROL_STACK_OPA_URL", "http://127.0.0.1:8181")
SCHEMA = os.path.abspath(os.path.join(
    os.path.dirname(__file__), "..", "..", "src", "control_stack", "state", "schema.sql"))

ACTOR = "agent-1"
ARGS = {"record_id": "rec-1", "status": "approved"}


def _db():
    return psycopg.connect(DSN, autocommit=True)


@pytest.fixture()
def live():
    with _db() as c:
        c.execute(open(SCHEMA, encoding="utf-8").read())
        for t in ("recovery_jobs", "outbox_events", "state_transitions", "action_transitions",
                  "policy_decisions", "authorization_records", "actions",
                  "records", "runs"):
            c.execute(f"DELETE FROM {t}")
        rid = f"run-{uuid.uuid4().hex[:8]}"
        c.execute("INSERT INTO runs (run_id, owner) VALUES (%s,'t')", (rid,))
        c.execute("INSERT INTO records (record_id) VALUES ('rec-1')")
    return OPAClient(OPA, policy_version="test-v1"), rid


def _auth(opa, rid, **kw):
    p = {"action_id": str(uuid.uuid4()), "run_id": rid,
         "action": "demo_update_record", "target": "rec-1",
         "arguments": dict(ARGS), "expected_resource_version": 0}
    p.update(kw)
    return authorize(DSN, opa, p, ACTOR, ["records.write"]), p


def _version():
    with _db() as c, c.cursor() as cur:
        cur.execute("SELECT version FROM records WHERE record_id='rec-1'")
        return cur.fetchone()[0]


def test_valid_record_atomic_effect(live):
    opa, rid = live
    rec, _ = _auth(opa, rid)
    res = execute(DSN, str(rec.action_id), dict(ARGS), ACTOR)
    assert res["new_version"] == 1
    with _db() as c, c.cursor() as cur:
        cur.execute("SELECT version, status FROM records WHERE record_id='rec-1'")
        assert cur.fetchone() == (1, "approved")
        cur.execute("SELECT status, result FROM actions WHERE action_id=%s",
                    (str(rec.action_id),))
        st, result = cur.fetchone()
        assert st == "committed" and result["new_version"] == 1
        cur.execute("SELECT COUNT(*) FROM state_transitions")
        assert cur.fetchone()[0] == 1
        cur.execute("SELECT new_status FROM action_transitions WHERE action_id=%s ORDER BY seq",
                    (str(rec.action_id),))
        assert [r[0] for r in cur.fetchall()] == [
            "validated", "authorized", "executing", "confirmed", "committed"]
        cur.execute("SELECT COUNT(*) FROM outbox_events")
        assert cur.fetchone()[0] == 1


def test_missing_record_no_effect(live):
    _, _rid = live
    with pytest.raises(ExecutionDenied):
        execute(DSN, str(uuid.uuid4()), dict(ARGS), ACTOR)
    assert _version() == 0


def test_tampered_record_no_effect(live):
    opa, rid = live
    rec, _ = _auth(opa, rid)
    with _db() as c:
        c.execute("UPDATE authorization_records SET permissions=%s WHERE action_id=%s",
                  (["records.read"], str(rec.action_id)))
    with pytest.raises(ExecutionDenied):
        execute(DSN, str(rec.action_id), dict(ARGS), ACTOR)
    assert _version() == 0


def test_expired_record_no_effect(live):
    opa, rid = live
    rec, p = _auth(opa, rid)
    with _db() as c:
        c.execute("UPDATE authorization_records SET expires_at=clock_timestamp()"
                  " WHERE action_id=%s", (str(rec.action_id),))
    with pytest.raises(ExecutionDenied):
        execute(DSN, str(rec.action_id), dict(ARGS), ACTOR)
    assert _version() == 0


def test_actor_mismatch_no_effect(live):
    opa, rid = live
    rec, _ = _auth(opa, rid)
    with pytest.raises(ExecutionDenied):
        execute(DSN, str(rec.action_id), dict(ARGS), "attacker")
    assert _version() == 0


def test_args_mismatch_no_effect(live):
    opa, rid = live
    rec, _ = _auth(opa, rid)
    with pytest.raises(ExecutionDenied):
        execute(DSN, str(rec.action_id),
                {"record_id": "rec-1", "status": "rejected"}, ACTOR)
    assert _version() == 0


def test_concurrent_same_action_one_effect_plus_replay(live):
    opa, rid = live
    rec, _ = _auth(opa, rid)
    aid = str(rec.action_id)
    outs = []

    def run():
        try:
            outs.append(execute(DSN, aid, dict(ARGS), ACTOR))
        except Exception as e:  # noqa: BLE001
            outs.append(e)

    ts = [threading.Thread(target=run) for _ in range(4)]
    [t.start() for t in ts]
    [t.join() for t in ts]
    assert _version() == 1
    # Genau ein Dict-Effekt; Rest Replay oder klassifizierter Fehler, nie zweiter Effect
    dicts = [o for o in outs if isinstance(o, dict)]
    assert len(dicts) == 1
    for o in outs:
        if isinstance(o, IdempotencyReplay):
            assert o.result == dicts[0]


def test_outbox_failure_rolls_back_everything(live):
    opa, rid = live
    rec, _ = _auth(opa, rid)
    crashed_event = str(uuid.uuid4())
    with _db() as c:
        # Kollision provozieren: Outbox-Insert im Write muss scheitern
        c.execute(
            "INSERT INTO outbox_events (event_id, run_id, action_id, sequence,"
            " event_type, resource_version, payload_hash, previous_event_hash)"
            " VALUES (%s,%s,%s,1,'state_committed',1,%s,%s)",
            (crashed_event, rid, str(rec.action_id), "0" * 64, "0" * 64))
    with pytest.raises(Exception):
        execute(DSN, str(rec.action_id), dict(ARGS), ACTOR,
                event_id=crashed_event)
    with _db() as c, c.cursor() as cur:
        cur.execute("SELECT version FROM records WHERE record_id='rec-1'")
        assert cur.fetchone()[0] == 0  # Ressourcen-Write zurückgerollt
        cur.execute("SELECT status, result FROM actions WHERE action_id=%s",
                    (str(rec.action_id),))
        st, result = cur.fetchone()
        assert result is None and st != "committed"
        cur.execute("SELECT COUNT(*) FROM state_transitions")
        assert cur.fetchone()[0] == 0
