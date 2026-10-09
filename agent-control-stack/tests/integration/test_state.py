"""Integrationstests state: echter DB-Zustand, keine reinen Rückgabewerte.

Seit Phase 1 (ADR-001) läuft jeder Write über den autorisierten Pfad
(gate.authorize → broker.execute → DEFINER-Funktion); guard-lose
Direkt-Commits ohne Authorization Record werden abgewiesen (I1).

DSN: CONTROL_STACK_TEST_DSN oder default localhost:5433.
"""
import os
import threading
import uuid

import psycopg
import pytest

from control_stack.execution.broker import execute
from control_stack.gate.executor import authorize
from control_stack.policy.client import OPAClient
from control_stack.state.repository import (
    IdempotencyConflictError,
    IdempotencyReplay,
    IllegalTransitionError,
    Repository,
    StaleVersionError,
)

DSN = os.environ.get(
    "CONTROL_STACK_TEST_DSN",
    "dbname=control_stack user=control_stack password=testpw host=127.0.0.1 port=5433 connect_timeout=5",
)
ADMIN = ("dbname=control_stack_test user=control_stack password=testpw"
         " host=127.0.0.1 port=5433 connect_timeout=5")
OPA = os.environ.get("CONTROL_STACK_OPA_URL", "http://127.0.0.1:8181")
SCHEMA = os.path.join(os.path.dirname(__file__), "..", "..", "src",
                      "control_stack", "state", "schema.sql")
ACTOR = "agent-1"


def _db():
    return psycopg.connect(DSN, autocommit=True)


@pytest.fixture()
def repo():
    from control_stack.mig.runner import migrate
    migrate(DSN)
    sql = open(os.path.abspath(SCHEMA), encoding="utf-8").read()
    with _db() as c:
        c.execute(sql)
        for t in ("recovery_jobs", "outbox_events", "state_transitions", "action_transitions",
                  "policy_decisions", "authorization_records", "actions",
                  "records", "runs"):
            c.execute(f"DELETE FROM {t}")
        rid = f"run-{uuid.uuid4().hex[:8]}"
        c.execute("INSERT INTO runs (run_id, owner) VALUES (%s,'t')", (rid,))
        c.execute("INSERT INTO records (record_id) VALUES ('rec-1')")
    return Repository(DSN), rid


def _auth(rid, record="rec-1", status="approved", expected=0):
    opa = OPAClient(OPA, policy_version="test-v1")
    p = {"action_id": str(uuid.uuid4()), "run_id": rid,
         "action": "demo_update_record", "target": record,
         "arguments": {"record_id": record, "status": status},
         "expected_resource_version": expected}
    rec = authorize(DSN, opa, p, ACTOR, ["records.write"])
    return str(rec.action_id), p["arguments"]


def _commit(rid, key_suffix, expected=0, record="rec-1"):
    aid, args = _auth(rid, record=record, expected=expected)
    return execute(DSN, aid, dict(args), ACTOR)


def test_valid_write_single_effect(repo):
    r, rid = repo
    res = _commit(rid, "1")
    assert res["new_version"] == 1
    with _db() as c, c.cursor() as cur:
        cur.execute("SELECT version, status FROM records WHERE record_id='rec-1'")
        assert cur.fetchone() == (1, "approved")
        cur.execute("SELECT COUNT(*) FROM state_transitions")
        assert cur.fetchone()[0] == 1
        cur.execute("SELECT COUNT(*) FROM outbox_events WHERE event_type='state_committed'")
        assert cur.fetchone()[0] == 1


def test_concurrent_same_version_one_winner(repo):
    r, rid = repo
    # Fünf unabhängige autorisierte Actions auf Version 0, parallele Ausführung.
    prepared = [_auth(rid) for _ in range(5)]
    outcomes = []

    def w(prep):
        aid, args = prep
        try:
            execute(DSN, aid, dict(args), ACTOR)
            outcomes.append("win")
        except StaleVersionError:
            outcomes.append("stale")

    ts = [threading.Thread(target=w, args=(p,)) for p in prepared]
    [t.start() for t in ts]
    [t.join() for t in ts]
    assert outcomes.count("win") == 1
    assert outcomes.count("stale") == 4
    with _db() as c, c.cursor() as cur:
        cur.execute("SELECT version FROM records WHERE record_id='rec-1'")
        assert cur.fetchone()[0] == 1
        cur.execute("SELECT COUNT(*) FROM state_transitions")
        assert cur.fetchone()[0] == 1


def test_replay_same_key_no_second_effect(repo):
    r, rid = repo
    repo_obj, _ = repo
    aid, args = _auth(rid)
    first = execute(DSN, aid, dict(args), ACTOR)
    again = execute(DSN, aid, dict(args), ACTOR)
    assert isinstance(again, IdempotencyReplay)
    assert again.result == first
    with _db() as c, c.cursor() as cur:
        cur.execute("SELECT version FROM records WHERE record_id='rec-1'")
        assert cur.fetchone()[0] == 1


def test_same_key_other_payload_conflict(repo):
    repo_obj, rid = repo
    aid, args = _auth(rid)
    execute(DSN, aid, dict(args), ACTOR)
    # Gleicher Key, anderer Payload direkt am Repository (umgeht keinen
    # Gate-Check, sondern trifft die Idempotenz-Prüfung in der Funktion).
    with pytest.raises(IdempotencyConflictError):
        repo_obj.commit_demo_update(
            run_id=rid, action_id=aid, record_id="rec-1",
            new_status="rejected", expected_version=1,
            idempotency_key=f"{rid}:{aid}", payload_hash="b" * 64,
            event_id=str(uuid.uuid4()), run_sequence=2,
            prev_event_hash="0" * 64,
            guard_arguments={"record_id": "rec-1", "status": "rejected"},
            guard_actor_id=ACTOR)


def test_missing_record_no_effect(repo):
    r, rid = repo
    aid, args = _auth(rid)
    with _db() as c:
        c.execute("DELETE FROM records WHERE record_id='rec-1'")
    # Broker lässt StaleVersionError durch (kein Effect, keine Transition).
    with pytest.raises(StaleVersionError) as e:
        execute(DSN, aid, dict(args), ACTOR)
    assert e.value.found == "missing"
    with _db() as c, c.cursor() as cur:
        cur.execute("SELECT COUNT(*) FROM state_transitions")
        assert cur.fetchone()[0] == 0


def test_illegal_lifecycle_rejected(repo):
    r, rid = repo
    aid = str(uuid.uuid4())
    r.create_action(action_id=aid, run_id=rid,
                    action="demo_read", target="rec-1", args_hash="c" * 64,
                    idempotency_key=f"{rid}:x1", payload_hash="c" * 64,
                    expected_resource_version=0)
    with pytest.raises(IllegalTransitionError):
        # proposed -> executing ist verboten
        r.transition_action(aid, "proposed", "executing")
    # DB-Zustand unverändert: kein Effect, Status weiter proposed
    assert r.load_action(aid)["status"] == "proposed"
