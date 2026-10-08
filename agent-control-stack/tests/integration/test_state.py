"""Integrationstests state: echter DB-Zustand, keine reinen Rückgabewerte.

DSN: CONTROL_STACK_TEST_DSN oder default localhost:5433.
"""
import os
import threading
import uuid

import psycopg
import pytest

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
SCHEMA = os.path.join(os.path.dirname(__file__), "..", "..", "src",
                      "control_stack", "state", "schema.sql")


def _db():
    return psycopg.connect(DSN, autocommit=True)


@pytest.fixture()
def repo():
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


def _commit(repo, rid, key_suffix, expected=0, record="rec-1"):
    return repo.commit_demo_update(
        run_id=rid, action_id=str(uuid.uuid4()),
        record_id=record, new_status="approved",
        expected_version=expected,
        idempotency_key=f"{rid}:{key_suffix}",
        payload_hash="a" * 64, event_id=str(uuid.uuid4()),
        run_sequence=int(key_suffix) if key_suffix.isdigit() else 1,
        prev_event_hash="0" * 64)


def test_valid_write_single_effect(repo):
    r, rid = repo
    res = _commit(r, rid, "1")
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
    outcomes = []

    def w(i):
        try:
            _commit(r, rid, f"9{i}")
            outcomes.append("win")
        except StaleVersionError:
            outcomes.append("stale")

    ts = [threading.Thread(target=w, args=(i,)) for i in range(5)]
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
    key = "42"
    first = _commit(r, rid, key)
    again = r.commit_demo_update(
        run_id=rid, action_id=str(uuid.uuid4()), record_id="rec-1",
        new_status="approved", expected_version=0,
        idempotency_key=f"{rid}:{key}", payload_hash="a" * 64,
        event_id=str(uuid.uuid4()), run_sequence=99,
        prev_event_hash="0" * 64)
    assert isinstance(again, IdempotencyReplay)
    assert again.result == first
    with _db() as c, c.cursor() as cur:
        cur.execute("SELECT version FROM records WHERE record_id='rec-1'")
        assert cur.fetchone()[0] == 1


def test_same_key_other_payload_conflict(repo):
    r, rid = repo
    _commit(r, rid, "7")
    with pytest.raises(IdempotencyConflictError):
        r.commit_demo_update(
            run_id=rid, action_id=str(uuid.uuid4()), record_id="rec-1",
            new_status="rejected", expected_version=1,
            idempotency_key=f"{rid}:7", payload_hash="b" * 64,
            event_id=str(uuid.uuid4()), run_sequence=2,
            prev_event_hash="0" * 64)


def test_missing_record_no_effect(repo):
    r, rid = repo
    with pytest.raises(StaleVersionError) as e:
        _commit(r, rid, "3", record="nope")
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
