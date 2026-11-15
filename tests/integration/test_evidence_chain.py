"""Phase 3 — F5 (Event-Kette), F6 (Konflikt-Evidenz), F8 (Checkpoint-Anker).

Regeln wie Phase 1/2: echte Runtime-Rollen, Assertions auf persistierten
DB-Zustand. Privilegierte Owner-Eingriffe (Kürzen, Manipulieren) sind
explizit markiert und simulieren einen kompromittierten Owner, keinen
Runtime-Pfad.
"""
import os
import threading
import uuid

import psycopg
import pytest
from psycopg import errors

from control_stack.evidence import (
    VerificationError,
    process_all,
    read_checkpoint,
    verify_run,
    write_checkpoint,
)
from control_stack.evidence.event_writer import TamperError
from control_stack.execution.broker import execute
from control_stack.gate.executor import authorize
from control_stack.policy.client import OPAClient
from control_stack.state.repository import IdempotencyConflictError, Repository
from control_stack.worker.runner import run_execute

ADMIN = ("dbname=control_stack_test user=control_stack password=testpw"
         " host=127.0.0.1 port=5433 connect_timeout=5")
GATE = ("dbname=control_stack_test user=stack_gate password=testpw_gate"
        " host=127.0.0.1 port=5433 connect_timeout=5")
WORKER = ("dbname=control_stack_test user=stack_worker password=testpw_worker"
          " host=127.0.0.1 port=5433 connect_timeout=5")
RECOVERY = ("dbname=control_stack_test user=stack_recovery password=testpw_recovery"
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
        c.execute("INSERT INTO records (record_id) VALUES ('rec-1')")
        c.execute("INSERT INTO records (record_id) VALUES ('rec-2')")
    return OPAClient(OPA, policy_version="test-v1"), rid


def _proposal(rid, target="rec-1", status="approved"):
    return {"action_id": str(uuid.uuid4()), "run_id": rid,
            "action": "demo_update_record", "target": target,
            "arguments": {"record_id": target, "status": status},
            "expected_resource_version": 0}


def _auth(opa, rid, target="rec-1", status="approved"):
    p = _proposal(rid, target, status)
    return authorize(GATE, opa, p, ACTOR, ["records.write"]), p


def _commit(opa, rid, target="rec-1", status="approved"):
    """Autorisiert und führt mit zueinander passenden Argumenten aus."""
    rec, p = _auth(opa, rid, target, status)
    execute(WORKER, str(rec.action_id), dict(p["arguments"]), ACTOR)
    return str(rec.action_id)


def _rows(sql, params=()):
    with _admin() as c, c.cursor() as cur:
        cur.execute(sql, params)
        return cur.fetchall()


def _sequences(rid):
    return [r[0] for r in _rows(
        "SELECT sequence FROM outbox_events WHERE run_id=%s ORDER BY sequence", (rid,))]


def _head(rid):
    row = _rows("SELECT event_hash FROM evidence_ledger WHERE run_id=%s"
                " ORDER BY sequence DESC LIMIT 1", (rid,))
    return row[0][0] if row else None


def _anchor(rid):
    write_checkpoint(RECOVERY, rid, _head(rid))


# -- F5: Sequenz und Vorgängerzeiger --------------------------------------
def test_f5_n1_sequence_is_server_side(live):
    opa, rid = live
    _commit(opa, rid, target="rec-1")
    _commit(opa, rid, target="rec-2", status="rejected")
    rows = _rows("SELECT sequence, event_id, prev_event_id FROM outbox_events"
                 " WHERE run_id=%s ORDER BY sequence", (rid,))
    assert [r[0] for r in rows] == [1, 2]
    assert rows[0][2] is None
    assert rows[1][2] == rows[0][1]


def test_f5_n2_caller_cannot_set_sequence():
    """Weder Funktion noch IPC akzeptieren eine Sequenz."""
    import inspect

    from control_stack.execution import broker

    assert "run_sequence" not in inspect.signature(broker.execute).parameters
    assert "prev_event_hash" not in inspect.signature(broker.execute).parameters


def test_f5_n2_ipc_sequence_field_is_ignored(live):
    """F5: ein run_sequence-Feld im IPC-Request darf die Sequenz nicht ändern."""
    opa, rid = live
    rec, p = _auth(opa, rid)
    out = run_execute(WORKER, {
        "op": "execute", "action_id": str(rec.action_id),
        "arguments": dict(p["arguments"]), "actor_id": ACTOR,
        "event_id": str(uuid.uuid4()),
        # Altlast-Feld: wird ignoriert, darf nicht persistiert werden.
        "run_sequence": 99, "prev_event_hash": "f" * 64,
    })
    assert "new_version" in out
    assert _sequences(rid) == [1]
    row = _rows("SELECT prev_event_id FROM outbox_events WHERE run_id=%s", (rid,))
    assert row[0][0] is None


def test_f5_n3_parallel_commits_have_no_gap(live):
    opa, rid = live
    recs = [_auth(opa, rid, target="rec-1")[0], _auth(opa, rid, target="rec-2")[0]]
    args = [{"record_id": "rec-1", "status": "approved"},
            {"record_id": "rec-2", "status": "approved"}]
    errors_out = []

    def run(rec, a):
        try:
            execute(WORKER, str(rec.action_id), a, ACTOR)
        except Exception as e:  # noqa: BLE001
            errors_out.append(e)

    ts = [threading.Thread(target=run, args=(r, a)) for r, a in zip(recs, args)]
    [t.start() for t in ts]
    [t.join() for t in ts]
    assert not errors_out, errors_out
    assert _sequences(rid) == [1, 2]


def test_f5_n4_gap_is_detected_by_writer(live):
    opa, rid = live
    _commit(opa, rid, target="rec-1")
    _commit(opa, rid, target="rec-2", status="rejected")
    # PRIVILEGIERT: erste Zeile entfernen ⇒ Lücke 1→2 ohne Vorgänger.
    with _admin() as c:
        c.execute("UPDATE outbox_events SET prev_event_id=NULL"
                  " WHERE run_id=%s AND sequence=2", (rid,))
        c.execute("DELETE FROM outbox_events WHERE run_id=%s AND sequence=1", (rid,))
    with pytest.raises(TamperError):
        process_all(WORKER)


def test_f5_n5_forged_prev_pointer_is_rejected(live):
    opa, rid = live
    _commit(opa, rid, target="rec-1")
    _commit(opa, rid, target="rec-2", status="rejected")
    # PRIVILEGIERT: Zeiger der zweiten Zeile fälschen ( zeigt auf sich selbst ).
    with _admin() as c:
        c.execute("UPDATE outbox_events SET prev_event_id=event_id"
                  " WHERE run_id=%s AND sequence=2", (rid,))
    with pytest.raises(TamperError):
        process_all(WORKER)


def test_f5_gap_and_head_breaker_detected_by_verifier(live):
    opa, rid = live
    _commit(opa, rid, target="rec-1")
    _commit(opa, rid, target="rec-2", status="rejected")
    process_all(WORKER)
    _anchor(rid)
    # PRIVILEGIERT: Ledger-Zeile und zugehörige Outbox-Zeile entfernen.
    with _admin() as c:
        c.execute("UPDATE outbox_events SET prev_event_id=NULL"
                  " WHERE run_id=%s AND sequence=2", (rid,))
        c.execute("DELETE FROM evidence_ledger WHERE run_id=%s AND sequence=1", (rid,))
        c.execute("DELETE FROM outbox_events WHERE run_id=%s AND sequence=1", (rid,))
    with pytest.raises(VerificationError):
        verify_run(WORKER, rid)


# -- F6: Idempotenzkonflikt als Evidenz -----------------------------------
def _conflict(opa, rid, payload_hash, target="rec-1"):
    rec, p = _auth(opa, rid, target=target)
    repo = Repository(WORKER)
    with pytest.raises(IdempotencyConflictError):
        repo.commit_demo_update(
            run_id=rid, action_id=str(rec.action_id), record_id=target,
            new_status="rejected", expected_version=0,
            idempotency_key=f"{rid}:{rec.action_id}", payload_hash=payload_hash,
            event_id=str(uuid.uuid4()), guard_arguments=p["arguments"],
            guard_actor_id=ACTOR)
    return str(rec.action_id)


def _conflicts(aid):
    return _rows("SELECT event_id, sequence, event_type, resource_version,"
                 " payload_hash FROM outbox_events WHERE action_id=%s"
                 " AND event_type='idempotency_conflict' ORDER BY sequence", (aid,))


def test_f6_n1_conflict_persists_one_event_without_effect(live):
    opa, rid = live
    aid = _conflict(opa, rid, "b" * 64)
    rows = _conflicts(aid)
    assert len(rows) == 1
    assert rows[0][3] == 0  # resource_version aus der Action
    assert _rows("SELECT COUNT(*) FROM state_transitions")[0][0] == 0
    assert _rows("SELECT version FROM records WHERE record_id='rec-1'")[0][0] == 0
    assert _rows("SELECT status FROM actions WHERE action_id=%s", (aid,))[0][0] == \
        "authorized"


def test_f6_n2_repeated_conflict_is_not_duplicated(live):
    opa, rid = live
    aid = _conflict(opa, rid, "b" * 64)
    _conflict(opa, rid, "b" * 64)
    assert len(_conflicts(aid)) == 1


def test_f6_n3_conflict_event_joins_the_chain(live):
    opa, rid = live
    _commit(opa, rid, target="rec-1")
    process_all(WORKER)
    aid = _conflict(opa, rid, "b" * 64, target="rec-2")
    process_all(WORKER)
    rows = _conflicts(aid)
    assert rows[0][1] == 2  # zweite Zeile der Kette
    assert _sequences(rid) == [1, 2]
    _anchor(rid)
    assert verify_run(WORKER, rid) == 2


def test_empty_run_can_be_anchored(live):
    """Ein Run ohne Events ist mit GENESIS prüfbar (Read-only-Runs)."""
    from control_stack.evidence.integrity import GENESIS

    _, rid = live
    write_checkpoint(RECOVERY, rid, GENESIS)
    assert read_checkpoint(WORKER, rid) == GENESIS
    assert verify_run(WORKER, rid) == 0


# -- F8: Checkpoint als Anker ---------------------------------------------
def test_f8_n1_recovery_cannot_overwrite_checkpoints(live):
    opa, rid = live
    _commit(opa, rid)
    process_all(WORKER)
    _anchor(rid)
    with psycopg.connect(RECOVERY, autocommit=True) as c:
        with pytest.raises(errors.InsufficientPrivilege):
            c.execute("UPDATE evidence_checkpoints SET head_hash=%s WHERE run_id=%s",
                      ("f" * 64, rid))
        with pytest.raises(errors.InsufficientPrivilege):
            c.execute("DELETE FROM evidence_checkpoints WHERE run_id=%s", (rid,))
        with pytest.raises(errors.InsufficientPrivilege):
            c.execute("INSERT INTO evidence_checkpoints (run_id, head_hash)"
                      " VALUES (%s,%s)", (rid, "f" * 64))
    assert len(_rows("SELECT 1 FROM evidence_checkpoints WHERE run_id=%s", (rid,))) == 1


def test_f8_n2_forged_checkpoint_after_truncation_rejected(live):
    opa, rid = live
    _commit(opa, rid, target="rec-1")
    _commit(opa, rid, target="rec-2", status="rejected")
    process_all(WORKER)
    _anchor(rid)
    # PRIVILEGIERT: Kette abschneiden und beim gekürzten Head neu ankern.
    with _admin() as c:
        c.execute("DELETE FROM evidence_ledger WHERE run_id=%s AND sequence=2", (rid,))
        c.execute("DELETE FROM outbox_events WHERE run_id=%s AND sequence=2", (rid,))
    head1 = _head(rid)
    with psycopg.connect(RECOVERY, autocommit=True) as c:
        with pytest.raises(errors.RaiseException) as exc:
            c.execute("SELECT fn_write_checkpoint(%s,%s)", (rid, head1))
    assert "checkpoint_regression" in str(exc.value)


def test_f8_n3_verify_requires_checkpoint(live):
    opa, rid = live
    _commit(opa, rid)
    process_all(WORKER)
    with pytest.raises(VerificationError):
        verify_run(WORKER, rid)


def test_f8_n4_checkpoint_history_is_checked(live):
    """Zwei gültige Anchors; ein Sprung zurück ist ein Bruch."""
    opa, rid = live
    _commit(opa, rid, target="rec-1")
    process_all(WORKER)
    _anchor(rid)
    head1 = read_checkpoint(WORKER, rid)
    _commit(opa, rid, target="rec-2", status="rejected")
    process_all(WORKER)
    _anchor(rid)
    assert read_checkpoint(WORKER, rid) != head1
    assert verify_run(WORKER, rid) == 2
    with psycopg.connect(RECOVERY, autocommit=True) as c:
        with pytest.raises(errors.RaiseException):
            c.execute("SELECT fn_write_checkpoint(%s,%s)", (rid, head1))