"""Phase 2 — F3 (Lifecycle-Historie) und F10 (Pair-CHECK, dead code).

Regeln wie Phase 1: echte Runtime-Rollen, Assertions auf persistierten
DB-Zustand. Privilegierte Owner-Eingriffe sind explizit markiert und
simulieren einen kompromittierten Owner, keinen Runtime-Pfad.
"""
import json
import os
import threading
import uuid

import psycopg
import pytest
from psycopg import errors

from control_stack.contracts import PAIRS
from control_stack.execution.broker import ExecutionDenied, execute
from control_stack.gate.executor import GateDenied, authorize
from control_stack.policy.client import OPAClient
from control_stack.recovery import reconcile

ADMIN = ("dbname=control_stack_test user=control_stack password=testpw"
         " host=127.0.0.1 port=5433 connect_timeout=5")
OPA = os.environ.get("CONTROL_STACK_OPA_URL", "http://127.0.0.1:8181")
ACTOR = "agent-1"
ARGS = {"record_id": "rec-1", "status": "approved"}
STATUSES = ["proposed", "validated", "authorized", "executing", "confirmed",
            "failed", "outcome_unknown", "committed", "quarantined",
            "rejected", "denied"]


def dsn(role: str) -> str:
    return (f"dbname=control_stack_test user={role} password=testpw_{role.split('_')[1]}"
            " host=127.0.0.1 port=5433 connect_timeout=5")


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
    return OPAClient(OPA, policy_version="test-v1"), rid


def _proposal(rid, **kw):
    p = {"action_id": str(uuid.uuid4()), "run_id": rid,
         "action": "demo_update_record", "target": "rec-1",
         "arguments": dict(ARGS), "expected_resource_version": 0}
    p.update(kw)
    return p


def _auth(opa, rid, **kw):
    p = _proposal(rid, **kw)
    return authorize(dsn("stack_gate"), opa, p, ACTOR, ["records.write"]), p


def _status(aid):
    with _admin() as c, c.cursor() as cur:
        cur.execute("SELECT status FROM actions WHERE action_id=%s", (aid,))
        row = cur.fetchone()
        return row[0] if row else None


def _transitions(aid):
    with _admin() as c, c.cursor() as cur:
        cur.execute("SELECT old_status, new_status FROM action_transitions"
                    " WHERE action_id=%s ORDER BY seq", (aid,))
        return [tuple(r) for r in cur.fetchall()]


def _jobs(aid):
    with _admin() as c, c.cursor() as cur:
        cur.execute("SELECT kind FROM recovery_jobs WHERE action_id=%s"
                    " ORDER BY created_at", (aid,))
        return [r[0] for r in cur.fetchall()]


def _force_transition(aid: str, old: str, new: str) -> None:
    """PRIVILEGIERTE Fixture: legaler Paar-Sprung als Owner in EINER Tx.

    Der deferred Konsistenz-Trigger prüft am Tx-Ende, deshalb müssen
    Transition und Snapshot gemeinsam geschrieben werden."""
    with psycopg.connect(ADMIN) as c:
        c.execute("INSERT INTO action_transitions (action_id, old_status, new_status)"
                  " VALUES (%s,%s,%s)", (aid, old, new))
        c.execute("UPDATE actions SET status=%s WHERE action_id=%s", (new, aid))


def _forge_committed(rid: str, result: dict) -> str:
    """PRIVILEGIERT: committed-Zeile ohne Effektspur (F4-Angriffssimulation)."""
    aid = str(uuid.uuid4())
    with _admin() as c:
        c.execute("ALTER TABLE actions DISABLE TRIGGER actions_insert_guard")
        c.execute("ALTER TABLE actions DISABLE TRIGGER actions_lifecycle_consistent")
        try:
            c.execute(
                "INSERT INTO actions (action_id, run_id, action, target, args_hash,"
                " idempotency_key, idempotency_payload_hash, status,"
                " expected_resource_version, result) VALUES (%s,%s,"
                " 'demo_update_record','rec-1',%s,%s,%s,'committed',0,%s::jsonb)",
                (aid, rid, "0" * 64, f"{rid}:{aid}", "0" * 64, json.dumps(result)))
        finally:
            c.execute("ALTER TABLE actions ENABLE TRIGGER actions_insert_guard")
            c.execute("ALTER TABLE actions ENABLE TRIGGER actions_lifecycle_consistent")
    return aid


# -- F3: Historie ---------------------------------------------------------
def test_f3_n1_reconcile_authorized_sets_outcome_unknown(live):
    opa, rid = live
    rec, _ = _auth(opa, rid)
    aid = str(rec.action_id)
    insp = reconcile(dsn("stack_recovery"), aid, rid)
    assert insp.outcome == "retry_allowed"
    assert _status(aid) == "outcome_unknown"
    assert _transitions(aid) == [
        ("proposed", "validated"), ("validated", "authorized"),
        ("authorized", "outcome_unknown"),
    ]
    assert _jobs(aid) == ["reconcile"]


def test_f3_n2_retry_after_reconcile_has_exact_path(live):
    opa, rid = live
    rec, _ = _auth(opa, rid)
    aid = str(rec.action_id)
    assert reconcile(dsn("stack_recovery"), aid, rid).outcome == "retry_allowed"
    out = execute(dsn("stack_worker"), aid, dict(ARGS), ACTOR)
    assert out["new_version"] == 1
    assert _status(aid) == "committed"
    assert _transitions(aid) == [
        ("proposed", "validated"), ("validated", "authorized"),
        ("authorized", "outcome_unknown"), ("outcome_unknown", "executing"),
        ("executing", "confirmed"), ("confirmed", "committed"),
    ]
    with _admin() as c, c.cursor() as cur:
        cur.execute("SELECT version FROM records WHERE record_id='rec-1'")
        assert cur.fetchone()[0] == 1  # genau ein Effect


def test_f3_n3_double_reconcile_no_duplicate_history(live):
    opa, rid = live
    rec, _ = _auth(opa, rid)
    aid = str(rec.action_id)
    assert reconcile(dsn("stack_recovery"), aid, rid).outcome == "retry_allowed"
    before = _transitions(aid)
    assert reconcile(dsn("stack_recovery"), aid, rid).outcome == "retry_allowed"
    assert _transitions(aid) == before  # kein outcome_unknown→outcome_unknown
    assert _jobs(aid) == ["reconcile"]  # kein zweiter Job


def test_f3_n3_parallel_reconcile_no_duplicates(live):
    opa, rid = live
    rec, _ = _auth(opa, rid)
    aid = str(rec.action_id)
    results = []

    def run():
        try:
            results.append(reconcile(dsn("stack_recovery"), aid, rid).outcome)
        except Exception as e:  # noqa: BLE001
            results.append(e)

    ts = [threading.Thread(target=run) for _ in range(4)]
    [t.start() for t in ts]
    [t.join() for t in ts]
    assert results and all(r == "retry_allowed" for r in results), results
    assert _transitions(aid).count(("authorized", "outcome_unknown")) == 1
    assert _status(aid) == "outcome_unknown"
    assert _jobs(aid) == ["reconcile"]


@pytest.mark.parametrize("source", ["authorized", "executing", "committed"])
def test_f3_n4_quarantine_edge_matches_source(live, source):
    opa, rid = live
    if source == "committed":
        aid = _forge_committed(rid, {"record_id": "rec-1", "new_version": 1})
        insp = reconcile(dsn("stack_recovery"), aid, rid)
        assert insp.outcome == "quarantined"
        assert _transitions(aid) == [("committed", "quarantined")]
    else:
        rec, _ = _auth(opa, rid)
        aid = str(rec.action_id)
        if source == "executing":
            _force_transition(aid, "authorized", "executing")
            # Bindungsfehler erzwingt Quarantäne (Owner-Eingriff im Test).
            with _admin() as c:
                c.execute("UPDATE authorization_records SET permissions=%s"
                          " WHERE action_id=%s", (["records.read"], aid))
        else:
            # Abweichende Ressourcenversion ⇒ nicht behebbar.
            with _admin() as c:
                c.execute("UPDATE records SET version=7 WHERE record_id='rec-1'")
        insp = reconcile(dsn("stack_recovery"), aid, rid)
        assert insp.outcome == "quarantined"
        assert _transitions(aid)[-1] == (source, "quarantined")
    assert _status(aid) == "quarantined"
    assert _jobs(aid) == ["quarantine"]


def test_f3_n5_gate_deny_writes_history(live):
    opa, rid = live
    aid = str(uuid.uuid4())
    p = _proposal(rid, action_id=aid)
    with pytest.raises(GateDenied):
        authorize(dsn("stack_gate"), opa, p, ACTOR, ["records.read"])
    assert _status(aid) == "denied"
    assert _transitions(aid) == [("proposed", "validated"), ("validated", "denied")]
    with _admin() as c, c.cursor() as cur:
        cur.execute("SELECT version FROM records WHERE record_id='rec-1'")
        assert cur.fetchone()[0] == 0


def test_f3_n6_quarantined_action_cannot_execute(live):
    opa, rid = live
    rec, _ = _auth(opa, rid)
    aid = str(rec.action_id)
    _force_transition(aid, "authorized", "quarantined")
    before = _transitions(aid)
    with pytest.raises(ExecutionDenied):
        execute(dsn("stack_worker"), aid, dict(ARGS), ACTOR)
    assert _transitions(aid) == before
    assert _status(aid) == "quarantined"
    with _admin() as c, c.cursor() as cur:
        cur.execute("SELECT version FROM records WHERE record_id='rec-1'")
        assert cur.fetchone()[0] == 0


# -- F10: DB-Erzwingung ---------------------------------------------------
def test_f10_n1_illegal_pair_rejected_by_check(live):
    opa, rid = live
    rec, _ = _auth(opa, rid)
    aid = str(rec.action_id)
    with _admin() as c:
        with pytest.raises(errors.CheckViolation):
            c.execute("INSERT INTO action_transitions (action_id, old_status, new_status)"
                      " VALUES (%s,'proposed','committed')", (aid,))


def test_f10_n1_snapshot_divergence_rejected(live):
    opa, rid = live
    rec, _ = _auth(opa, rid)
    aid = str(rec.action_id)
    with _admin() as c:
        # legaler Paarwechsel, aber ohne Transition ⇒ deferred Trigger greift.
        with pytest.raises(errors.RaiseException):
            c.execute("UPDATE actions SET status='denied' WHERE action_id=%s", (aid,))
    assert _status(aid) == "authorized"  # Rollback


def test_f10_n2_runtime_roles_cannot_write_lifecycle(live):
    opa, rid = live
    rec, _ = _auth(opa, rid)
    aid = str(rec.action_id)

    with psycopg.connect(dsn("stack_gate"), autocommit=True) as c:
        with pytest.raises(errors.InsufficientPrivilege):
            c.execute("INSERT INTO action_transitions (action_id, old_status, new_status)"
                      " VALUES (%s,'authorized','executing')", (aid,))
        with pytest.raises(errors.InsufficientPrivilege):
            c.execute("UPDATE actions SET status='quarantined' WHERE action_id=%s", (aid,))
        # Gate-Funktion akzeptiert nur Gate-Kanten.
        with pytest.raises(errors.RaiseException):
            c.execute("SELECT fn_gate_transition(%s,'validated')", (aid,))

    with psycopg.connect(dsn("stack_recovery"), autocommit=True) as c:
        with pytest.raises(errors.InsufficientPrivilege):
            c.execute("UPDATE actions SET status='quarantined' WHERE action_id=%s", (aid,))
        with pytest.raises(errors.InsufficientPrivilege):
            c.execute("SELECT fn_gate_transition(%s,'authorized')", (aid,))
        # Recovery darf nur Quarantäne/Reconcile-Kanten.
        with pytest.raises(errors.RaiseException):
            c.execute("SELECT fn_recovery_transition(%s,'executing')", (aid,))

    assert _status(aid) == "authorized"
    assert _transitions(aid) == [("proposed", "validated"), ("validated", "authorized")]


def test_f10_n3_global_invariant_after_flows(live):
    opa, rid = live
    rec, _ = _auth(opa, rid)
    execute(dsn("stack_worker"), str(rec.action_id), dict(ARGS), ACTOR)
    # zusätzlicher Deny-Pfad
    with pytest.raises(GateDenied):
        authorize(dsn("stack_gate"), opa, _proposal(rid), ACTOR, ["records.read"])
    with _admin() as c, c.cursor() as cur:
        cur.execute(
            "SELECT a.action_id, a.status,"
            " (SELECT t.new_status FROM action_transitions t"
            "   WHERE t.action_id=a.action_id ORDER BY t.seq DESC LIMIT 1)"
            " FROM actions a")
        rows = cur.fetchall()
    assert rows
    for aid, status, last in rows:
        assert status == (last or "proposed"), (aid, status, last)


def test_f10_n4_db_check_equals_python_pairs(live):
    opa, rid = live
    rec, _ = _auth(opa, rid)
    aid = str(rec.action_id)
    accepted = set()
    # Alle 121 Paare in einer zurückgerollten Tx gegen den echten CHECK testen.
    with psycopg.connect(ADMIN) as c, c.cursor() as cur:
        for old in STATUSES:
            for new in STATUSES:
                cur.execute("SAVEPOINT pair_probe")
                try:
                    cur.execute(
                        "INSERT INTO action_transitions (action_id, old_status, new_status)"
                        " VALUES (%s,%s,%s)", (aid, old, new))
                    accepted.add((old, new))
                except errors.CheckViolation:
                    pass
                cur.execute("ROLLBACK TO SAVEPOINT pair_probe")
        c.rollback()
    assert accepted == set(PAIRS)
