"""Phase-1-Acceptance (docs/acceptance-phase-1.md): F1, F2, F4, F7.

Regeln: echte Runtime-Rollen, persistente DB-Prüfung, kein reines
Exception-Assert. Privilegierte Fixtures (Owner-Eingriffe) sind je Test
als solche markiert und stehen NICHT für Runtime-Angriffsmöglichkeiten.
"""
import json
import os
import threading
import uuid
import psycopg
import pytest
from psycopg import errors

from control_stack.contracts import args_hash
from control_stack.execution.broker import ExecutionDenied, execute
from control_stack.gate.executor import GateDenied, GateRejected, authorize
from control_stack.policy.client import OPAClient
from control_stack.recovery import reconcile
from control_stack.state.repository import (
    AuthorizationMismatchError,
    Repository,
)

ADMIN = ("dbname=control_stack_test user=control_stack password=testpw"
         " host=127.0.0.1 port=5433 connect_timeout=5")
OPA = os.environ.get("CONTROL_STACK_OPA_URL", "http://127.0.0.1:8181")
ACTOR = "agent-1"
ARGS = {"record_id": "rec-1", "status": "approved"}


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
        c.execute("INSERT INTO records (record_id) VALUES ('rec-1'),('rec-2')")
    return OPAClient(OPA, policy_version="test-v1"), rid


def _auth(opa, rid, **kw):
    p = {"action_id": str(uuid.uuid4()), "run_id": rid,
         "action": "demo_update_record", "target": "rec-1",
         "arguments": dict(ARGS), "expected_resource_version": 0}
    p.update(kw)
    return authorize(dsn("stack_gate"), opa, p, ACTOR, ["records.write"]), p


def _versions():
    with _admin() as c, c.cursor() as cur:
        cur.execute("SELECT record_id, version, status FROM records ORDER BY record_id")
        return cur.fetchall()


# -- F1 -----------------------------------------------------------------
def test_f1_diverged_target_rejected_at_gate(live):
    """F1-N (Gate-Schicht): target != record_id ⇒ kein Record, kein Effect."""
    opa, rid = live
    bad = {"action_id": str(uuid.uuid4()), "run_id": rid,
           "action": "demo_update_record", "target": "rec-1",
           "arguments": {"record_id": "rec-2", "status": "approved"},
           "expected_resource_version": 0}
    with pytest.raises(GateRejected):
        authorize(dsn("stack_gate"), opa, bad, ACTOR, ["records.write"])
    with _admin() as c, c.cursor() as cur:
        cur.execute("SELECT COUNT(*) FROM actions")
        assert cur.fetchone()[0] == 0
        cur.execute("SELECT COUNT(*) FROM authorization_records")
        assert cur.fetchone()[0] == 0
    assert _versions() == [("rec-1", 0, "pending"), ("rec-2", 0, "pending")]


def test_f1_diverged_record_denied_at_execution(live):
    """F1-N (Tiefenstaffelung): eingeschleuster Mismatch-Record (PRIVILEGIERTE
    Fixture, Owner) ⇒ Broker + DB-Funktion lehnen ab, beide Ressourcen intakt."""
    _, rid = live
    aid = str(uuid.uuid4())
    forged_args = {"record_id": "rec-2", "status": "approved"}
    ah = args_hash(forged_args)
    # PRIVILEGIERTE Fixture: direkt als Owner geschrieben, kein Runtime-Pfad.
    with _admin() as c:
        c.execute(
            "INSERT INTO actions (action_id, run_id, action, target, args_hash,"
            " idempotency_key, idempotency_payload_hash, status,"
            " expected_resource_version) VALUES (%s,%s,'demo_update_record',"
            " 'rec-1',%s,%s,%s,'authorized',0)",
            (aid, rid, ah, f"{rid}:{aid}", ah))
        c.execute(
            "INSERT INTO authorization_records (action_id, canonical_hash, action,"
            " target, args_hash, actor_id, permissions, expected_resource_version,"
            " preconditions, policy_version, context_hash, expires_at)"
            " VALUES (%s,'" + "0" * 64 + "','demo_update_record','rec-1',%s,"
            " 'agent-1','{records.write}',0,'{}','test-v1','" + "0" * 64 + "',"
            " now() + interval '5 minutes')",
            (aid, ah))
    with pytest.raises(ExecutionDenied):
        execute(dsn("stack_worker"), aid, dict(forged_args), ACTOR)
    repo = Repository(dsn("stack_worker"))
    with pytest.raises(AuthorizationMismatchError):
        repo.commit_demo_update(
            run_id=rid, action_id=aid, record_id="rec-2",
            new_status="approved", expected_version=0,
            idempotency_key=f"{rid}:{aid}", payload_hash=ah,
            event_id=str(uuid.uuid4()), run_sequence=1,
            prev_event_hash="0" * 64,
            guard_arguments=dict(forged_args), guard_actor_id=ACTOR)
    assert _versions() == [("rec-1", 0, "pending"), ("rec-2", 0, "pending")]
    with _admin() as c, c.cursor() as cur:
        cur.execute("SELECT COUNT(*) FROM state_transitions")
        assert cur.fetchone()[0] == 0
        cur.execute("SELECT COUNT(*) FROM outbox_events")
        assert cur.fetchone()[0] == 0
        cur.execute("SELECT status, result FROM actions WHERE action_id=%s", (aid,))
        st, res = cur.fetchone()
        assert st == "authorized" and res is None


def test_f1_matching_target_commits_only_authorized_resource(live):
    """F1-P: übereinstimmendes Ziel ⇒ genau diese Ressource wird verändert."""
    opa, rid = live
    rec, p = _auth(opa, rid)
    out = execute(dsn("stack_worker"), str(rec.action_id), dict(p["arguments"]), ACTOR)
    assert out["record_id"] == "rec-1" and out["new_version"] == 1
    assert _versions() == [("rec-1", 1, "approved"), ("rec-2", 0, "pending")]


# -- F2 -----------------------------------------------------------------
def test_f2_completed_run_blocks_execution(live):
    """F2-N: Run nach Autorisierung completed ⇒ kein Effect, Voll-Rollback."""
    opa, rid = live
    rec, p = _auth(opa, rid)
    aid = str(rec.action_id)
    with _admin() as c:
        c.execute("UPDATE runs SET status='completed' WHERE run_id=%s", (rid,))
    with pytest.raises(ExecutionDenied):
        execute(dsn("stack_worker"), aid, dict(p["arguments"]), ACTOR)
    assert _versions() == [("rec-1", 0, "pending"), ("rec-2", 0, "pending")]
    with _admin() as c, c.cursor() as cur:
        cur.execute("SELECT status, result FROM actions WHERE action_id=%s", (aid,))
        st, res = cur.fetchone()
        assert st == "authorized" and res is None
        cur.execute("SELECT COUNT(*) FROM state_transitions")
        assert cur.fetchone()[0] == 0
        cur.execute("SELECT COUNT(*) FROM outbox_events")
        assert cur.fetchone()[0] == 0


def test_f2_authorize_on_completed_run_denied(live):
    """F2-N (Gate): Autorisierung auf abgeschlossenem Run ⇒ Deny."""
    opa, rid = live
    with _admin() as c:
        c.execute("UPDATE runs SET status='completed' WHERE run_id=%s", (rid,))
    with pytest.raises(GateDenied):
        _auth(opa, rid)


def test_f2_race_completion_vs_execution(live):
    """F2-R: konkurrierender Abschluss ⇒ höchstens 1 Effect, nie partiell."""
    opa, rid = live
    rec, p = _auth(opa, rid)
    aid = str(rec.action_id)

    def run_exec():
        try:
            execute(dsn("stack_worker"), aid, dict(p["arguments"]), ACTOR)
        except Exception:  # noqa: BLE001 — Deny oder Stale sind legitime Ausgänge
            pass

    def run_complete():
        with _admin() as c:
            c.execute("UPDATE runs SET status='completed' WHERE run_id=%s", (rid,))

    ts = [threading.Thread(target=run_exec) for _ in range(3)]
    tc = threading.Thread(target=run_complete)
    for t in ts:
        t.start()
    tc.start()
    for t in ts:
        t.join()
    tc.join()
    with _admin() as c, c.cursor() as cur:
        cur.execute("SELECT version FROM records WHERE record_id='rec-1'")
        ver = cur.fetchone()[0]
        assert ver in (0, 1)
        cur.execute("SELECT COUNT(*) FROM state_transitions")
        assert cur.fetchone()[0] == ver
        cur.execute("SELECT status, result FROM actions WHERE action_id=%s", (aid,))
        st, res = cur.fetchone()
        if ver == 1:
            assert st == "committed" and res is not None
            cur.execute("SELECT COUNT(*) FROM outbox_events")
            assert cur.fetchone()[0] == 1
        else:
            assert res is None
            cur.execute("SELECT COUNT(*) FROM outbox_events")
            assert cur.fetchone()[0] == 0


# -- F4 -----------------------------------------------------------------
def test_f4_forged_commit_quarantined_not_replayed(live):
    """F4-N: gefälschtes committed ohne Effektnachweis (PRIVILEGIERTE Fixture,
    Owner, Trigger explizit deaktiviert) ⇒ quarantined, nie Replay."""
    _, rid = live
    fake = str(uuid.uuid4())
    with _admin() as c:
        c.execute("ALTER TABLE actions DISABLE TRIGGER actions_insert_guard")
        try:
            c.execute(
                "INSERT INTO actions (action_id, run_id, action, target, args_hash,"
                " idempotency_key, idempotency_payload_hash, status,"
                " expected_resource_version, result) VALUES (%s,%s,"
                " 'demo_update_record','rec-1',%s,%s,%s,'committed',0,"
                " '{\"record_id\":\"rec-1\",\"new_version\":1}')",
                (fake, rid, "0" * 64, f"{rid}:{fake}", "0" * 64))
        finally:
            c.execute("ALTER TABLE actions ENABLE TRIGGER actions_insert_guard")
    insp = reconcile(dsn("stack_recovery"), fake, rid)
    assert insp.outcome == "quarantined"
    with _admin() as c, c.cursor() as cur:
        cur.execute("SELECT status FROM actions WHERE action_id=%s", (fake,))
        assert cur.fetchone()[0] == "quarantined"
        cur.execute("SELECT kind FROM recovery_jobs WHERE action_id=%s", (fake,))
        assert cur.fetchone()[0] == "quarantine"
        cur.execute("SELECT version FROM records WHERE record_id='rec-1'")
        assert cur.fetchone()[0] == 0


def test_f4_real_commit_still_replays(live):
    """F4-Positivkontrolle: echter Commit mit Effektnachweis ⇒ Replay."""
    opa, rid = live
    rec, p = _auth(opa, rid)
    first = execute(dsn("stack_worker"), str(rec.action_id), dict(p["arguments"]), ACTOR)
    insp = reconcile(dsn("stack_recovery"), str(rec.action_id), rid)
    assert insp.outcome == "replayed" and insp.result == first


def test_f4_copied_result_without_own_transition_quarantined(live):
    """F4: Resultat einer fremden Action kopiert (keine eigene Transition,
    PRIVILEGIERTE Fixture) ⇒ quarantined, nie Replay des fremden Resultats."""
    opa, rid = live
    rec, p = _auth(opa, rid)
    first = execute(dsn("stack_worker"), str(rec.action_id), dict(p["arguments"]), ACTOR)
    other = str(uuid.uuid4())
    with _admin() as c:
        c.execute("INSERT INTO records (record_id) VALUES ('rec-9')")
        c.execute("ALTER TABLE actions DISABLE TRIGGER actions_insert_guard")
        try:
            c.execute(
                "INSERT INTO actions (action_id, run_id, action, target, args_hash,"
                " idempotency_key, idempotency_payload_hash, status,"
                " expected_resource_version, result) VALUES (%s,%s,"
                " 'demo_update_record','rec-9',%s,%s,%s,'committed',0,%s::jsonb)",
                (other, rid, "0" * 64, f"{rid}:{other}", "0" * 64,
                 json.dumps(first)))
        finally:
            c.execute("ALTER TABLE actions ENABLE TRIGGER actions_insert_guard")
    insp = reconcile(dsn("stack_recovery"), other, rid)
    assert insp.outcome == "quarantined"
    with _admin() as c, c.cursor() as cur:
        cur.execute("SELECT status FROM actions WHERE action_id=%s", (other,))
        assert cur.fetchone()[0] == "quarantined"
        cur.execute("SELECT version FROM records WHERE record_id='rec-1'")
        assert cur.fetchone()[0] == 1  # nur der eine echte Effect existiert


def test_f4_manipulated_result_despite_transition_quarantined(live):
    """F4: echte Transition, aber nachträglich manipuliertes Resultat
    (PRIVILEGIERTE Fixture, Owner-UPDATE) ⇒ quarantined statt Replay."""
    opa, rid = live
    rec, p = _auth(opa, rid)
    aid = str(rec.action_id)
    execute(dsn("stack_worker"), aid, dict(p["arguments"]), ACTOR)
    with _admin() as c:
        c.execute(
            "UPDATE actions SET result=%s::jsonb WHERE action_id=%s",
            (json.dumps({"record_id": "rec-1", "old_version": 0,
                         "new_version": 2, "status": "approved"}), aid))
    insp = reconcile(dsn("stack_recovery"), aid, rid)
    assert insp.outcome == "quarantined"
    with _admin() as c, c.cursor() as cur:
        cur.execute("SELECT status FROM actions WHERE action_id=%s", (aid,))
        assert cur.fetchone()[0] == "quarantined"
        cur.execute("SELECT version FROM records WHERE record_id='rec-1'")
        assert cur.fetchone()[0] == 1  # Effect selbst bleibt genau einer


# -- F7 -----------------------------------------------------------------
def test_f7_worker_cannot_write_records_directly(live):
    """F7-N1: direkter Ressourcen-Write als Worker ⇒ InsufficientPrivilege."""
    live  # noqa: B018 — Fixture für DB-Setup
    with psycopg.connect(dsn("stack_worker"), autocommit=True) as c:
        with pytest.raises(errors.InsufficientPrivilege):
            c.execute("UPDATE records SET status='approved', version=99"
                      " WHERE record_id='rec-1'")
        with pytest.raises(errors.InsufficientPrivilege):
            c.execute("DELETE FROM records WHERE record_id='rec-1'")
        with pytest.raises(errors.InsufficientPrivilege):
            c.execute("INSERT INTO records (record_id) VALUES ('rec-x')")
    assert _versions() == [("rec-1", 0, "pending"), ("rec-2", 0, "pending")]


def test_f7_worker_cannot_forge_actions(live):
    """F7-N2: gefälschte Actions/Resultate als Worker ⇒ InsufficientPrivilege."""
    _, rid = live
    fake = str(uuid.uuid4())
    with psycopg.connect(dsn("stack_worker"), autocommit=True) as c:
        with pytest.raises(errors.InsufficientPrivilege):
            c.execute(
                "INSERT INTO actions (action_id, run_id, action, target, args_hash,"
                " idempotency_key, idempotency_payload_hash, status,"
                " expected_resource_version, result) VALUES (%s,%s,"
                " 'demo_update_record','rec-1',%s,%s,%s,'committed',0,'{}')",
                (fake, rid, "0" * 64, f"{rid}:{fake}", "0" * 64))
        with pytest.raises(errors.InsufficientPrivilege):
            c.execute("UPDATE actions SET status='committed' WHERE action_id=%s",
                      (fake,))
    with _admin() as c, c.cursor() as cur:
        cur.execute("SELECT COUNT(*) FROM actions WHERE action_id=%s", (fake,))
        assert cur.fetchone()[0] == 0


def test_f7_worker_cannot_forge_evidence(live):
    """F7-N3: direkte Outbox-/Ledger-Manipulation als Worker ⇒ verweigert."""
    _, rid = live
    with psycopg.connect(dsn("stack_worker"), autocommit=True) as c:
        with pytest.raises(errors.InsufficientPrivilege):
            c.execute(
                "INSERT INTO outbox_events (event_id, run_id, action_id, sequence,"
                " event_type, resource_version, payload_hash, previous_event_hash)"
                " VALUES ('forge',%s,NULL,1,'state_committed',1,%s,%s)",
                (rid, "0" * 64, "0" * 64))
        with pytest.raises(errors.InsufficientPrivilege):
            c.execute(
                "INSERT INTO evidence_ledger (event_id, run_id, sequence,"
                " event_hash, prev_hash) VALUES ('forge',%s,1,%s,%s)",
                (rid, "a" * 64, "b" * 64))
    with _admin() as c, c.cursor() as cur:
        cur.execute("SELECT COUNT(*) FROM outbox_events")
        assert cur.fetchone()[0] == 0
        cur.execute("SELECT COUNT(*) FROM evidence_ledger")
        assert cur.fetchone()[0] == 0


def test_f7_gate_cannot_forge_terminal_actions(live):
    """F7-N4: Gate kann keinen terminalen Action-Zustand einschleusen
    (Trigger; legitime authorized/denied-INSERTs bleiben möglich)."""
    opa, rid = live
    with psycopg.connect(dsn("stack_gate"), autocommit=True) as c:
        with pytest.raises(errors.RaiseException):
            c.execute(
                "INSERT INTO actions (action_id, run_id, action, target, args_hash,"
                " idempotency_key, idempotency_payload_hash, status,"
                " expected_resource_version, result) VALUES (%s,%s,"
                " 'demo_update_record','rec-1',%s,%s,%s,'committed',0,'{}')",
                (str(uuid.uuid4()), rid, "0" * 64, "gk", "gp"))
        with pytest.raises(errors.InsufficientPrivilege):
            c.execute("UPDATE actions SET status='denied' WHERE run_id=%s", (rid,))
    # Positivkontrolle: Gate-Autorisierung funktioniert weiterhin.
    rec, _ = _auth(opa, rid)
    with _admin() as c, c.cursor() as cur:
        cur.execute("SELECT status FROM actions WHERE action_id=%s",
                    (str(rec.action_id),))
        assert cur.fetchone()[0] == "authorized"


def test_009_new_functions_closed_by_default(live):
    """009 (PRIVILEGIERT, Owner-Setup): neu angelegte Funktionen erhalten kein
    PUBLIC EXECUTE (009-Effekt, nicht nur aktuelle ACL); explizite Grants
    bleiben möglich."""
    live  # noqa: B018 — Fixture für DB-Setup
    with _admin() as c, c.cursor() as cur:
        cur.execute("CREATE FUNCTION fn_review_probe() RETURNS void LANGUAGE sql"
                    " AS $$SELECT$$")
        cur.execute("SELECT proacl FROM pg_proc WHERE proname='fn_review_probe'")
        acl = cur.fetchone()[0]
        assert acl is None or not any("PUBLIC" in str(e) for e in acl), acl
        cur.execute("SELECT has_function_privilege('stack_worker',"
                    " 'fn_review_probe()', 'EXECUTE')")
        assert cur.fetchone()[0] is False
        cur.execute("SELECT has_function_privilege('stack_gate',"
                    " 'fn_review_probe()', 'EXECUTE')")
        assert cur.fetchone()[0] is False
        # Expliziter Grant bleibt möglich (Positivkontrolle).
        cur.execute("GRANT EXECUTE ON FUNCTION fn_review_probe() TO stack_worker")
        cur.execute("SELECT has_function_privilege('stack_worker',"
                    " 'fn_review_probe()', 'EXECUTE')")
        assert cur.fetchone()[0] is True
        cur.execute("DROP FUNCTION fn_review_probe()")


def test_f7_legitimate_role_flow_still_works(live):
    """F7-P: regulärer Gate-/Worker-/Recovery-Ablauf mit Rollen-DSNs."""
    from control_stack.evidence import process_all, verify_run
    opa, rid = live
    rec, p = _auth(opa, rid)
    out = execute(dsn("stack_worker"), str(rec.action_id), dict(p["arguments"]), ACTOR)
    assert out["new_version"] == 1
    assert process_all(dsn("stack_worker")) != []
    assert verify_run(dsn("stack_worker"), rid) == 1
    insp = reconcile(dsn("stack_recovery"), str(rec.action_id), rid)
    assert insp.outcome == "replayed"
