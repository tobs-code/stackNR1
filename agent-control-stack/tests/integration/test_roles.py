"""DB-Rollen: echte Verbindungen je Rolle, keine SET ROLE-Abkürzung.

Test-DB control_stack_test (frisch migriert). Passwörter TEST-ONLY.
"""
import os
import uuid

import psycopg
import pytest
from psycopg import errors

from control_stack.execution.broker import execute
from control_stack.gate.executor import authorize
from control_stack.policy.client import OPAClient
from control_stack.recovery import reconcile

ADMIN = ("dbname=control_stack_test user=control_stack password=testpw"
         " host=127.0.0.1 port=5433 connect_timeout=5")
OPA = os.environ.get("CONTROL_STACK_OPA_URL", "http://127.0.0.1:8181")


def dsn(role: str) -> str:
    return (f"dbname=control_stack_test user={role} password=testpw_{role.split('_')[1]}"
            " host=127.0.0.1 port=5433 connect_timeout=5")


def _admin():
    return psycopg.connect(ADMIN, autocommit=True)


@pytest.fixture()
def fresh():
    from control_stack.mig.runner import migrate
    with _admin() as c:
        for t in ("recovery_jobs", "outbox_events", "state_transitions",
                  "action_transitions", "policy_decisions",
                  "authorization_records", "actions", "records", "runs",
                  "schema_migrations"):
            c.execute(f"DELETE FROM {t}")
        c.execute("DELETE FROM schema_migrations")
    migrate(ADMIN)
    with _admin() as c:
        rid = f"run-{uuid.uuid4().hex[:8]}"
        c.execute("INSERT INTO runs (run_id, owner) VALUES (%s,'t')", (rid,))
        c.execute("INSERT INTO records (record_id) VALUES ('rec-1')")
    return rid


def _proposal(rid):
    return {"action_id": str(uuid.uuid4()), "run_id": rid,
            "action": "demo_update_record", "target": "rec-1",
            "arguments": {"record_id": "rec-1", "status": "approved"},
            "expected_resource_version": 0}


def test_owner_separation(fresh):
    with _admin() as c, c.cursor() as cur:
        cur.execute("SELECT tablename, tableowner FROM pg_tables WHERE schemaname='public'")
        owners = {r[0]: r[1] for r in cur.fetchall()}
    assert owners, "keine Tabellen"
    app_tables = {k: v for k, v in owners.items() if k != "schema_migrations"}
    assert set(app_tables.values()) == {"stack_owner"}, app_tables


def test_no_public_grants_and_no_privileged_membership(fresh):
    with _admin() as c, c.cursor() as cur:
        cur.execute(
            "SELECT table_name, privilege_type FROM information_schema.role_table_grants"
            " WHERE grantee='PUBLIC' AND table_schema='public'")
        assert cur.fetchall() == []
        for role in ("stack_gate", "stack_worker", "stack_recovery"):
            cur.execute(
                "SELECT 1 FROM pg_auth_members m JOIN pg_roles r ON r.oid=m.roleid"
                " WHERE m.member=(SELECT oid FROM pg_roles WHERE rolname=%s)"
                " AND r.rolname IN ('pg_read_all_data','pg_write_all_data','pg_signal_backend')",
                (role,))
            assert cur.fetchone() is None, role


def test_gate_insert_only_on_auth_records(fresh):
    rid = fresh
    opa = OPAClient(OPA, policy_version="test-v1")
    rec = authorize(dsn("stack_gate"), opa, _proposal(rid), "agent-1", ["records.write"])
    aid = str(rec.action_id)
    with psycopg.connect(dsn("stack_gate"), autocommit=True) as c:
        with pytest.raises(errors.InsufficientPrivilege):
            c.execute("UPDATE authorization_records SET target='x' WHERE action_id=%s", (aid,))
        with pytest.raises(errors.InsufficientPrivilege):
            c.execute("DELETE FROM authorization_records WHERE action_id=%s", (aid,))
        with pytest.raises(errors.InsufficientPrivilege):
            c.execute("TRUNCATE authorization_records")
    with _admin() as c, c.cursor() as cur:
        cur.execute("SELECT target FROM authorization_records WHERE action_id=%s", (aid,))
        assert cur.fetchone()[0] == "rec-1"  # unverändert


def test_worker_read_only_on_auth_records_but_can_execute(fresh):
    rid = fresh
    opa = OPAClient(OPA, policy_version="test-v1")
    rec = authorize(dsn("stack_gate"), opa, _proposal(rid), "agent-1", ["records.write"])
    aid = str(rec.action_id)
    with psycopg.connect(dsn("stack_worker"), autocommit=True) as c, c.cursor() as cur:
        cur.execute("SELECT canonical_hash FROM authorization_records WHERE action_id=%s", (aid,))
        assert cur.fetchone() is not None  # Lesen ok
        with pytest.raises(errors.InsufficientPrivilege):
            cur.execute("UPDATE authorization_records SET target='x' WHERE action_id=%s", (aid,))
        with pytest.raises(errors.InsufficientPrivilege):
            cur.execute("DELETE FROM authorization_records WHERE action_id=%s", (aid,))
        with pytest.raises(errors.InsufficientPrivilege):
            cur.execute("INSERT INTO authorization_records (action_id) VALUES ('y')")
    res = execute(dsn("stack_worker"), aid,
                  {"record_id": "rec-1", "status": "approved"}, "agent-1")
    assert res["new_version"] == 1  # Execution-Pfad funktioniert mit Worker-Rechten


def test_recovery_cannot_alter_authorizations(fresh):
    rid = fresh
    opa = OPAClient(OPA, policy_version="test-v1")
    rec = authorize(dsn("stack_gate"), opa, _proposal(rid), "agent-1", ["records.write"])
    aid = str(rec.action_id)
    with psycopg.connect(dsn("stack_recovery"), autocommit=True) as c:
        with pytest.raises(errors.InsufficientPrivilege):
            c.execute("UPDATE authorization_records SET target='x' WHERE action_id=%s", (aid,))
    insp = reconcile(dsn("stack_recovery"), aid, rid)
    assert insp.outcome == "retry_allowed"  # eigener Job-Pfad funktioniert
