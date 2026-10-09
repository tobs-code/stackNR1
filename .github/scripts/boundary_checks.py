"""Gemeinsame verhaltensbasierte Boundary-Prüfungen für die Phase-1-CI.

Jede Funktion wirft AssertionError bei Abweichung (fail-closed):
Erfolg ist ausschließlich „keine Exception", niemals eine Logmeldung.

Vertrag (aus dem Repository, nicht angenommen):
- Rollen: stack_owner (NOLOGIN, Objekt-Owner), stack_gate, stack_worker,
  stack_recovery (LOGIN, TEST-ONLY-Passwörter, siehe
  agent-control-stack/migrations/002_roles.sql).
- Geschützte DEFINER-Funktionen aus 005: fn_execute_write, fn_execute_read,
  fn_ledger_append (+ fn_test_kill_self nur für Tests).
- Migration 009 schließt Funktions-Defaults global für die Creator-Rollen
  stack_owner und control_stack (008 war wirkungslos, bleibt als Historie).

Wichtig: Die Probe-Funktionen werden in einem EIGENEN Schema `ci_probe`
angelegt (Owner stack_owner), NICHT in `public`. Migration 002 entzieht
PUBLIC alle Schema-Rechte auf `public`, und 006 gibt stack_owner nur USAGE —
stack_owner kann dort also keine Funktionen anlegen. Ein eigenes Schema prüft
die GLOBALE Default-ACL-Regel aus 009 (ohne IN SCHEMA), ohne die
Produktionsberechtigungen für `public` zu lockern.

Entscheidend ist ausschließlich das EFFEKTIVE Recht
(has_function_privilege), niemals der ACL-Text: proacl=NULL bedeutet
„Defaults gelten", und Defaults können PUBLIC-EXECUTE enthalten.

Umgebung (CI und lokal identisch):
- PostgreSQL 16, Admin-User control_stack / testpw (Superuser aus
  POSTGRES_USER), OPA wird hier NICHT benötigt (reine DB-Prüfungen).
- Lokal:  docker run -d -p 5433:5432 -e POSTGRES_USER=control_stack
           -e POSTGRES_PASSWORD=testpw -e POSTGRES_DB=control_stack
           postgres:16-alpine
"""

from __future__ import annotations

import psycopg
from psycopg import errors

EXPECTED_CHAIN = [
    "001_schema.sql",
    "002_roles.sql",
    "003_evidence.sql",
    "004_seq_least_privilege.sql",
    "005_phase1_boundary.sql",
    "006_owner_schema_usage.sql",
    "007_test_kill_grant.sql",
    "008_default_privileges_closed.sql",
    "009_default_privileges_functions_global.sql",
]

PROBE_SCHEMA = "ci_probe"

# Geschützte Ausführungsfunktionen aus 005 (müssen DEFINER + Owner-only
# sein, aber für stack_worker ausführbar bleiben).
PROTECTED_FUNCTIONS = ("fn_execute_write", "fn_execute_read", "fn_ledger_append")


def assert_migration_chain(cur) -> None:
    """Alle 9 Migrationen in exakter Reihenfolge angewendet."""
    cur.execute("SELECT name FROM schema_migrations ORDER BY applied_at, name")
    names = [r[0] for r in cur.fetchall()]
    assert names == EXPECTED_CHAIN, f"Migrationskette abweichend: {names}"


def ensure_probe_schema(admin) -> None:
    """Test-eigenes Schema für Probe-Funktionen (Owner stack_owner)."""
    with admin.cursor() as cur:
        cur.execute(f"DROP SCHEMA IF EXISTS {PROBE_SCHEMA} CASCADE")
        cur.execute(f"CREATE SCHEMA {PROBE_SCHEMA} AUTHORIZATION stack_owner")


def drop_probe_schema(admin) -> None:
    with admin.cursor() as cur:
        cur.execute(f"DROP SCHEMA IF EXISTS {PROBE_SCHEMA} CASCADE")


def probe_function_closed(admin, creator: str, probe: str) -> None:
    """Eine Probe-Funktion als `creator` anlegen und effektive Defaults prüfen.

    Maßgeblich ist has_function_privilege (effektiv), nicht der ACL-Text.
    """
    qname = f"{PROBE_SCHEMA}.{probe}()"
    with admin.cursor() as cur:
        if creator != "control_stack":
            cur.execute(f"SET ROLE {creator}")
        try:
            cur.execute(f"CREATE FUNCTION {qname} RETURNS void LANGUAGE sql"
                        " AS $$SELECT$$")
        finally:
            if creator != "control_stack":
                cur.execute("RESET ROLE")
        for role in ("stack_worker", "stack_gate"):
            cur.execute("SELECT has_function_privilege(%s, %s, 'EXECUTE')",
                        (role, qname))
            assert cur.fetchone()[0] is False, \
                f"{qname} (creator {creator}): {role} hat Default-EXECUTE"
        # Positivkontrolle: expliziter GRANT funktioniert weiterhin.
        cur.execute(f"GRANT EXECUTE ON FUNCTION {qname} TO stack_worker")
        cur.execute("SELECT has_function_privilege('stack_worker', %s, 'EXECUTE')",
                    (qname,))
        assert cur.fetchone()[0] is True, \
            f"{qname}: expliziter GRANT EXECUTE wirkt nicht"


def assert_function_defaults_closed(admin) -> None:
    """Neu angelegte Funktionen sind für Worker/Gate NICHT ausführbar.

    Prüft beide Creator-Rollen aus 009 (stack_owner, control_stack) im
    test-eigenen Schema (s. Modul-Docstring, warum nicht in public).
    """
    ensure_probe_schema(admin)
    try:
        probe_function_closed(admin, "stack_owner", "fn_ci_probe_owner")
        probe_function_closed(admin, "control_stack", "fn_ci_probe_admin")
    finally:
        drop_probe_schema(admin)


def assert_definer_functions_intact(admin) -> None:
    """005-Funktionen: SECURITY DEFINER, Owner stack_owner, search_path=public,
    für stack_worker ausführbar (sonst wäre der legitime Pfad kaputt).

    Alle Prüfungen laufen über den OID aus EINER schemaqualifizierten
    public-Abfrage — keine zweite globale Namenssuche, die gleichnamige
    Funktionen anderer Schemas einbeziehen könnte.
    """
    with admin.cursor() as cur:
        for fn in PROTECTED_FUNCTIONS:
            cur.execute(
                "SELECT p.oid, p.prosecdef, r.rolname, p.proconfig "
                "FROM pg_proc p JOIN pg_roles r ON r.oid = p.proowner "
                "WHERE p.proname=%s AND p.pronamespace='public'::regnamespace",
                (fn,))
            rows = cur.fetchall()
            assert rows, f"{fn}: Funktion fehlt in public"
            for oid, prosecdef, owner, proconfig in rows:
                assert prosecdef is True, f"{fn}: kein SECURITY DEFINER"
                assert owner == "stack_owner", f"{fn}: Owner ist {owner}"
                assert proconfig is not None and any(
                    s == "search_path=public" for s in proconfig), \
                    f"{fn}: unsicherer search_path: {proconfig}"
                cur.execute(
                    "SELECT has_function_privilege('stack_worker', %s, 'EXECUTE')",
                    (oid,))
                assert cur.fetchone()[0] is True, \
                    f"{fn}: stack_worker hat kein EXECUTE (legitimer Pfad kaputt)"


def _role_dsn(db: str, role: str, host: str, port: str) -> str:
    # TEST-ONLY-Passwörter, exakt wie in 002_roles.sql vergeben.
    return (f"dbname={db} user={role} password=testpw_{role.split('_')[1]} "
            f"host={host} port={port} connect_timeout=10")


def _assert_denied(cur, stmt: str, expect, label: str) -> None:
    """Ein verweigerter Schreibversuch: erwartet `expect`, Erfolg oder eine
    ANDERE Exception lassen die Prüfung fehlschlagen (fail-closed)."""
    try:
        cur.execute(stmt)
    except expect:
        pass
    else:
        raise AssertionError(f"direktes DML gelang ({label}): {stmt}")


def assert_direct_dml_denied(admin, db: str, host: str, port: str) -> None:
    """F7-N1..N4 aus docs/acceptance-phase-1.md, je Rolle mit echten Credentials.

    - stack_worker (F7-N1..N3): UPDATE records, gefälschter committed-INSERT
      in actions, INSERT in outbox_events/evidence_ledger -> alles
      InsufficientPrivilege (005 hat die Grants entzogen).
    - stack_gate (F7-N4): gefälschter terminaler INSERT (Gate HAT INSERT, also
      greift hier der 005-Trigger -> RaiseException) sowie UPDATE actions
      (kein UPDATE-Grant -> InsufficientPrivilege).
    - stack_recovery: KEIN Denial-Test — die Matrix fordert dort nur den
      legitimen Ablauf (F7-P, von der Full-Suite abgedeckt). Keine still-
      schweigende Übertragung fremder Rollenverbote.

    Abnahmeregeln 2+3: nach jedem Versuch persistente Prüfung — keine
    ci-Schmuggelzeilen, records-Tabelle bitidentisch zu vorher.
    """
    with admin.cursor() as cur:
        cur.execute("SELECT record_id, status, version FROM records ORDER BY 1")
        records_before = cur.fetchall()

    worker = _role_dsn(db, "stack_worker", host, port)
    with psycopg.connect(worker, autocommit=True) as c, c.cursor() as cur:
        _assert_denied(cur, "UPDATE records SET status='approved'",
                       errors.InsufficientPrivilege, "F7-N1/worker")
        _assert_denied(cur,
                       "INSERT INTO actions (action_id, run_id, action, target,"
                       " args_hash, idempotency_key, idempotency_payload_hash,"
                       " status, expected_resource_version, result)"
                       " VALUES ('ci-worker-forge','ci-run','demo_read','rec-1',"
                       " 'h','k','p','committed',0,'{}')",
                       errors.InsufficientPrivilege, "F7-N2/worker")
        _assert_denied(cur,
                       "INSERT INTO outbox_events (event_id, run_id, action_id,"
                       " sequence, event_type, resource_version, payload_hash,"
                       " previous_event_hash)"
                       " VALUES ('ci-worker-ev','ci-run','ci-worker-forge',1,"
                       " 'state_committed',1,'h','g')",
                       errors.InsufficientPrivilege, "F7-N3/worker-outbox")
        _assert_denied(cur,
                       "INSERT INTO evidence_ledger (event_id, run_id, sequence,"
                       " event_hash, prev_hash)"
                       " VALUES ('ci-worker-ev','ci-run',1,'h','g')",
                       errors.InsufficientPrivilege, "F7-N3/worker-ledger")
        c.rollback()

    gate = _role_dsn(db, "stack_gate", host, port)
    with psycopg.connect(gate, autocommit=True) as c, c.cursor() as cur:
        _assert_denied(cur,
                       "INSERT INTO actions (action_id, run_id, action, target,"
                       " args_hash, idempotency_key, idempotency_payload_hash,"
                       " status, expected_resource_version, result)"
                       " VALUES ('ci-gate-forge','ci-run','demo_read','rec-1',"
                       " 'h','k','p','committed',0,'{}')",
                       errors.RaiseException, "F7-N4/gate-insert")
        _assert_denied(cur,
                       "UPDATE actions SET status='committed'"
                       " WHERE action_id='ci-gate-forge'",
                       errors.InsufficientPrivilege, "F7-N4/gate-update")
        c.rollback()

    with admin.cursor() as cur:
        cur.execute("SELECT count(*) FROM actions WHERE action_id LIKE 'ci-%'")
        assert cur.fetchone()[0] == 0, "geschmuggelte ci-Action persistiert"
        cur.execute("SELECT count(*) FROM outbox_events WHERE event_id LIKE 'ci-%'")
        assert cur.fetchone()[0] == 0, "geschmuggeltes ci-Outbox-Event persistiert"
        cur.execute("SELECT count(*) FROM evidence_ledger WHERE event_id LIKE 'ci-%'")
        assert cur.fetchone()[0] == 0, "geschmuggelter ci-Ledger-Eintrag persistiert"
        cur.execute("SELECT record_id, status, version FROM records ORDER BY 1")
        assert cur.fetchall() == records_before, "records-Tabelle verändert"
