"""Upgrade-Check (Phase 1): rekonstruierter Altstand 001–004 -> Upgrade bis 009.

Ausgangsstand (realistisch, kein leeres Schema): ein aus den Migrationen
001–004 des aktuellen Checkouts rekonstruierter Altstand —
Tabellen/Rollen/Least-Privilege ohne Phase-1-Boundary — plus Seed-Daten
(ein Run, ein Record), die das Upgrade überleben müssen.

Herkunftshinweis (präzise, keine Überbehauptung): Dies ist NICHT automatisch
ein Checkout des historischen `main`-Commits. Die Dateien 001–004 stammen aus
dem PR-Checkout (der Runner muss die zu prüfenden Migrationen ausführen).
Der `guards`-Job im selben Workflow beweist, dass 001–004 gegenüber dem
Merge-Base mit main unverändert sind — erst dadurch entspricht der
rekonstruierte Altstand dem historischen Stand von main.

Erwarteter Endzustand: identisch zum Fresh-Install (Kette 001–009, Defaults
geschlossen, DEFINER intakt, direktes DML verweigert) plus intakte Seed-Daten.
Vor dem Upgrade wird zusätzlich bewiesen, dass neue Funktionen im Altstand
noch PUBLIC-ausführbar waren (sonst hätte 009 nichts geändert).

Jede Abweichung -> AssertionError -> Job rot.

Verwendung: wie check_fresh_install.py, dann
    PYTHONPATH=agent-control-stack/src python .github/scripts/check_upgrade.py
Gleiche Umgebungsvariablen (PGHOST/PGPORT/PGADMIN_USER/PGADMIN_PASSWORD).
"""

from __future__ import annotations

import os
import sys

import psycopg

REPO = os.path.join(os.path.dirname(__file__), "..", "..")
sys.path.insert(0, os.path.join(REPO, "agent-control-stack", "src"))
sys.path.insert(0, os.path.dirname(__file__))

from boundary_checks import (  # noqa: E402
    EXPECTED_CHAIN,
    assert_definer_functions_intact,
    assert_direct_dml_denied,
    assert_function_defaults_closed,
    assert_migration_chain,
)
from control_stack.mig.runner import migrate  # noqa: E402

HOST = os.environ.get("PGHOST", "127.0.0.1")
PORT = os.environ.get("PGPORT", "5433")
ADMIN_USER = os.environ.get("PGADMIN_USER", "control_stack")
ADMIN_PW = os.environ.get("PGADMIN_PASSWORD", "testpw")
DB = "upgrade_check"
BASELINE = EXPECTED_CHAIN[:4]  # 001–004 == Stand von main vor Phase 1


def admin_dsn(db: str) -> str:
    return (f"dbname={db} user={ADMIN_USER} password={ADMIN_PW} "
            f"host={HOST} port={PORT} connect_timeout=10")


def apply_baseline(admin) -> None:
    """001–004 direkt per SQL (wie ein altes Release), inkl. Runner-Buchhaltung."""
    migdir = os.path.join(REPO, "agent-control-stack", "migrations")
    with admin.cursor() as cur:
        for name in BASELINE:
            with open(os.path.join(migdir, name), encoding="utf-8") as f:
                cur.execute(f.read())
        cur.execute("CREATE TABLE IF NOT EXISTS schema_migrations"
                    " (name TEXT PRIMARY KEY, applied_at TIMESTAMPTZ DEFAULT now())")
        for name in BASELINE:
            cur.execute("INSERT INTO schema_migrations (name) VALUES (%s)"
                        " ON CONFLICT DO NOTHING", (name,))
        cur.execute("INSERT INTO runs (run_id, owner) VALUES ('upgrade-seed-run','t')"
                    " ON CONFLICT DO NOTHING")
        cur.execute("INSERT INTO records (record_id) VALUES ('upgrade-seed-rec')"
                    " ON CONFLICT DO NOTHING")


def old_default_was_open(admin) -> None:
    """Negativkontrolle VOR dem Upgrade: neue Funktion ist PUBLIC-ausführbar.

    Gleiches test-eigenes Schema wie die Nachher-Prüfung (s. boundary_checks),
    damit Vorher/Nachher vergleichbar sind. Maßgeblich: effektives Recht.
    """
    from boundary_checks import PROBE_SCHEMA, ensure_probe_schema
    ensure_probe_schema(admin)
    with admin.cursor() as cur:
        cur.execute("SET ROLE stack_owner")
        try:
            cur.execute(f"CREATE FUNCTION {PROBE_SCHEMA}.fn_ci_pre_probe()"
                        " RETURNS void LANGUAGE sql AS $$SELECT$$")
        finally:
            cur.execute("RESET ROLE")
        cur.execute("SELECT has_function_privilege('stack_worker',"
                    f" '{PROBE_SCHEMA}.fn_ci_pre_probe()', 'EXECUTE')")
        assert cur.fetchone()[0] is True, \
            "Altstand unerwartet: Default bereits geschlossen, Upgrade wirkungslos?"
        cur.execute(f"DROP FUNCTION {PROBE_SCHEMA}.fn_ci_pre_probe()")


def main() -> None:
    with psycopg.connect(admin_dsn("postgres"), autocommit=True) as c:
        c.execute(f'DROP DATABASE IF EXISTS "{DB}"')
        c.execute(f'CREATE DATABASE "{DB}"')
    with psycopg.connect(admin_dsn(DB), autocommit=True) as admin:
        apply_baseline(admin)
        with admin.cursor() as cur:
            cur.execute("SELECT name FROM schema_migrations ORDER BY applied_at, name")
            assert [r[0] for r in cur.fetchall()] == BASELINE, "Baseline unvollständig"
        old_default_was_open(admin)
    applied = migrate(admin_dsn(DB))
    assert applied == EXPECTED_CHAIN[4:], f"Upgrade-Pfad abweichend: {applied}"
    with psycopg.connect(admin_dsn(DB), autocommit=True) as admin:
        with admin.cursor() as cur:
            assert_migration_chain(cur)
            # Seed-Daten haben das Upgrade überlebt.
            cur.execute("SELECT count(*) FROM runs WHERE run_id='upgrade-seed-run'")
            assert cur.fetchone()[0] == 1, "Seed-Run verloren"
            cur.execute("SELECT count(*) FROM records WHERE record_id='upgrade-seed-rec'")
            assert cur.fetchone()[0] == 1, "Seed-Record verloren"
        assert_function_defaults_closed(admin)
        assert_definer_functions_intact(admin)
        assert_direct_dml_denied(admin, DB, HOST, PORT)
    print("upgrade OK: 001-004 + Seed -> 009, Defaults geschlossen, DML verweigert")


if __name__ == "__main__":
    main()
