"""Fresh-Install-Check (Phase 1, F7/F9-Korrektur-Nachweis).

Szenario: leere PostgreSQL-16-Datenbank, Migrationen 001–009 in definierter
Reihenfolge über den echten Runner, danach verhaltensbasierte Prüfungen.
Jede Abweichung -> AssertionError -> Job rot. Es gibt keinen „nur loggen"-
Erfolgspfad.

Verwendung (CI und lokal identisch):
    docker run -d -p 5433:5432 -e POSTGRES_USER=control_stack \\
        -e POSTGRES_PASSWORD=testpw -e POSTGRES_DB=control_stack \\
        postgres:16-alpine
    pip install "psycopg[binary]==3.2.4"
    PYTHONPATH=agent-control-stack/src python .github/scripts/check_fresh_install.py

Umgebung: PGHOST (default 127.0.0.1), PGPORT (default 5433),
PGADMIN_USER (default control_stack), PGADMIN_PASSWORD (default testpw).
TEST-ONLY-Credentials, vgl. agent-control-stack/migrations/002_roles.sql.
"""

from __future__ import annotations

import os
import sys

import psycopg

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..",
                                "agent-control-stack", "src"))
sys.path.insert(0, os.path.dirname(__file__))

from boundary_checks import (  # noqa: E402
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
DB = "fresh_install"


def admin_dsn(db: str) -> str:
    return (f"dbname={db} user={ADMIN_USER} password={ADMIN_PW} "
            f"host={HOST} port={PORT} connect_timeout=10")


def main() -> None:
    with psycopg.connect(admin_dsn("postgres"), autocommit=True) as c:
        c.execute(f'DROP DATABASE IF EXISTS "{DB}"')
        c.execute(f'CREATE DATABASE "{DB}"')
    applied = migrate(admin_dsn(DB))
    assert len(applied) == 9, f"erwarte 9 frische Migrationen, bekam: {applied}"
    with psycopg.connect(admin_dsn(DB), autocommit=True) as admin:
        with admin.cursor() as cur:
            assert_migration_chain(cur)
        assert_function_defaults_closed(admin)
        assert_definer_functions_intact(admin)
        assert_direct_dml_denied(admin, DB, HOST, PORT)
    print(f"fresh-install OK: 9 Migrationen, Defaults geschlossen, DML verweigert ({DB})")


if __name__ == "__main__":
    main()
