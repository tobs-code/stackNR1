"""Migrations-Runner: Dateien in Reihenfolge, als Owner-Admin (Superuser).

Verfolgt angewendete Migrationen in schema_migrations. Idempotent.
Aufruf: python -m control_stack.mig.runner "<admin-dsn>"
"""
from __future__ import annotations

import os
import sys

import psycopg

MIGRATIONS = ["001_schema.sql", "002_roles.sql", "003_evidence.sql",
               "004_seq_least_privilege.sql", "005_phase1_boundary.sql",
               "006_owner_schema_usage.sql", "007_test_kill_grant.sql"]


def migrate(admin_dsn: str) -> list[str]:
    base = os.path.join(os.path.dirname(__file__), "..", "..", "..", "migrations")
    base = os.path.abspath(base)
    applied: list[str] = []
    with psycopg.connect(admin_dsn, autocommit=True) as c:
        c.execute("CREATE TABLE IF NOT EXISTS schema_migrations"
                  " (name TEXT PRIMARY KEY, applied_at TIMESTAMPTZ DEFAULT now())")
        rows = c.execute("SELECT name FROM schema_migrations").fetchall()
        done = {r[0] for r in rows}
        for name in MIGRATIONS:
            if name in done:
                continue
            sql = open(os.path.join(base, name), encoding="utf-8").read()
            c.execute(sql)
            c.execute("INSERT INTO schema_migrations (name) VALUES (%s)", (name,))
            applied.append(name)
    return applied


if __name__ == "__main__":
    print(migrate(sys.argv[1]))
