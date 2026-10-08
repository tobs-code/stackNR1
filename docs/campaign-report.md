# Kampagnen-Report v0.1

- Datum: 2026-10-09
- Matrix: `docs/campaign.md` (eingefroren vor dem Lauf)
- Geprüfter Code-Commit: `e91b84960df0ec4fb81286e47494d349a9527524`
  (81/81-Lauf auf genau diesem Code-Stand; Matrix-Provenienz bleibt separat:
  `docs/campaign.md`, eingefroren vor dem Kampagnen-Lauf)
- Testbefehl: `$env:PYTHONPATH="src"; python3 -m pytest tests/ -q -p no:cacheprovider`
  (Workdir `agent-control-stack/`)
- Python: 3.13.7; pydantic 2.12.0 (installiert; Pin in pyproject: 2.10.4),
  psycopg[binary] 3.2.4, pytest 8.3.4 (8.4.2 installiert), httpx 0.28.1
- Umgebung: Postgres 16 (Container `stack-pg`), OPA 0.68 (`stack-opa`),
  Test-DB `control_stack_test` (migriert 001–004 via `mig/runner.py`;
  Stand per `SELECT name FROM schema_migrations` verifiziert)

## Ergebnis: 81/81 grün

| Suite | Tests |
|---|---|
| unit (contracts, JCS, OPA-Client) | 16 |
| integration state/gate/execution/recovery/roles/evidence/worker | 48 |
| adversarial campaign + closeout (C1–C5, A4, D2, D6 voll, E, I6, I7, demo_read, I8) | 17 |

## Abdeckung je Matrix-Gruppe

- Autorisierung A1–A3: `test_gate.py` (Deny/timeout/Schema) + A4 neu (Race → StaleVersion).
- Ausführung B1–B4: `test_execution.py` (Tamper/Expiry/Mismatch/Parallelität).
- Transaktionen C1–C5: neu, Trigger-Injektion je Grenze → jeweils Voll-Rollback
  (Status `authorized`, kein Result, keine Transitions, kein Outbox-Event).
- Recovery & Evidence D1–D6: Kill-Test (`test_recovery.py`), D2 neu
  (Replay schlägt Drift), D3–D5 (`test_evidence.py`), D6 neu (Grant-Matrix exakt).
- E: Verifier schreibt nie (zwei Fehlschläge, Ledger unverändert bis auf injizierten Tamper).

## Bekannte Grenzen (kein Sicherheitsbeweis)

- Trigger-Setup + Tamper-Setup laufen als Owner (dokumentierte Ausnahme je Test).
- Kill-Test trifft den Commit-Zeitpunkt nicht deterministisch; Invariante
  (max. 1 Effect) gilt per Konstruktion für beide Ausgänge.
- Externe Side Effects ausserhalb des Modells (nur DB-interner Write getestet).
- Owner-Angreifer ausserhalb des Modells; Checkpoint-Grenze dokumentiert.
