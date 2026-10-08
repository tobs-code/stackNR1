# Kampagnen-Report v0.1

- Datum: 2026-10-09
- Matrix: `docs/campaign.md` (eingefroren vor dem Lauf)
- Code-Stand: Commit `325eea6` + uncommittete Kampagnen-Tests (dieser Report
  wird mit demselben Commit gepusht; SHA siehe Git-Log)
- Umgebung: Postgres 16 (Container `stack-pg`), OPA 0.68 (`stack-opa`),
  Test-DB `control_stack_test` (frisch migriert 001–003)

## Ergebnis: 67/67 grün

| Suite | Tests |
|---|---|
| unit (contracts, JCS, OPA-Client) | 16 |
| integration state/gate/execution/recovery/roles/evidence | 42 |
| adversarial campaign (C1–C5, A4, D2, D6, E) | 9 |

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
