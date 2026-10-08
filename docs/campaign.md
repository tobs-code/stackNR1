# Fehlerkampagne v0.1 — eingefrorene Testmatrix

Stand: 2026-10-09. Basis-Commit: `325eea6`. Diese Matrix wird vor dem Lauf
festgeschrieben; Implementierung: `tests/adversarial/test_campaign.py`.
Jeder Fall definiert: Startzustand → injizierter Fehler → erwarteter DB-Zustand.

## Gruppe 1 — Autorisierung (→ kein unautorisierter Effekt)

| # | Injektion | Erwarteter DB-Zustand |
|---|---|---|
| A1 | OPA-Deny (falsche Permission) | `actions=denied`, kein Record, `records.version` unverändert |
| A2 | OPA-Timeout / unreachable | Exception, keine Action-Zeile, kein Effect |
| A3 | OPA-Antwort ungültig (Schema/non-bool) | `PolicyError`, keine Freigabe |
| A4 | Auth→Execute-Race: Ressource nach `authorize()` verändert | `execute()` → StaleVersion, kein Effect, keine Ressourcen-Transition |

## Gruppe 2 — Ausführung (→ kein ungültiger/doppelter Effect)

| # | Injektion | Erwarteter DB-Zustand |
|---|---|---|
| B1 | Record nach Persistenz manipuliert (target/permissions) | `ExecutionDenied`, `records.version` unverändert |
| B2 | Record abgelaufen vor `execute()` | `ExecutionDenied` (in-Tx-Check), kein Effect |
| B3 | Actor/Args weichen vom Record ab | `ExecutionDenied`, kein Effect |
| B4 | 4 parallele `execute()` derselben Action | genau 1 Effect, Rest Replay |

## Gruppe 3 — Transaktionen (→ alles-oder-nichts)

Trigger-basierte Fehler an jeder Grenze des atomaren Writes:

| # | Injektion (Trigger RAISE) | Erwarteter DB-Zustand |
|---|---|---|
| C1 | `BEFORE UPDATE ON records` | Rollback: version unverändert, kein Result, keine Transitions, kein Outbox-Event, Status bleibt `authorized` |
| C2 | `BEFORE UPDATE ON actions` (Result-Write) | wie C1 |
| C3 | `BEFORE INSERT ON action_transitions` | wie C1 |
| C4 | `BEFORE INSERT ON state_transitions` | wie C1 |
| C5 | `BEFORE INSERT ON outbox_events` | wie C1 |

## Gruppe 4 — Recovery & Evidence (→ korrekte Rekonstruktion)

| # | Injektion | Erwarteter DB-Zustand |
|---|---|---|
| D1 | Backend-Kill während `execute()` (ACK evtl. verloren) | nach `reconcile()`: max. 1 Effect; `replayed` oder genau 1 Retry |
| D2 | `reconcile()` nach Commit bei divergierter Version | `replayed` (Commit+Result schlägt Versionsdrift) |
| D3 | Writer läuft 4× parallel | keine Verluste/Duplikate, Kette verifizierbar |
| D4 | Outbox-Payload / Ledger-Hash / Reihenfolge manipuliert, Event gelöscht | `VerificationError`, Verifier schreibt nichts |
| D5 | Checkpoint-Head falsch / Kette abgeschnitten | `VerificationError` |
| D6 | Effektive Grant-Matrix pro Rolle | exakt die dokumentierten Privilegien, keine Extras |

## Abschlusskriterien

- Jeder Test prüft PostgreSQL-Zustand (Zeilen, Versionen, Ledger), nicht nur Returns.
- Kein Test läuft als Tabellenbesitzer für Sicherheits-Assertions (Ausnahme: Trigger-Setup C1–C5 + Tamper-Setup D4, dokumentiert je Test).
- Report: `docs/campaign-report.md` mit Commit-SHA, unverändert nach Lauf.
