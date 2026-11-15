# Phase 3 Acceptance Matrix — F5, F6, F8

- Status: Verbindlich für die Phase-3-Abnahme
- Datum: 2026-11-16
- Scope: Event-Kette, Konflikt-Evidenz, Checkpoint-Anker
- Spec-Basis: `docs/spec-v0.1.md` Rev. 8 (SHA-256 `91B7FCA2…C552105E`)
- Audit-Baseline: `docs/audit-nr1-report.md` — unverändert; keine Audit-Befunde nachträglich ändern
- Architektur: `docs/adr-001-f7-db-enforced-boundary.md`
- Migration: `migrations/011_evidence_chain.sql`

## 1. Allgemeine Abnahmeregeln

1. Tests verwenden die tatsächlichen Runtime-Datenbankrollen und den realen Ausführungspfad.

2. Negative Tests prüfen persistierten Zustand, nicht nur Exceptions oder Rückgabewerte.

3. Sequenz und Vorgängerzeiger entstehen serverseitig; kein Aufrufer (Funktion, IPC, Argument) kann sie setzen.

4. Ein Manipulationsversuch am Vorgängerzeiger, an der Sequenz oder am Anker führt zu einem Fehler — nie zu einer stillen Reparatur.

5. Privilegierte Test-Fixtures (Owner-Eingriffe: Kürzen, Zeiger fälschen, Zeilen löschen) sind als solche gekennzeichnet und simulieren einen kompromittierten Owner, keinen Runtime-Pfad.

6. Positive Kontrolltests müssen weiterhin erfolgreiche, autorisierte Ausführungen mit lückenloser Kette und gültigem Anker nachweisen.

## 2. Verbindliche Tests

| ID | Testfall | Erwartetes Ergebnis | Persistente Prüfung |
| --- | --- | --- | --- |
| F5-N1 | Zwei Commits ohne Writer-Pass | Sequenzen 1,2; `prev_event_id` der 2 zeigt auf die 1 | Outbox-Zeilen und Zeiger in der DB |
| F5-N2 | Aufrufer versucht Sequenz/Zeiger zu setzen | Feld existiert nicht (Funktion + IPC-Requestfeld wird ignoriert) | Sequenz bleibt 1, Zeiger NULL |
| F5-N3 | Parallele Commits im selben Run | Eindeutige, lückenlose Sequenzen | `UNIQUE(run_id, sequence)` + Run-Lock |
| F5-N4 | Lücke in der Outbox (Owner) | Writer bricht ab | `TamperError`, keine Ledger-Zeile |
| F5-N5 | Gefälschter Vorgängerzeiger (Owner) | Writer bricht ab | `TamperError`, keine Ledger-Zeile |
| F5-N6 | Lücke in Outbox **und** Ledger (Owner) | Verify schlägt an | `VerificationError` |
| F6-N1 | Gleicher Key, anderer Payload | Exception **und** genau ein Nachweis | Ein `idempotency_conflict`-Ereignis, kein `state_transitions`, Version unverändert, Status bleibt `authorized` |
| F6-N2 | Identischer Konflikt erneut | Kein Duplikat | Weiterhin genau ein Ereignis |
| F6-N3 | Konflikt-Ereignis nach regulärem Event | Kette bleibt gültig | Sequenz 2, Verify PASS mit Anker |
| F8-N1 | `INSERT`/`UPDATE`/`DELETE` auf `evidence_checkpoints` als Recovery | Datenbank verweigert | `InsufficientPrivilege`; genau ein Checkpoint |
| F8-N2 | Kürzen + Anker beim gekürzten Head (Owner) | Neuer Anker abgelehnt | `checkpoint_regression` |
| F8-N3 | Verify ohne Checkpoint | Abnahme verweigert | `VerificationError` |
| F8-N4 | Zwei gültige Anker, Sprung zurück | Bruch erkannt | `checkpoint_regression`; Kette selbst PASS |
| REG | Phasen 1+2 inkl. Kill-Test | Unverändert grün | Kein Regress in Effekt-, Bindungs-, Lifecycle- oder Evidenzprüfungen |

## 3. Architekturvorgabe F5/F6/F8

* `fn_outbox_append` vergibt `sequence = COALESCE(MAX(sequence),0)+1` und `prev_event_id` unter dem `runs`-Lock; die Funktion ist nicht an Runtime-Rollen vergeben.

* Der Writer leitet `prev_hash` aus dem Ledger-Head ab und prüft die lückenlose Folge **und** den Zeiger, bevor er `fn_ledger_append` aufruft.

* Der Verifier prüft Kontinuität ab 1 in Outbox **und** Ledger, den Vorgängerzeiger, die Hash-Kette, die Checkpoint-Abstammung und liest den Anker selbst. `require_checkpoint=False` ist nur für laufende Runs vorgesehen und ein bewusster Opt-out.

* `evidence_checkpoints` ist append-only (`checkpoint_id BIGSERIAL PRIMARY KEY`); ein neuer Head muss Nachfahre des vorherigen sein.

* Ein Idempotenzkonflikt wird als Rückgabewert behandelt: die Transaktion committet nur das deduplizierte `idempotency_conflict`-Ereignis, erst danach wird die Exception geworfen. So kann der Rollback den Nachweis nicht vernichten.

* Bestehende Datenbanken werden migriert: `previous_event_hash` entfällt, `prev_event_id` wird aus der Sequenzreihenfolge nachgezogen, Checkpoints bekommen eine `checkpoint_id`. Lücken bleiben als NULL sichtbar und fallen im Betrieb auf; es wird nichts stillschweigend repariert.

* Owner und Superuser bleiben ausserhalb des Bedrohungsmodells. Ein kompromittierter Owner kann Zeilen löschen und Anker fälschen; das ist eine dokumentierte Grenze, kein Runtime-Angriffspfad.

## 4. Abschlusskriterium

**Phase 3 ist erst abgenommen, wenn der vollständige Lauf zweimal reproduzierbar ist, frischer Aufbau und Upgrade beide grün sind und die persistierten Zustände den Regeln aus Abschnitt 1 entsprechen.**

Abweichungen werden als offene Findings dokumentiert. Sie dürfen nicht durch Abschwächung der Tests oder stillschweigende Änderung des eingefrorenen Audit-Berichts geschlossen werden.