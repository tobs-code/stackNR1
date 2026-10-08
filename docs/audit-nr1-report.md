# stackNR1 — Audit-Bericht (EINGEFROREN)

- Datum: 2026-10-09
- Audit-Stand (HEAD): `ff7d18b`
- Code unter Test laut `campaign-report.md`: `e91b849` (Diff zu verifiziertem Lauf `03c779e` = nur Report-Datei)
- Normative Referenz: `docs/spec-v0.1.md` Rev. 6 (eingefroren)
- Dienste: Postgres 16 (`stack-pg`, Port 5433), OPA 0.68 (`stack-opa`, Port 8181), Test-DB `control_stack_test`
- Regeln: kein Produktionscode und keine bestehenden Tests geändert (Arbeitskopie verifiziert sauber);
  ausschließlich lokale Testdienste/Testdaten; jeder Befund per persistentem DB-Zustand belegt.
- Status: EINGEFROREN. Änderungen nur als neuer Revisions-Eintrag, nie still.

## Angreifermodelle

- **M1 (Agent-Eingaben):** kontrolliert Proposal-Felder, IPC-Argumente (`action_id`, `arguments`, `actor_id`,
  `event_id`, `run_sequence`, `prev_event_hash`). Kein DB-Zugriff, keine Credentials.
- **M2 (Race/Retry):** konkurrierende legitime Pfade, Abstürze, verlorene ACKs, Reconcile-Aufrufe.
- **M3 (Runtime-Credentials):** besitzt Worker-, Gate- oder Recovery-Credentials (z. B. kompromittierter
  Prozess/Host), spricht direkt SQL. Kein Owner/Superuser. **Dies ist die strittige Grenze (F7).**
- Außerhalb des Modells: Owner/Superuser-Angreifer (kann Kette + Checkpoint konsistent neu schreiben).

## Befunde

### F1 — BUG, P0: Effekt auf anderer Ressource als autorisiert (M1)
- Invariante: I3 (Bindung) + I4 (ressourcenspezifische Version), Spec §1/§5.
- Ursache: Gate prüft OPA/`resource_version` gegen `proposal.target`
  (`src/control_stack/gate/executor.py:50`), CAS-Write läuft gegen `arguments.record_id`
  (`src/control_stack/execution/broker.py:88`, `adapters.py`). Kein Cross-Check `target == record_id`.
- Repro: `authorize(target=rec-1, arguments={record_id: rec-2, status: approved}, expected=0)`,
  beide Version 0 → `execute()` committet `rec-2` v0→v1; `rec-1` unverändert;
  `state_transitions` zeigt `rec-2`, `actions`/`authorization_records` zeigen `rec-1`.
- Erwartet: Reject ohne Effect. Tatsächlich: fremder Effect + divergente Buchhaltung.
- Fix-Vertrag: genau ein kanonisches Ziel; `arguments.record_id == target` sonst Abbruch ohne Effect;
  Versionsprüfung + CAS auf demselben Ziel in derselben Transaktion.
- Regression: Mismatch-Versuch ⇒ `ExecutionDenied`; beide Ressourcen unverändert, keine
  `state_transitions`-Zeile, kein Outbox-Event, kein `result`.

### F2 — BUG, P0: Write nach Run-Abschluss committet (M1/M2)
- Invariante: Spec §3 „Writes nur wenn `active`“ (I2/Lifecycle).
- Ursache: weder `broker.execute()` noch `repository._enforce_guard()` prüfen `runs.status`.
- Repro: `authorize()` (active) → `UPDATE runs SET status='completed'` → `execute()` committet v0→v1
  inkl. Transitionen + Outbox.
- Fix-Vertrag: `runs.status == 'active'` **in derselben Transaktion** wie der Effect prüfen
  (Run-Zeile sperren/CAS), sonst Rollback ohne Effect. Check zu Transaktionsbeginn genügt nicht.
- Regression: Race authorize→complete→execute ⇒ kein Effect, Version/Transitions/Outbox unverändert.

### F4 — BUG, P0: Fake-Commit wird als Replay akzeptiert (M2/M3)
- Invariante: I5/I6 (nur nachgewiesener Effect ⇒ Replay).
- Ursache: `recovery/reconciliation.py:36-37` gibt bei `committed + result` sofort `replayed`
  zurück, ohne `state_transitions`/Outbox/Effect zu verlangen.
- Repro: `actions`-Zeile `committed` + Fake-`result`, 0 Transitions, 0 Outbox-Events →
  `reconcile()` ⇒ `replayed {'fake': True}`.
- Fix-Vertrag: `replayed` nur bei konsistentem Nachweis (Transition + `result` + Ressourcenvversion
  passen zusammen); Widerspruch ⇒ `quarantined`, nie `replayed`.
- Regression: geschmiedete `committed`-Zeile ohne Transition ⇒ `quarantined`, kein Replay-Result.

### F7 — ARCHITECTURAL_LIMIT, P0 (Architekturentscheidung, M3)
- Frage: Erzwingt die DB die Sicherheitsgrenze selbst, oder nur der Prozess?
- Belegt mit echten Rollen-Verbindungen: `stack_worker` kann `records` direkt ändern,
  `committed`-Actions mit Fake-Result einschleusen (→ F4 adelt sie) und `outbox_events` +
  `evidence_ledger` direkt beschreiben; `stack_gate` kann `committed`-Zeilen einschleusen.
  Die D6-Grant-Matrix ist exakt, testet aber nur Happy-Path-Rechte, nie Missbrauch.
- Entscheidung offen (Varianten: Prozess-als-Grenze vs. DB-seitig erzwungener Ausführungspfad
  mit Autorisierung + Run-Status + Zielbindung + CAS + Idempotenz in einer Transaktion).
  Bis zur Entscheidung gilt: **v0.1 ist nicht als gegen kompromittierte Runtime-Prozesse
  abgesichert deklarierbar** (präzise Aussage über den getesteten Umfang).
- Regression (bei Variante „DB als Grenze“): Negativmatrix je Rolle — direkte Ressourcen-Writes,
  gefälschte Actions, direkte Evidenz-Inserts und Record-Manipulation scheitern mit
  `InsufficientPrivilege`; legitime Pfade funktionieren weiterhin.

### F3 — BUG, P1: Illegale/falsche Lifecycle-Historie (M2)
- Invariante: Spec §3 (Automat) + §4 (`actions.status` = Snapshot der letzten Transition).
- Belegt: `reconcile()` schreibt `outcome_unknown→outcome_unknown` (illegal; Altstatus geht verloren,
  `recovery/controller.py:35-42`); Retry-Commit schreibt danach `authorized→executing` statt
  `outcome_unknown→executing`; Quarantäne schreibt **keine** Transition (Status divergiert).
- Fix-Vertrag: alle Statuswechsel über einen zentralen Übergangspfad in derselben Transaktion wie
  der Snapshot; illegale Paare scheitern (DB-CHECK oder unvermeidbarer Pfad).
- Regression: reconcile→retry→commit erzeugt exakt
  `… authorized, outcome_unknown, executing, confirmed, committed` (alle Paare legal);
  Quarantäne hinterlässt Abschluss-Transition.

### F5 — BUG, P1: Sequenzen/Verkettung schwächer als suggeriert (M1/M2)
- Invariante: Spec §4 (Sequenz unter Run-Lock; Lücke/Duplikat ⇒ Writes stoppen).
- Belegt: `run_sequence`/`prev_event_hash` aus IPC ungeprüft persistiert; `previous_event_hash`
  wird von Writer/Verifier nie gelesen; Verifier ohne Checkpoint akzeptiert Lücke (seq 1,3 ⇒ PASS);
  negative Sequenz persistiert.
- Fix-Vertrag: Sequenz serverseitig pro Run atomar vergeben; `prev_hash` aus Vorgänger ableiten;
  Verifier prüft Kontinuität + Outbox↔Ledger↔Checkpoint-Beziehung.
- Regression: Lücke/Duplikat/Müll-Hash ⇒ Commit scheitert bzw. Verifier schlägt an.

### F8 — ARCHITECTURAL_LIMIT / SPEC_GAP, P1 (M3)
- `verify_run()` ohne Checkpoint erkennt Abschneiden nicht (gekürzte Kette ⇒ PASS, 1 Event).
- `evidence_checkpoints` ist per `ON CONFLICT DO UPDATE` durch `stack_recovery` beliebig
  überschreibbar (`evidence/verifier.py:55-61`): Kürzen → Checkpoint neu setzen → Verify PASS.
  Ein Anker in derselben Vertrauensdomäne ist kein unabhängiger Anker.
- Fix-Vertrag: Checkpoint-Berechtigungen neu gestalten (append-only / getrennte Domäne / externer
  Anker); Verifier-Pflicht zum Checkpoint für Abnahme definieren.
- Regression: Kürzung + Überschreibversuch ⇒ weiterhin `VerificationError`.

### F6 — BUG, P1: `idempotency_conflict`-Ereignis fehlt (M1)
- Spec §6 Test 5 verlangt Ablehnung **+ Sicherheitsereignis**. `IdempotencyConflictError` wird
  geworfen, aber nie ein Outbox-Event geschrieben (Typ nur im CHECK-Constraint, kein `INSERT`).
- Fix-Vertrag: Konflikt persistiert `idempotency_conflict`-Evidence (transaktional, ohne Effect).
- Regression: gleicher Key/anderer Payload ⇒ Exception **und** genau ein Nachweis-Event.

### F9 — SPEC_GAP mit BUG-Anteil, P2: Read-Pfad (M1/M2)
- `execute_read()` prüft `expected_resource_version` nie (autorisiert v0, geliefert v5, `confirmed`).
- Keine Read-Idempotenz: jeder Doppel-Read hängt erneut `authorized→executing→confirmed` an.
- Fix-Vertrag: Read-Versionssemantik in Spec klären + implementieren; Wiederholungsregel definieren.
- Regression: stale Read ⇒ Reject bzw. spezifiziertes Verhalten; Doppel-Read ohne Transitionswachstum.

### F10 — TEST_GAP, P1 (strukturelle Ursache von F3)
- Die §4-Pair-CHECKs auf `action_transitions` existieren nicht; `transition()` ist Dead Code
  (nur `transition_action`, nie heißer Pfad); `failed` unerreichbar. Wird durch F3-Fix mit abgedeckt.

## Ohne Gegenbeispiel (getestete Fälle, kein Beweis)
Record-Tamper/Expiry/Actor-/Args-Mismatch ⇒ `ExecutionDenied` ohne Effect; Stale-CAS ⇒ Reject;
`_test_hook` via Worker-IPC nicht erreichbar; unbekannte IPC-Ops/fehlende DSN fail closed.

## Phasierung (Empfehlung)
- Phase 1 (Autorisierung/Ausführungsgrenze): F1, F2, F4, F7 (erst F7 entscheiden).
- Phase 2 (Lifecycle-Invariante): F3, F10.
- Phase 3 (Evidenz): F5, F6, F8.
- Phase 4 (Read-Vertrag + Regression): F9 + Negativmatrix aller Befunde (DB-Zustand, nicht nur Exceptions).
