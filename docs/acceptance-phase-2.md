# Phase 2 Acceptance Matrix — F3, F10

- Status: Verbindlich für die Phase-2-Abnahme
- Datum: 2026-11-15
- Scope: Lifecycle-Historie und DB-erzwungene Statusübergänge
- Spec-Basis: `docs/spec-v0.1.md` Rev. 7 (SHA-256 `F2BDE27F…C2B8B3`)
- Audit-Baseline: `docs/audit-nr1-report.md` — unverändert; keine Audit-Befunde nachträglich ändern
- Architektur: `docs/adr-001-f7-db-enforced-boundary.md`
- Migration: `migrations/010_lifecycle.sql`

## 1. Allgemeine Abnahmeregeln

1. Tests verwenden die tatsächlichen Runtime-Datenbankrollen und den realen Ausführungspfad.

2. Negative Tests prüfen persistierten Zustand, nicht nur Exceptions oder Rückgabewerte.

3. Jeder Statuswechsel erzeugt genau einen `action_transitions`-Eintrag; `actions.status` entspricht am Transaktionsende dem letzten Eintrag (bzw. `proposed` ohne Eintrag).

4. Ein abgewiesener Übergang darf weder den Snapshot noch die Historie verändern.

5. Privilegierte Test-Fixtures zur Erzeugung inkonsistenter Zustände sind ausdrücklich als solche gekennzeichnet und deaktivieren die Guards nur lokal.

6. Positive Kontrolltests müssen weiterhin erfolgreiche, autorisierte Ausführungen nachweisen.

## 2. Verbindliche Tests

| ID | Testfall | Erwartetes Ergebnis | Persistente Prüfung |
| --- | --- | --- | --- |
| F3-N1 | Reconcile auf `authorized` vor dem ersten Ausführungsversuch | `outcome_unknown` + ein Reconcile-Job | Exakt `authorized→outcome_unknown`; Snapshot `outcome_unknown`; ein offener Job |
| F3-N2 | Retry nach F3-N1 bis zum Commit | Genau ein Effect | Folge `authorized, outcome_unknown, executing, confirmed, committed`; alle Paare legal |
| F3-N3 | Doppeltes/paralleles Reconcile | Keine Duplikate | Kein `outcome_unknown→outcome_unknown`; genau eine Kante, ein Job |
| F3-N4 | Quarantäne aus `authorized`, `executing`, `committed` | Status `quarantined` | Genau eine `X→quarantined`-Kante passend zum Quellstatus; ein Quarantine-Job |
| F3-N5 | Gate-Deny | Ablehnung ohne Effect | `proposed→validated→denied`; Snapshot `denied`; Ressource unverändert |
| F3-N6 | Ausführung einer `quarantined` Action | Ablehnung ohne Effect | Keine neue Transition, kein Ressourcen-Write |
| F10-N1 | Illegales Paar direkt als Owner | Datenbank verweigert | `CheckViolation`; keine Zeile persistiert |
| F10-N1b | Snapshot ohne Transition geändert (Owner) | Datenbank verweigert | Deferred Trigger rollt die Tx zurück; Snapshot unverändert |
| F10-N2 | Illegale Writes/Funktionskanten als `stack_gate`, `stack_worker`, `stack_recovery` | Datenbank verweigert | `InsufficientPrivilege` bzw. `lifecycle_forbidden`; Historie unverändert |
| F10-N3 | Globale Invariante nach gemischten Abläufen | Snapshot = letzte Transition | Jede Action erfüllt `status = COALESCE(last_transition, 'proposed')` |
| F10-N4 | Alle 121 Statuspaare gegen den echten CHECK | Menge = kanonische Menge | Akzeptierte Paare == `control_stack.contracts.transitions.PAIRS` |
| REG | Phase-1-Suite (F1/F2/F4/F7) und Kill-Test | Unverändert grün | Kein Regress in Effekt-, Bindungs- oder Evidenzprüfungen |

## 3. Architekturvorgabe F3/F10

* Statuswechsel laufen ausschliesslich über `SECURITY DEFINER`-Funktionen (`fn_gate_transition`, `fn_recovery_transition`, intern `fn_apply_transition`, `fn_execute_write`, `fn_execute_read`).

* Runtime-Rollen besitzen kein direktes `INSERT`/`UPDATE` auf `actions` oder `action_transitions`; das Gate behält nur `INSERT` für den Startzustand `proposed`.

* Der Pair-CHECK ist die zweite Schranke; der deferred Konsistenz-Trigger ist die dritte und prüft Snapshot gegen Historie am Transaktionsende.

* Bestehende Datenbanken mit illegalen Altzeilen bleiben startfähig: Der CHECK wird `NOT VALID` angelegt, gilt aber für alle neuen Zeilen. Die Reparatur von Altzeilen ist ein dokumentierter, manueller Schritt.

* Owner und Superuser bleiben ausserhalb des Bedrohungsmodells; ein kompromittierter Owner kann Guards deaktivieren. Das ist eine dokumentierte Grenze, kein Runtime-Angriffspfad.

## 4. Abschlusskriterium

**Phase 2 ist erst abgenommen, wenn beide Testläufe (Upgrade und frischer Aufbau) grün sind, der vollständige Lauf zweimal reproduzierbar ist und die persistierten Zustände den Regeln aus Abschnitt 1 entsprechen.**

Abweichungen werden als offene Findings dokumentiert. Sie dürfen nicht durch Abschwächung der Tests oder stillschweigende Änderung des eingefrorenen Audit-Berichts geschlossen werden.
