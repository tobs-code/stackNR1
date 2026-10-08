# Phase 1 Acceptance Matrix — F1, F2, F4, F7

- Status: Verbindlich für die Phase-1-Abnahme
- Datum: 2026-10-09
- Scope: Authorization/Execution Boundary
- Architecture decision: ADR-001 — DB-enforced boundary (`docs/adr-001-f7-db-enforced-boundary.md`)
- Audit baseline: `docs/audit-nr1-report.md` — unverändert; keine Audit-Befunde nachträglich ändern
- Production code: Außerhalb dieses Dokuments unverändert

## 1. Allgemeine Abnahmeregeln

1. Tests verwenden die tatsächlichen Runtime-Datenbankrollen und den realen Ausführungspfad.

2. Negative Tests prüfen persistierten Zustand, nicht nur Exceptions oder Rückgabewerte.

3. Ein abgewiesener Schreibversuch darf weder einen Ressourceneffekt noch einen partiellen Lifecycle-, Ergebnis- oder Evidenzeintrag erzeugen.

4. Jede Änderung an geschütztem Zustand und die dafür erforderlichen Validierungen müssen innerhalb derselben atomaren Datenbanktransaktion wirksam sein.

5. Privilegierte Test-Fixtures zur Erzeugung inkonsistenter Zustände sind ausdrücklich als solche zu kennzeichnen. Sie dürfen nicht mit Angriffsmöglichkeiten einer Runtime-Rolle verwechselt werden.

6. Positive Kontrolltests müssen weiterhin erfolgreiche, autorisierte Ausführungen nachweisen.

7. Ein grüner Testlauf allein genügt nicht: Die Abnahmekriterien müssen vollständig erfüllt sein.

## 2. Verbindliche Tests

| ID    | Testfall                                                                                                            | Erwartetes Ergebnis                                          | Persistente Prüfung                                                                                |
| ----- | ------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------ | -------------------------------------------------------------------------------------------------- |
| F1-N  | Autorisiertes `target` und `arguments.record_id` unterscheiden sich                                                 | Ablehnung ohne Effekt                                        | Beide Ressourcen unverändert; keine neue State-Transition, kein Outbox-Event, kein Erfolgsergebnis |
| F1-P  | `target` und `record_id` stimmen überein; Autorisierung und Version sind gültig                                     | Erfolgreiche Ausführung                                      | Ausschließlich das autorisierte Ziel verändert; Version korrekt erhöht                             |
| F2-N  | Run wird nach Autorisierung, vor Ausführung auf `completed` gesetzt                                                 | Ausführung abgelehnt                                         | Ressource, Resultat, Transitions und Outbox bleiben frei von partiellen Effekten                   |
| F2-R  | Run-Status ändert sich konkurrierend zur Ausführung                                                                 | Keine Ausführung auf Basis eines veralteten Aktivitätschecks | Transaktionale Synchronisierung bzw. CAS verhindert den Effekt nach Abschluss des Runs             |
| F4-N  | Privilegierte Test-Fixture erzeugt `committed` mit Resultat, aber ohne konsistente Effekt-/Transitions-/Evidenzspur | Kein gültiger Replay; Widerspruch wird quarantänisiert       | Kein gefälschtes Resultat als Erfolg zurückgegeben; Quarantäne persistent dokumentiert             |
| F7-N1 | `stack_worker` versucht direkte Ressourcenänderung                                                                  | Datenbank verweigert Zugriff                                 | Ressource unverändert; `InsufficientPrivilege`                                                     |
| F7-N2 | `stack_worker` versucht gefälschte Action-/Resultat-Datensätze einzufügen oder zu verändern                         | Datenbank verweigert nicht erlaubte Operationen              | Keine gefälschte Action oder Erfolgsspur persistiert                                               |
| F7-N3 | `stack_worker` versucht direkte Outbox-/Ledger-Manipulation                                                         | Datenbank verweigert Zugriff                                 | Keine manipulierten Evidenzeinträge persistiert                                                    |
| F7-N4 | `stack_gate` versucht, einen gefälschten terminalen Action-Zustand zu erzeugen                                      | Datenbank verweigert unzulässige Schreiboperationen          | Kein gefälschter Commit-Zustand persistiert                                                        |
| F7-P  | Regulärer Gate-/Worker-/Recovery-Ablauf                                                                             | Legitime Operationen bleiben funktionsfähig                  | Autorisierung, Effekt, Ergebnis und vorgesehene Evidenz konsistent                                 |

## 3. Architekturvorgabe F7

Die Datenbank bildet die Sicherheitsgrenze für geschützte Operationen.

* Runtime-Rollen erhalten keine beliebigen Schreibrechte auf geschützte Ressourcen-, Action- und Evidenztabellen.

* Privilegierte Datenbankfunktionen sind kein ausreichender Schutz, wenn sie die erforderlichen Invarianten nicht selbst durchsetzen.

* Der geschützte Ausführungspfad muss Autorisierung, Zielbindung, aktiven Run, Idempotenz und Versionsprüfung zusammenhängend erzwingen.

* Direkte Manipulationstests müssen mit den jeweiligen Runtime-Rollen ausgeführt werden, nicht ausschließlich mit dem Tabellen-Owner.

* Owner und Superuser bleiben außerhalb des definierten Bedrohungsmodells. Unabhängige Evidenzverankerung ist ein separater Architekturpunkt.

## 4. Abschlusskriterium

**Phase 1 ist erst abgenommen, wenn alle negativen und positiven Tests bestanden sind, persistierte Zustände geprüft wurden und die Tests reproduzierbar auf dem dokumentierten Code-Stand laufen.**

Ein Test, der lediglich einen Fehler zurückgibt, ohne die relevanten Datenbankzustände zu kontrollieren, erfüllt die Abnahmeregel nicht.

Abweichungen werden als offene Findings dokumentiert. Sie dürfen nicht durch Abschwächung der Tests oder stillschweigende Änderung des eingefrorenen Audit-Berichts geschlossen werden.
