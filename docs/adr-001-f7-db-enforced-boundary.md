# ADR-001 — F7: Datenbank erzwingt die Sicherheitsgrenze (Variante 2)

- Datum: 2026-10-09
- Status: ENTSCHIEDEN
- Kontext: stackNR1-Befund F7 (`docs/audit-nr1-report.md`, eingefroren — dieser Eintrag ändert den Bericht nicht).
- Angreifergrenze: M3 (kompromittierte Runtime-Credentials, kein Owner/Superuser).

## Entscheidung

Variante 2: Die Datenbank erzwingt die Sicherheitsgrenze für die geschützten Operationen.
Der Prozess allein ist nicht die Sicherheitsgrenze.

## Zielarchitektur (eng begrenzt, keine neue Infrastruktur)

- Runtime-Rollen dürfen geschützte Ressourcen, Action-Status und Evidenz nicht beliebig direkt verändern.
- Geschützte Writes laufen über einen fest definierten Ausführungspfad, der Zielbindung (F1),
  Autorisierung, Run-Status (F2), CAS und Idempotenz gemeinsam in einer Transaktion prüft.
- Autorisierungsdaten und Effekt werden in einer Transaktion konsistent verarbeitet.
- Eine privilegierte Ausführungsfunktion genügt nur, wenn sie selbst alle maßgeblichen Invarianten
  erzwingt — sonst wird die Umgehung lediglich verschoben.
- Owner/Superuser bleibt außerhalb des Schutzmodells; unabhängige Evidenzverankerung (F8)
  bleibt eine gesonderte Architekturfrage.

## Konsequenz

Bis zur Umsetzung gilt weiter: v0.1 ist nicht als gegen kompromittierte Runtime-Prozesse
abgesichert deklarierbar. Die 81 grünen Tests der Kampagne bleiben gültig, decken M3 aber nicht ab.

## Abnahmeregel Phase 1

Kein Phase-1-Fix (F1, F2, F4, F7) gilt als fertig, solange Negativtests mit den tatsächlichen
Runtime-Credentials nicht belegen: kein fremder Ressourcen-Write, kein gefälschter Commit als
Replay, keine direkte Evidenz-Manipulation. Alle Prüfungen gegen den persistenten DB-Zustand.
Erst danach beginnt der Fix-Zweig; davor wird die Acceptance-Matrix für Phase 1 verbindlich gemacht.
