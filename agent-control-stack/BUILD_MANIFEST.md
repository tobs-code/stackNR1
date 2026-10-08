# Build Manifest v0.1

Verbindliche Grundlage: `docs/spec-v0.1.md` Rev. 2 (eingefroren).

- SHA-256 (spec-v0.1.md): `E5D3C8A24F34328A224CA99ABD3CA6E4D64894DB0699A236A8031871A26D9B5F`
- Status: FROZEN — keine stillen Änderungen während der Implementierung.
  Jede Änderung braucht neue Rev. + neuen Hash + Eintrag hier.
- Scope: DB-interner Demo-Write zuerst (atomare Transaktion),
  kein externer Effect in v0.1.
- Regel: Nicht implementierter Schutz = fehlend, nicht bestanden.
  Tests prüfen DB-Zustand + Effect + Audit-Ereignis, nicht nur Statuscodes.

## Änderungslog

| Datum | Änderung | Hash |
|---|---|---|
| 2026-10-09 | Rev. 2 eingefroren | E5D3C8A2…9B5F |
