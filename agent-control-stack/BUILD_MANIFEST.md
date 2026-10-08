# Build Manifest v0.1

Verbindliche Grundlage: `docs/spec-v0.1.md` Rev. 4 (eingefroren).

- SHA-256 (spec-v0.1.md): `34930FC3490A1ACB57280E57D330E5EEDAED077BD67DD09C63F766686DA20ACD`
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
| 2026-10-09 | Rev. 3: B1 result-Speicherung, B2 Multi-Transition, B3 vollständiger Auth-Record | 85DD2DD4…CA3DC4 |
| 2026-10-09 | Rev. 4: C1 kanonisches Feldset = Record-Felder (args_hash/context_hash), Record-Immutability via REVOKE; C2 action_transitions vs state_transitions getrennt | 34930FC3…A20ACD |
