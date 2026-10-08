# Build Manifest v0.1

Verbindliche Grundlage: `docs/spec-v0.1.md` Rev. 5 (eingefroren).

- SHA-256 (spec-v0.1.md): `9E0E0CB7A9FF4AED554714D84C3EABB5961067C3CEEFD17DF8B552C169C1EE04`
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
| 2026-10-09 | Rev. 5: D1 demo_read-Pfad, D2 Worker-Prozess+IPC, D3 Deny-Fingerprint, D4 TEST-ONLY I6-Hooks | 9E0E0CB7…1EE04 |
