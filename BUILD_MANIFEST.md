# Build Manifest v0.1

Verbindliche Grundlage: `docs/spec-v0.1.md` Rev. 6 (eingefroren).

- SHA-256 (spec-v0.1.md): `7A11EF3DC8A6276D8C6776B66DD3AC34A8DEA2DF2DEA00E2970CA100CA6207D5`
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
| 2026-10-09 | Rev. 6: §8 evidenzgebunden abgenommen, I6 kill_mid_tx echt, Recovery-Bindungsprüfung, Seq-Minimalrechte (004) | 7A11EF3D…6207D5 |
