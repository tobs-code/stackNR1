# Safety Stack v0.1 Spezifikation (prüfbare Bauanleitung) — Rev. 6

Abgeleitet aus `read.me`, überarbeitet nach Reviews.
Rev. 5 schliesst Abnahme-Lücken: (D1) `demo_read`-Ausführungspfad
(effect-frei, terminal `confirmed`, Leseergebnis als `result`, kein Outbox-Event);
(D2) Worker als separater OS-Prozess mit eigenen Credentials + JSON-StdIO-IPC
(Gate importiert `execution` nie — per AST-Check getestet);
(D3) I7 Deny-Fingerprint (`repeat_of` bei gleichem Fingerprint <15min);
(D4) deterministische I6-Hooks als TEST-ONLY (`_test_hook`).
Status: EINGEFROREN (siehe BUILD_MANIFEST.md). Keine stillen Änderungen.

## 0. Scope v0.1

Ziel: minimaler sicherer Kern. Enthalten: Action Contract, Policy-Prüfung
(OPA), obligatorisches Gate, Zustandsautomat, PostgreSQL, 2 Demo-Tools
(`demo_read` read-only, `demo_update_record` schreibend **in PostgreSQL**).
Explizit NICHT in v0.1: externer Seiteneffekt (kommt erst nach stabilem
DB-Write-Pfad), Qdrant/KG-Memory, Temporal, Envoy, Rekor-Anker (nur lokaler
Checkpoint ausserhalb des Event-Schreibers), ClickHouse, Manual Approval
(deferriert → `quarantined`, siehe §7.1).

Fail-closed: Fehler, Timeout oder unbekannter Zustand auf dem Pfad
Proposal → Ausführung ⇒ Deny/Block, nie Allow. Wenn Evidence-Persistenz
nicht verfügbar ⇒ Writes blockiert.

Demo-Write-Entscheidung (Review §5): fachlicher Effect von
`demo_update_record` läuft **direkt in PostgreSQL**, damit Effect +
Idempotency Record + State Transition + Outbox Event in **einer Transaktion**
liegen. Erst danach externer Effect mit echtem `outcome_unknown`.

---

## 1. Invarianten (I1–I8, testbar)

- **I1 Kein Bypass (P0-fix):** Tool-Effect nur über vom Gate kontrollierten
  Ausführungskanal. Worker = separater OS-Prozess mit eigenen Credentials;
  Adapter akzeptiert keine frei konstruierbaren Aufträge, sondern lädt den
  serverseitig persistierten Authorization Record und prüft ihn unmittelbar
  vor dem Effect. Test: direkter Funktions-/IPC-Aufruf ohne Record ⇒ kein Effect.
- **I2 Deny-dominiert:** Nur explizites `allow` führt weiter. `deny`,
  `abstain`, `error`, Timeout (>500ms), unreachable ⇒ kein Effect.
- **I3 Bindung (Rev. 4, C1-fix):** Freigabe = unveränderlicher Authorization
  Record. Rekonstruktionsfunktion (verbindlich, identisch bei Erzeugung und
  Prüfung):
  1. Kanonisiere `arguments` per JCS (Schlüssel sortiert, UTF-8) →
     `args_hash = sha256(canon_args_hex)`.
  2. Kanonisiere `preconditions`-Snapshot per JCS → Teil des Record-Feldsets.
  3. `canonical_hash = sha256(JCS(record_fields))` mit exakt diesem Feldset
     (Reihenfolge JCS, keine Extras):
     `{action, target, args_hash, actor_id, permissions_sorted,
     expected_resource_version, preconditions_canon, policy_version,
     context_hash, action_id, expires_at_iso}`.
  Der Worker lädt `authorization_records` + `actions`-Zeile, vergleicht jedes
  Feld und berechnet den Hash neu — Mismatch ⇒ Reject. Unveränderlichkeit:
  Worker-DB-Rolle erhält kein UPDATE/DELETE auf `authorization_records`
  (REVOKE, siehe §4); App-Schicht schreibt Records nur einmal (INSERT).
  Hash allein authentifiziert nichts — Bindung gilt nur zusammen mit
  Reload + Feldvergleich + Rollentrennung.
- **I4 Stale-Reject (P0-fix):** Versionsprüfung + Übergang **atomar**
  (`SELECT ... FOR UPDATE` auf betroffener Zeile oder Compare-and-Swap-
  Update `WHERE version = expected`). TOCTOU zwischen Check und Write ⇒
  Reject. Version ist **ressourcenspezifisch** (siehe §4, `records.version`),
  nicht nur run-weit; bei mehreren Ressourcen alle binden.
- **I5 Idempotenz (P0-fix):** Atomarer Claim vor Effect (INSERT … ON CONFLICT-
  Logik, §4). Regeln: gleicher Key + gleicher Payload + abgeschlossen ⇒
  gespeichertes Ergebnis; gleicher Key + gleicher Payload + laufend ⇒ Status,
  keine Zweitausführung; gleicher Key + anderer Payload ⇒ hart ablehnen +
  Sicherheitsereignis. Key wird **serverseitig** an Aktion gebunden
  (`run_id + action_id`), nicht frei vom LLM gewählt.
  Exactly-once-Grenze: garantiert nur für DB-internen Effect (eine
  Transaktion). Für externe Systeme nur via zielseitiger Idempotency-ID oder
  Reconcile — sonst bleibt `outcome_unknown` bestehen.
- **I6 Outcome-Unknown:** Timeout/keine Bestätigung ⇒ `outcome_unknown`,
  kein Retry ohne Reconcile + Idempotenz-Nachweis.
- **I7 Kein Self-Bypass (P1-eingeengt):** definiert über kanonischen Payload
  + normalisierte Ziel-ID + gleiche Aktionsklasse + gleicher Run, mit
  Deny-Fingerprint begrenzter Gültigkeit. Wiederholungs-/Umgehungsversuche
  werden protokolliert; Re-Autorisierung nur bei explizit geänderter
  Voraussetzung. Keine Garantie gegen beliebige semantische Umformulierung.
- **I8 Manuelle Freigabe:** in v0.1 **deferriert** — kein Approval-Pfad,
  betroffene Aktionen gehen nach `quarantined`. Falls später eingeführt:
  gilt nur für `(action_id, action, target, args-hash, state_version)`,
  Einmalverwendung, Ablaufzeit, Freigabe-Identität ≠ Agenten-Identität,
  hebt I1–I6 nie auf.

## 2. Aktionsvertrag

```python
class ActionProposal(BaseModel):
    action_id: str            # UUID, vom Gate vergeben/geprüft
    run_id: str
    # actor_id NICHT vom LLM — setzt das Gate aus Auth-Kontext:
    action: Literal["demo_read", "demo_update_record"]
    target: str               # normalisierte Ziel-ID
    arguments: dict           # strikt je Aktion validiert
    expected_resource_version: int  # Version des betroffenen Records
    model_config = ConfigDict(extra="forbid")  # unbekannte Felder ⇒ Reject
```

- `demo_read`: `{record_id: str}`.
- `demo_update_record`: `{record_id: str, status: Literal["approved","rejected"]}`.
- `idempotency_key = f"{run_id}:{action_id}"`, serverseitig gebildet.
  Typo `idempotivity_key` aus Rev. 1 behoben.

## 3. Zustandsautomat

Action: `proposed → validated → authorized → executing →
{confirmed | failed | outcome_unknown} → {committed | quarantined}`,
terminal zusätzlich `rejected`, `denied`.
Fachlicher Endstatus (`confirmed/failed/quarantined`) bleibt terminal;
Audit-Verbuchung ist separates Merkmal/Ereignis (kein
`failed → committed`-Missverständnis aus Rev. 1).

| Von | Nach | Bedingung |
|---|---|---|
| proposed | validated | Schema + Capability ok |
| proposed | rejected | Schema/Capability verletzt |
| validated | authorized | Preconditions ok + OPA allow + Authorization Record persistiert |
| validated | denied | OPA deny/error/timeout/abstain |
| validated | rejected | Precondition/Stale atomar verletzt |
| authorized | executing | atomarer Idempotency-Claim erfolgreich |
| executing | confirmed | Effect verifiziert |
| executing | failed | definitiver Fehlschlag |
| executing | outcome_unknown | Timeout/keine Bestätigung |
| outcome_unknown | executing | nur nach Reconcile + Idempotenz-Nachweis |
| outcome_unknown | quarantined | Reconcile ergebnislos |
| confirmed | committed | Transaktion (Effect+Version+Outbox) erfolgreich |

Run: `active → {completed | aborted | quarantined}`; Writes nur wenn `active`.

## 3b. Lese-Pfad (Rev. 5, D1)

`demo_read` ist effect-frei: Guard-Prüfung + Record-Reload + `verify()` +
Expiry-Check wie beim Write, dann `SELECT` der Ressource in derselben
Transaktion. Lifecycle: `… → authorized → executing → confirmed` (terminal;
kein `committed`). Das Leseergebnis wird als `actions.result` persistiert
(erfüllt den Result-CHECK, ermöglicht Replay). Keine Ressourcen-Transition,
kein Outbox-Event — Reads verändern keinen fachlichen Zustand.

## 4. SQL-Schema (PostgreSQL, v0.1)

```sql
CREATE TABLE runs (
  run_id TEXT PRIMARY KEY,
  owner TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'active'
    CHECK (status IN ('active','completed','aborted','quarantined')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Fachliche Ressource für Demo-Write (ressourcenspezifische Version, §P0)
CREATE TABLE records (
  record_id TEXT PRIMARY KEY,
  status TEXT NOT NULL DEFAULT 'pending'
    CHECK (status IN ('pending','approved','rejected')),
  version INT NOT NULL DEFAULT 0
);

CREATE TABLE actions (
  action_id TEXT PRIMARY KEY,
  run_id TEXT NOT NULL REFERENCES runs(run_id),
  action TEXT NOT NULL CHECK (action IN ('demo_read','demo_update_record')),
  target TEXT NOT NULL,
  args_hash TEXT NOT NULL,           -- unveränderlich nach authorized
  idempotency_key TEXT NOT NULL UNIQUE,
  idempotency_payload_hash TEXT NOT NULL,
  status TEXT NOT NULL
    CHECK (status IN ('proposed','validated','authorized','executing',
                      'confirmed','failed','outcome_unknown',
                      'committed','quarantined','rejected','denied')),
  expected_resource_version INT NOT NULL,
  result JSONB NULL,                -- B1: gespeichertes Ergebnis; atomar mit
                                    -- Effect geschrieben, Replay liest hier
  result_written_at TIMESTAMPTZ NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  CHECK ((status NOT IN ('confirmed','committed') OR result IS NOT NULL))
);

-- B3: vollständiger Authorization Record. Alle Hash-Eingaben sind hier
-- oder per FK in actions persistiert; der Worker rekonstruiert daraus
-- denselben canonical_hash (JCS über das Feldset unten, §1 I3).
-- Unveränderlichkeit (C1): Gate-Rolle INSERT-only auf
-- authorization_records; Worker-Rolle SELECT-only (REVOKE UPDATE, DELETE,
-- als Migrations-SQL im Build-Schritt nachziehen.)
CREATE TABLE authorization_records (
  action_id TEXT PRIMARY KEY REFERENCES actions(action_id),
  canonical_hash TEXT NOT NULL,
  action TEXT NOT NULL,              -- aus actions gespiegelt, Reload-Vergleich
  target TEXT NOT NULL,              -- normalisierte Ziel-ID
  args_hash TEXT NOT NULL,           -- canon(action+args)
  actor_id TEXT NOT NULL,
  permissions TEXT[] NOT NULL,
  expected_resource_version INT NOT NULL,
  preconditions JSONB NOT NULL,      -- geprüfte Preconditions (Snapshot)
  policy_version TEXT NOT NULL,
  context_hash TEXT NOT NULL,        -- Hash über Run-Status + Versionen
  expires_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE policy_decisions (
  action_id TEXT NOT NULL REFERENCES actions(action_id),
  decision TEXT NOT NULL CHECK (decision IN ('allow','deny','abstain')),
  policy_version TEXT NOT NULL,
  context_hash TEXT NOT NULL,
  decided_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (action_id, policy_version, context_hash)
);

Action-Lebenszyklus (Rev. 4, C2-fix): `action_transitions` protokolliert
jeden Action-Statuswechsel (proposed → … → committed); `state_transitions`
protokolliert **ausschliesslich** fachliche Ressourcenversionen
(nur `demo_update_record`, genau eine Zeile pro erfolgreichem CAS).
`actions.status` ist abgeleiteter Snapshot des letzten
`action_transitions`-Eintrags und wird in derselben Transaktion gesetzt.

CREATE TABLE action_transitions (
  seq BIGSERIAL PRIMARY KEY,
  action_id TEXT NOT NULL REFERENCES actions(action_id),
  old_status TEXT NOT NULL,
  new_status TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
-- Erlaubte Paare als CHECK (Spiegel von §3):
-- proposed→{validated,rejected}, validated→{authorized,denied,rejected},
-- authorized→executing, executing→{confirmed,failed,outcome_unknown},
-- outcome_unknown→{executing,quarantined}, confirmed→committed.

-- B2: mehrere Transitionen pro action_id (Lebenszyklus §3).
-- Fachlicher Ressourcen-Übergang nur für demo_update_record; für
-- demo_read keine Zeile hier (kein Ressourcen-Effect).
CREATE TABLE state_transitions (
  seq BIGSERIAL PRIMARY KEY,
  run_id TEXT NOT NULL REFERENCES runs(run_id),
  action_id TEXT NOT NULL REFERENCES actions(action_id),
  record_id TEXT NOT NULL REFERENCES records(record_id),
  old_version INT NOT NULL,
  new_version INT NOT NULL,
  CHECK (new_version = old_version + 1),
  UNIQUE (record_id, old_version)
);
CREATE INDEX ON state_transitions (action_id, seq);

CREATE TABLE outbox_events (
  event_id TEXT PRIMARY KEY,
  run_id TEXT NOT NULL REFERENCES runs(run_id),
  action_id TEXT REFERENCES actions(action_id),
  sequence BIGINT NOT NULL,
  event_type TEXT NOT NULL CHECK (event_type IN
    ('action_proposed','action_validated','action_rejected','policy_allowed',
     'policy_denied','execution_started','execution_confirmed',
     'execution_failed','execution_outcome_unknown','state_committed',
     'recovery_started','recovery_resolved','idempotency_conflict')),
  resource_version INT NOT NULL,
  payload_hash TEXT NOT NULL,
  previous_event_hash TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (run_id, sequence)
);

CREATE TABLE recovery_jobs (
  job_id TEXT PRIMARY KEY,
  run_id TEXT NOT NULL REFERENCES runs(run_id),
  action_id TEXT NOT NULL REFERENCES actions(action_id),
  kind TEXT NOT NULL CHECK (kind IN ('reconcile','quarantine')),
  status TEXT NOT NULL DEFAULT 'open'
    CHECK (status IN ('open','in_progress','resolved','escalated')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
```

Transaktionsregeln:
- Demo-Write: `UPDATE records SET … WHERE record_id=… AND version=expected`
  (CAS) + `actions.status='committed' + actions.result` + `state_transitions`
  + `outbox_events` in **einer** Transaktion. `rowcount=0` ⇒ Stale-Reject.
  Replay (gleicher Key, gleicher Payload, abgeschlossen) liest `actions.result`,
  führt keinen Effect aus.
- Event-Kette pro Run serialisiert (UNIQUE(run_id, sequence),
  Sequenzvergabe unter Run-Lock); Lücke/Duplikat ⇒ Writes stoppen, kein
  Neustart der Kette durch Überschreiben; Checkpoint ausserhalb des
  Event-Schreibers sichern.

## 5. OPA-Regeln (Rego v1, P0-fix)

Action→Permission-Mapping liegt **in der Policy**, nicht im Input:

```rego
package control.authz

import rego.v1

default allow := false

required_permission := "records.read" if {
	input.action == "demo_read"
}

required_permission := "records.write" if {
	input.action == "demo_update_record"
}

allow if {
	input.action == "demo_read"
	input.run.status == "active"
	required_permission in input.actor.permissions
	input.resource_version == input.expected_resource_version
	not input.expired
}

allow if {
	input.action == "demo_update_record"
	input.run.status == "active"
	required_permission in input.actor.permissions
	input.resource_version == input.expected_resource_version
	not input.expired
}
```

Gate stellt sicher: `input.actor/run/resource_version` aus vertrauenswürdigen
Quellen (Auth-Kontext, DB), nie aus LLM-Payload; `expired` aus
vertrauenswürdiger Zeit. `allow==true` + keine Invarianten-Verletzung ⇒
weiter, sonst Deny. OPA-Timeout ⇒ Deny (POLICY_UNAVAILABLE: alles blockiert).

## 6. Verpflichtende Negativtests (Abnahme)

PASS = kein unzulässiger Effect + Nachweis-Ereignis vorhanden.

1. Direktaufruf ohne Authorization Record ⇒ kein Effect.
2. Stale-Version (parallele CAS-Konkurrenz) ⇒ genau ein Gewinner, Rest Reject.
3. Args nach Freigabe geändert (Hash-Mismatch beim Reload) ⇒ Reject.
4. Doppelaufruf gleicher Key/gleicher Payload (parallel) ⇒ genau 1 Effect.
5. Gleicher Key/anderer Payload ⇒ hart ablehnen + `idempotency_conflict`.
6. OPA gestoppt/timeout ⇒ Deny, alles blockiert.
7. Absturz nach Effect vor Commit (nur für späteren externen Effect;
   für DB-Write per Transaktion nicht möglich) ⇒ `outcome_unknown` +
   Reconcile, kein Doppel-Effect.
8. Audit-Lücke/Duplikat/Manipulation ⇒ erkannt (`integrity.py verify`
   schlägt an, Writes stoppen).

## 7. Festlegungen vor Build (Review §3)

1. **Manual Approval:** aus v0.1 gestrichen → `quarantined` + `recovery_jobs`
   (`quarantine`). Keine Approval-Tabelle in v0.1.
2. **Hash-Kette:** pro Run serialisiert, Sequenz unter Lock, Checkpoint
   ausserhalb des Schreibers.
3. **Config-Schutz:** SHA-Pin fest im Deployment hinterlegt (nicht nur in
   veränderbarer `security.yaml`); signierte Config später.

## 8. Abnahme-Checkliste (Rev. 6, evidenzgebunden)

Jede PASS-Markierung verweist auf konkrete Tests; Status pro Invariante:
PASS / PARTIAL / OPEN. Nicht implementierter Schutz gilt als OPEN, nie als PASS.

- [x] **I1 Kein Bypass — PASS** (`test_worker.py`: Subprozess + eigene DSN,
  unbekannte Ops reject, Gate importiert `execution` nie per AST-Check).
  Grenze: OS-Prozessisolation angenommen, nicht bewiesen (kein Container-/Sandbox-Nachweis).
- [x] **I2 Deny-dominiert — PASS** (`test_policy_client.py` parametrisiert:
  false/null/str/violations/HTTP-500/JSON/Schema/unreachable; `test_gate.py` live).
- [x] **I3 Bindung — PASS** (`test_contracts.py`: jedes Feld einzeln manipuliert;
  `test_execution.py`: Tamper/Actor/Args-Mismatch; Guard-Reload in-Transaktion).
- [x] **I4 Atomar — PASS** (CAS-Gewinner-Test, Trigger C1–C5 Voll-Rollback,
  Race A4 ohne Transition).
- [x] **I5 Idempotenz — PASS** (parallel 1 Effect + Replay, Payload-Konflikt;
  Verlierer unterscheidet Replay/Konflikt).
- [x] **I6 Outcome unknown — PASS** (`lost_ack` → Replay deterministisch;
  `kill_mid_tx` echter Backend-Tod in offener Tx → genau 1 Retry;
  Kill-Test beidseitig; Reconcile liest Zustand neu ein).
- [x] **I7 Self-Bypass — PASS (eng definiert)** (Deny → Repeat mit `repeat_of`,
  geänderte Permission → Allow). Keine allgemeine semantische Garantie.
- [x] **I8 Keine manuelle Freigabe — PASS** (kein Approval-Parameter, keine
  Tabelle, kein Override-String; Quarantäne-Pfad getestet).
- [x] **Audit/Evidence — PASS** (Writer-Idempotenz/Konkurrenz, Tamper/Löschung/
  Abschneiden erkannt, Checkpoint-Rolle getrennt, Verifier schreibt nie).
- [x] **Rollen — PASS** (volle Tabellen-Matrix + Sequenz-Minimalmatrix per 004,
  echte Verbindungen, PUBLIC-frei, Owner-Trennung).
- [x] **Scope — PASS** (`demo_read` + `demo_update_record` beide ausführbar,
  Rev.-5-Semantik; Widerspruch Result-CHECK als Spec-Änderung D1 dokumentiert,
  nicht als Testkorrektur).
