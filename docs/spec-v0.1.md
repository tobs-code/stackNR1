# Safety Stack v0.1 Spezifikation (prüfbare Bauanleitung) — Rev. 3

Abgeleitet aus `read.me`, überarbeitet nach Reviews.
Rev. 3 fixt drei Blocker aus dem Spec-vs-Repo-Review:
(B1) Ergebnis-Speicherung für Idempotency-Replay,
(B2) mehrere Transitionen pro Action,
(B3) vollständiger rekonstruierbarer Authorization Record.
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
- **I3 Bindung (P0-fix):** Freigabe = unveränderlicher Authorization Record
  mit kanonischem Hash über: canon(action+args, JCS) + Typen + actor_id +
  permissions + target + betroffene Ressourcen-Versionen + preconditions +
  policy_version + action_id + expiry (vertrauenswürdige Zeit). Hash allein
  authentifiziert nichts — Record wird   vor dem Effect. Kanonisches Feldset (JCS, Schlüssel sortiert):
  `{action, target, args, actor_id, permissions (sortiert), target,
  expected_resource_version, preconditions, policy_version, context,
  action_id, expires_at}` — exakt die in `authorization_records` (+`actions`)
  persistierten Werte; der Worker lädt Record + Action-Zeile und vergleicht
  Feld für Feld plus Hash.
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

## 8. Abnahme-Checkliste

- [ ] Kein Effect ohne Gate (Umgehungspfade blockiert)
- [ ] Policy-Ausfall blockiert (Deny/Timeout/Fehler ⇒ kein Effect)
- [ ] Freigabe unveränderlich gebunden (Record-Reload vor Effect)
- [ ] State-Übergänge atomar (CAS, kein TOCTOU)
- [ ] Idempotenz bei Parallelität (höchstens 1 Effect; Konflikt erkannt)
- [ ] Crash-Recovery korrekt (Reconcile statt Blind-Retry)
- [ ] Audit überprüfbar (Lücke/Duplikat/Manipulation erkannt)
- [ ] Keine manuelle Freigabe möglich (quarantined statt Override)
