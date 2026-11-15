-- 001_schema: Tabellen (Rev. 4 §4). Läuft als stack_owner.
CREATE TABLE IF NOT EXISTS runs (
  run_id TEXT PRIMARY KEY,
  owner TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'active'
    CHECK (status IN ('active','completed','aborted','quarantined')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS records (
  record_id TEXT PRIMARY KEY,
  status TEXT NOT NULL DEFAULT 'pending'
    CHECK (status IN ('pending','approved','rejected')),
  version INT NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS actions (
  action_id TEXT PRIMARY KEY,
  run_id TEXT NOT NULL REFERENCES runs(run_id),
  action TEXT NOT NULL CHECK (action IN ('demo_read','demo_update_record')),
  target TEXT NOT NULL,
  args_hash TEXT NOT NULL,
  idempotency_key TEXT NOT NULL UNIQUE,
  idempotency_payload_hash TEXT NOT NULL,
  status TEXT NOT NULL
    CHECK (status IN ('proposed','validated','authorized','executing',
                      'confirmed','failed','outcome_unknown',
                      'committed','quarantined','rejected','denied')),
  expected_resource_version INT NOT NULL,
  result JSONB NULL,
  result_written_at TIMESTAMPTZ NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  CHECK ((status NOT IN ('confirmed','committed') OR result IS NOT NULL))
);

CREATE TABLE IF NOT EXISTS authorization_records (
  action_id TEXT PRIMARY KEY REFERENCES actions(action_id),
  canonical_hash TEXT NOT NULL,
  action TEXT NOT NULL,
  target TEXT NOT NULL,
  args_hash TEXT NOT NULL,
  actor_id TEXT NOT NULL,
  permissions TEXT[] NOT NULL,
  expected_resource_version INT NOT NULL,
  preconditions JSONB NOT NULL,
  policy_version TEXT NOT NULL,
  context_hash TEXT NOT NULL,
  expires_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS policy_decisions (
  action_id TEXT NOT NULL REFERENCES actions(action_id),
  decision TEXT NOT NULL CHECK (decision IN ('allow','deny','abstain')),
  policy_version TEXT NOT NULL,
  context_hash TEXT NOT NULL,
  decided_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (action_id, policy_version, context_hash)
);

CREATE TABLE IF NOT EXISTS action_transitions (
  seq BIGSERIAL PRIMARY KEY,
  action_id TEXT NOT NULL REFERENCES actions(action_id),
  old_status TEXT NOT NULL,
  new_status TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS state_transitions (
  seq BIGSERIAL PRIMARY KEY,
  run_id TEXT NOT NULL REFERENCES runs(run_id),
  action_id TEXT NOT NULL REFERENCES actions(action_id),
  record_id TEXT NOT NULL REFERENCES records(record_id),
  old_version INT NOT NULL,
  new_version INT NOT NULL,
  CHECK (new_version = old_version + 1),
  UNIQUE (record_id, old_version)
);
CREATE INDEX IF NOT EXISTS ix_state_transitions_action ON state_transitions (action_id, seq);

CREATE TABLE IF NOT EXISTS outbox_events (
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

CREATE TABLE IF NOT EXISTS recovery_jobs (
  job_id TEXT PRIMARY KEY,
  run_id TEXT NOT NULL REFERENCES runs(run_id),
  action_id TEXT NOT NULL REFERENCES actions(action_id),
  kind TEXT NOT NULL CHECK (kind IN ('reconcile','quarantine')),
  status TEXT NOT NULL DEFAULT 'open'
    CHECK (status IN ('open','in_progress','resolved','escalated')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
