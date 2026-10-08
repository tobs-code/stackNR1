-- 003_evidence: Ledger + Checkpoints (Rev. 4 §4). Läuft als Owner-Admin.
CREATE TABLE IF NOT EXISTS evidence_ledger (
  event_id TEXT PRIMARY KEY REFERENCES outbox_events(event_id),
  run_id TEXT NOT NULL REFERENCES runs(run_id),
  sequence BIGINT NOT NULL,
  event_hash TEXT NOT NULL,
  prev_hash TEXT NOT NULL,
  processed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (run_id, sequence)
);

-- Checkpoint: ausserhalb des Writers geschrieben (unabhängiger Prozess/Rolle).
CREATE TABLE IF NOT EXISTS evidence_checkpoints (
  run_id TEXT PRIMARY KEY REFERENCES runs(run_id),
  head_hash TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

DO $$
DECLARE r RECORD;
BEGIN
  FOR r IN SELECT tablename FROM pg_tables WHERE schemaname='public'
           AND tablename IN ('evidence_ledger','evidence_checkpoints')
           AND tableowner <> 'stack_owner' LOOP
    EXECUTE format('ALTER TABLE public.%I OWNER TO stack_owner', r.tablename);
  END LOOP;
END $$;

REVOKE ALL ON evidence_ledger, evidence_checkpoints FROM PUBLIC;
-- Writer (Worker-Rolle): Ledger schreiben+lesen, keine Checkpoints.
GRANT SELECT, INSERT ON evidence_ledger TO stack_worker;
-- Checkpoint-Schreiber (Recovery-Rolle, getrennt vom Writer): nur Checkpoints.
GRANT SELECT, INSERT, UPDATE ON evidence_checkpoints TO stack_recovery;
GRANT SELECT ON evidence_checkpoints TO stack_worker;
GRANT SELECT ON evidence_ledger TO stack_recovery, stack_gate;
