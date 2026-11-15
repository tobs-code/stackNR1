-- 011_evidence_chain: F5/F6/F8 — serverseitige Kette, Konflikt-Evidenz, Anker.
-- Läuft als Owner-Admin (Superuser). Idempotent (IF EXISTS / IF NOT EXISTS).
--
--   F5: Sequenz und Vorgängerzeiger vergibt die DB unter Run-Lock. Der Aufrufer
--       kann beides nicht mehr beeinflussen (kein Parameter, keine IPC-Felder).
--   F6: Ein Idempotenzkonflikt schreibt genau ein `idempotency_conflict`-Ereignis
--       (dedupliziert je action_id + payload_hash), bevor die Tx ohne Effekt endet.
--   F8: evidence_checkpoints ist append-only und abstammungsgeprüft; nur
--       fn_write_checkpoint schreibt, und ein neuer Head muss Nachfahre des
--       vorherigen Checkpoints sein.
--
-- Upgrade-Hinweis: `previous_event_hash` war ein ungeprüfter Aufrufer-Wert und
-- wird durch `prev_event_id` ersetzt. Vorhandene Zeilen werden aus der
-- Sequenzreihenfolge nachgezogen; Lücken bleiben als NULL sichtbar (der
-- Verifier meldet sie), es wird nichts stillschweigend "repariert".

-- 1. Outbox: Vorgängerzeiger statt Aufrufer-Hash --------------------------
ALTER TABLE outbox_events ADD COLUMN IF NOT EXISTS prev_event_id TEXT
  REFERENCES outbox_events(event_id);

UPDATE outbox_events o
   SET prev_event_id = (
         SELECT p.event_id FROM outbox_events p
          WHERE p.run_id = o.run_id AND p.sequence = o.sequence - 1)
 WHERE o.prev_event_id IS NULL AND o.sequence > 1;

ALTER TABLE outbox_events DROP COLUMN IF EXISTS previous_event_hash;

-- 2. Checkpoints: append-only, mehrere Zeilen je Run ----------------------
DO $$
DECLARE v_pk text;
BEGIN
  SELECT conname INTO v_pk FROM pg_constraint
   WHERE conrelid = 'evidence_checkpoints'::regclass AND contype = 'p'
     AND pg_get_constraintdef(oid) NOT LIKE '%(checkpoint_id)%';
  IF v_pk IS NOT NULL THEN
    EXECUTE format('ALTER TABLE evidence_checkpoints DROP CONSTRAINT %I', v_pk);
  END IF;
END $$;

ALTER TABLE evidence_checkpoints
  ADD COLUMN IF NOT EXISTS checkpoint_id BIGSERIAL;
CREATE INDEX IF NOT EXISTS evidence_checkpoints_run_idx
  ON evidence_checkpoints (run_id, checkpoint_id);

-- Primärschlüssel explizit sicherstellen (ADD COLUMN IF NOT EXISTS überspringt
-- die Constraint-Anlage, wenn die Spalte schon existiert).
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint
                  WHERE conrelid = 'evidence_checkpoints'::regclass
                    AND contype = 'p') THEN
    ALTER TABLE evidence_checkpoints ADD PRIMARY KEY (checkpoint_id);
  END IF;
END $$;

-- Runtime-Rollen schreiben Checkpoints ausschliesslich über fn_write_checkpoint.
REVOKE INSERT, UPDATE, DELETE ON evidence_checkpoints
  FROM stack_recovery, stack_worker, stack_gate;
GRANT SELECT ON evidence_checkpoints TO stack_recovery, stack_worker;

-- 3. Serverseitige Sequenz- und Zeigervergabe (intern) --------------------
CREATE OR REPLACE FUNCTION fn_outbox_append(
  p_event_id text, p_run_id text, p_action_id text, p_event_type text,
  p_resource_version int, p_payload_hash text
) RETURNS bigint
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public
AS $$
DECLARE
  v_status text;
  v_sequence bigint;
  v_prev text;
  v_existing text;
BEGIN
  -- Serialisiert die Vergabe pro Run. Im normalen Ausführungspfad ist die
  -- runs-Zeile bereits durch fn_execute_write gesperrt (No-op).
  SELECT status INTO v_status FROM runs WHERE run_id = p_run_id FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'auth_missing: run % fehlt', p_run_id;
  END IF;

  -- Dedupe für Konflikt-Evidenz: gleicher Konflikt wird nicht doppelt verbucht.
  IF p_event_type = 'idempotency_conflict' THEN
    SELECT event_id INTO v_existing FROM outbox_events
     WHERE run_id = p_run_id AND action_id = p_action_id
       AND event_type = 'idempotency_conflict'
       AND payload_hash = p_payload_hash
     LIMIT 1;
    IF FOUND THEN
      SELECT sequence INTO v_sequence FROM outbox_events WHERE event_id = v_existing;
      RETURN v_sequence;
    END IF;
  END IF;

  SELECT COALESCE(MAX(sequence), 0) + 1 INTO v_sequence
    FROM outbox_events WHERE run_id = p_run_id;
  SELECT event_id INTO v_prev FROM outbox_events
   WHERE run_id = p_run_id ORDER BY sequence DESC LIMIT 1;

  INSERT INTO outbox_events (event_id, run_id, action_id, sequence, event_type,
    resource_version, payload_hash, prev_event_id)
  VALUES (p_event_id, p_run_id, p_action_id, v_sequence, p_event_type,
    p_resource_version, p_payload_hash, v_prev);
  RETURN v_sequence;
END; $$;
ALTER FUNCTION fn_outbox_append(text, text, text, text, int, text) OWNER TO stack_owner;
REVOKE ALL ON FUNCTION fn_outbox_append(text, text, text, text, int, text) FROM PUBLIC;

-- 4. Geschützter Demo-Write ohne Sequenz-/Hash-Parameter ------------------
DROP FUNCTION IF EXISTS fn_execute_write(
  text, text, text, text, int, text, text, text, bigint, text, text, text);

CREATE OR REPLACE FUNCTION fn_execute_write(
  p_action_id text, p_run_id text, p_record_id text, p_new_status text,
  p_expected_version int, p_idempotency_key text, p_payload_hash text,
  p_event_id text, p_guard_actor text, p_test_hook text
) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public
AS $$
DECLARE
  v_act actions%ROWTYPE;
  v_auth authorization_records%ROWTYPE;
  v_run_status text;
  v_found_version int;
  v_new_version int;
  v_result jsonb;
  v_conflict_event text;
BEGIN
  SELECT * INTO v_act FROM actions WHERE action_id = p_action_id FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'auth_missing: keine Action %', p_action_id;
  END IF;
  IF v_act.action <> 'demo_update_record' THEN
    RAISE EXCEPTION 'auth_mismatch: Action % nicht ausfuehrbar', v_act.action;
  END IF;
  -- F3/F10: Quarantäne ist eine Sperre, kein Replay. Vor jedem anderen Pfad.
  IF v_act.status = 'quarantined' THEN
    RAISE EXCEPTION 'lifecycle_reject: Action % ist quarantined', p_action_id;
  END IF;
  SELECT * INTO v_auth FROM authorization_records WHERE action_id = p_action_id;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'auth_missing: kein Authorization Record %', p_action_id;
  END IF;
  IF clock_timestamp() > v_auth.expires_at THEN
    RAISE EXCEPTION 'auth_expired: Record % abgelaufen', p_action_id;
  END IF;
  IF v_auth.actor_id <> p_guard_actor THEN
    RAISE EXCEPTION 'auth_mismatch: actor weicht ab';
  END IF;
  IF v_auth.action <> v_act.action OR v_auth.target <> v_act.target
     OR v_auth.args_hash <> v_act.args_hash
     OR v_auth.expected_resource_version <> v_act.expected_resource_version THEN
    RAISE EXCEPTION 'auth_mismatch: Record weicht von Action-Zeile ab';
  END IF;
  -- F1: genau ein kanonisches Ziel — Schreibziel muss dem autorisierten Ziel entsprechen.
  IF p_record_id <> v_auth.target THEN
    RAISE EXCEPTION 'auth_mismatch: Ziel % weicht vom autorisierten Ziel % ab',
      p_record_id, v_auth.target;
  END IF;
  IF v_act.idempotency_key <> p_idempotency_key THEN
    RAISE EXCEPTION 'auth_mismatch: idempotency_key weicht ab';
  END IF;
  -- F6: gleicher Key, anderer Payload. Die Evidenz entsteht VOR jedem Effekt,
  -- als Rückgabewert statt als Exception — ein RAISE würde sie mitrollbacken.
  IF v_act.idempotency_payload_hash <> p_payload_hash THEN
    v_conflict_event := gen_random_uuid()::text;
    PERFORM fn_outbox_append(v_conflict_event, v_act.run_id, p_action_id,
                             'idempotency_conflict', v_act.expected_resource_version,
                             p_payload_hash);
    RETURN jsonb_build_object('conflict', 'idempotency_conflict',
                              'event_id', v_conflict_event);
  END IF;
  IF v_auth.args_hash <> p_payload_hash THEN
    RAISE EXCEPTION 'auth_mismatch: Payload weicht vom Record ab';
  END IF;
  IF v_act.result IS NOT NULL THEN
    RETURN jsonb_build_object('replay', v_act.result);
  END IF;
  -- Nur autorisierte bzw. nach Reconcile erneut freigegebene Actions starten.
  IF v_act.status NOT IN ('authorized', 'outcome_unknown') THEN
    RAISE EXCEPTION 'lifecycle_reject: Action % ist %', p_action_id, v_act.status;
  END IF;
  IF v_auth.expected_resource_version <> p_expected_version THEN
    RAISE EXCEPTION 'auth_mismatch: erwartete Version weicht vom Record ab';
  END IF;
  -- F2: Run-Status in derselben Transaktion geprüft, Zeile bis Commit gesperrt.
  SELECT status INTO v_run_status FROM runs WHERE run_id = v_act.run_id FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'auth_missing: run % fehlt', v_act.run_id;
  END IF;
  IF v_run_status <> 'active' THEN
    RAISE EXCEPTION 'run_inactive: run % ist %', v_act.run_id, v_run_status;
  END IF;
  UPDATE records SET status = p_new_status, version = version + 1
   WHERE record_id = p_record_id AND version = p_expected_version
   RETURNING version INTO v_new_version;
  IF NOT FOUND THEN
    SELECT version INTO v_found_version FROM records WHERE record_id = p_record_id;
    IF NOT FOUND THEN
      RAISE EXCEPTION 'stale_version|%|%|missing', p_record_id, p_expected_version;
    ELSE
      RAISE EXCEPTION 'stale_version|%|%|found=%', p_record_id, p_expected_version, v_found_version;
    END IF;
  END IF;
  -- TEST-ONLY Hook (D4): echter Backend-Tod in offener Tx. Nicht via IPC erreichbar.
  IF p_test_hook = 'kill_mid_tx' THEN
    PERFORM fn_test_kill_self();
    RAISE EXCEPTION 'unreachable: backend survived';
  END IF;
  v_result := jsonb_build_object('record_id', p_record_id, 'old_version', p_expected_version,
                                 'new_version', v_new_version, 'status', p_new_status);
  UPDATE actions SET status = 'committed', result = v_result, result_written_at = now()
   WHERE action_id = p_action_id;
  -- Startkante ist der tatsächliche Ist-Status (authorized oder outcome_unknown).
  INSERT INTO action_transitions (action_id, old_status, new_status) VALUES
    (p_action_id, v_act.status, 'executing'),
    (p_action_id, 'executing', 'confirmed'),
    (p_action_id, 'confirmed', 'committed');
  INSERT INTO state_transitions (run_id, action_id, record_id, old_version, new_version)
    VALUES (v_act.run_id, p_action_id, p_record_id, p_expected_version, v_new_version);
  -- F5: Sequenz und Vorgängerzeiger vergibt die DB, nicht der Aufrufer.
  PERFORM fn_outbox_append(p_event_id, v_act.run_id, p_action_id, 'state_committed',
                           v_new_version, p_payload_hash);
  RETURN v_result;
END;
$$;
ALTER FUNCTION fn_execute_write(text, text, text, text, int, text, text, text, text, text)
  OWNER TO stack_owner;
REVOKE ALL ON FUNCTION fn_execute_write(text, text, text, text, int, text, text, text, text, text)
  FROM PUBLIC;
GRANT EXECUTE ON FUNCTION fn_execute_write(text, text, text, text, int, text, text, text, text, text)
  TO stack_worker;

-- 5. Checkpoint-Schreiber mit Abstammungsprüfung (F8) ---------------------
CREATE OR REPLACE FUNCTION fn_write_checkpoint(p_run_id text, p_head_hash text)
RETURNS text
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public
AS $$
DECLARE
  v_genesis text := 'GENESIS:' || repeat('0', 56);
  v_previous text;
  v_hash text := p_head_hash;
  v_prev text;
  v_steps int := 0;
  v_max_steps int;
BEGIN
  SELECT head_hash INTO v_previous FROM evidence_checkpoints
   WHERE run_id = p_run_id ORDER BY checkpoint_id DESC LIMIT 1;

  IF v_previous IS NULL THEN
    -- Erster Anker: entweder ein realer Ledger-Head oder GENESIS bei einem
    -- Run ohne Events (Read-only-Run). Ein leeres Ankerbild ist damit prüfbar.
    IF p_head_hash = v_genesis
       AND NOT EXISTS (SELECT 1 FROM evidence_ledger WHERE run_id = p_run_id) THEN
      INSERT INTO evidence_checkpoints (run_id, head_hash) VALUES (p_run_id, p_head_hash);
      RETURN p_head_hash;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM evidence_ledger
                    WHERE run_id = p_run_id AND event_hash = p_head_hash) THEN
      RAISE EXCEPTION 'checkpoint_unknown_head: % nicht im Ledger von %',
        p_head_hash, p_run_id;
    END IF;
    INSERT INTO evidence_checkpoints (run_id, head_hash) VALUES (p_run_id, p_head_hash);
    RETURN p_head_hash;
  END IF;

  -- Der Head muss ein realer Ledger-Eintrag dieses Runs sein.
  PERFORM 1 FROM evidence_ledger WHERE run_id = p_run_id AND event_hash = p_head_hash;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'checkpoint_unknown_head: % nicht im Ledger von %', p_head_hash, p_run_id;
  END IF;

  -- Kein Fortschritt: idempotenter Wiederholungsaufruf, keine neue Zeile.
  IF v_previous = p_head_hash THEN
    RETURN p_head_hash;
  END IF;

  -- Abstammung: vom neuen Head rückwärts bis zum vorherigen Checkpoint.
  SELECT COUNT(*) INTO v_max_steps FROM evidence_ledger WHERE run_id = p_run_id;
  WHILE v_steps <= v_max_steps LOOP
    SELECT prev_hash INTO v_prev FROM evidence_ledger
     WHERE run_id = p_run_id AND event_hash = v_hash;
    IF NOT FOUND THEN
      RAISE EXCEPTION 'checkpoint_unknown_head: Kette bricht bei %', v_hash;
    END IF;
    IF v_prev = v_previous THEN
      INSERT INTO evidence_checkpoints (run_id, head_hash) VALUES (p_run_id, p_head_hash);
      RETURN p_head_hash;
    END IF;
    IF v_prev = v_genesis OR v_prev = v_hash THEN
      EXIT;
    END IF;
    v_hash := v_prev;
    v_steps := v_steps + 1;
  END LOOP;

  -- Kein Pfad zum vorherigen Anker: Abschneiden oder fremde Kette.
  RAISE EXCEPTION 'checkpoint_regression: % ist kein Nachfahre von %',
    p_head_hash, v_previous;
END; $$;
ALTER FUNCTION fn_write_checkpoint(text, text) OWNER TO stack_owner;
REVOKE ALL ON FUNCTION fn_write_checkpoint(text, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION fn_write_checkpoint(text, text) TO stack_recovery;
