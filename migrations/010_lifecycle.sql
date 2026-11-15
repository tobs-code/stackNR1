-- 010_lifecycle: F3/F10 — legaler Lifecycle, DB-erzwungene Historie.
-- Läuft als Owner-Admin (Superuser). Idempotent (OR REPLACE / IF EXISTS).
--
-- Durchsetzung in drei Schichten:
--   1. Pair-CHECK auf action_transitions (Spiegel von Spec Rev. 7 §3).
--   2. Deferred Konsistenz-Trigger: actions.status = new_status der letzten
--      Transition (bzw. 'proposed' ohne Transition), geprüft am Tx-Ende.
--   3. Statuswechsel nur über SECURITY-DEFINER-Funktionen; Runtime-Rollen
--      haben kein direktes INSERT/UPDATE mehr auf actions/action_transitions.
--
-- Upgrade-Hinweis: Altzeilen (z. B. proposed→proposed aus dem alten
-- Repository-Pfad) können den CHECK verletzen. Der CHECK wird deshalb
-- NOT VALID angelegt und nur bei fehlerfreier Prüfung validiert; für NEUE
-- Zeilen gilt er immer. Reparatur von Altzeilen ist bewusst kein stiller
-- Delete und bleibt ein dokumentierter, manueller Schritt.

-- 1. Rechte: Statuswechsel nur noch über Funktionen -----------------------
REVOKE INSERT, UPDATE, DELETE ON actions FROM stack_gate, stack_worker, stack_recovery;
GRANT SELECT ON actions TO stack_gate, stack_worker, stack_recovery;
-- Gate legt Actions an (Insert-Guard: nur 'proposed'), alles Weitere per Funktion.
GRANT INSERT ON actions TO stack_gate;

REVOKE INSERT, UPDATE, DELETE ON action_transitions
  FROM stack_gate, stack_worker, stack_recovery;
GRANT SELECT ON action_transitions TO stack_gate, stack_worker, stack_recovery;

-- Keine Runtime-Rolle schreibt noch direkt in BIGSERIAL-Tabellen; die
-- Transition-Sequenz wird ausschliesslich im Owner-Kontext der Funktionen genutzt.
REVOKE USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public
  FROM stack_gate, stack_worker, stack_recovery;
ALTER DEFAULT PRIVILEGES FOR ROLE stack_owner IN SCHEMA public
  REVOKE ALL ON SEQUENCES FROM stack_gate, stack_worker, stack_recovery;

-- 2. Insert-Guard verschärfen: nur 'proposed' ist ein legaler Startzustand.
-- (authorized/denied entstehen jetzt ausschliesslich über fn_gate_transition.)
CREATE OR REPLACE FUNCTION trg_actions_insert_guard()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.status <> 'proposed' THEN
    RAISE EXCEPTION 'actions: direkter INSERT mit Status % verboten (nur proposed)', NEW.status;
  END IF;
  RETURN NEW;
END; $$;
ALTER FUNCTION trg_actions_insert_guard() OWNER TO stack_owner;

-- 3. Pair-CHECK (Spiegel von §3, Rev. 7) ---------------------------------
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
     WHERE conname = 'action_transitions_pair_check'
       AND conrelid = 'action_transitions'::regclass
  ) THEN
    ALTER TABLE action_transitions
      ADD CONSTRAINT action_transitions_pair_check
      CHECK ((old_status, new_status) IN (
        ('proposed',        'validated'),
        ('proposed',        'rejected'),
        ('validated',       'authorized'),
        ('validated',       'denied'),
        ('validated',       'rejected'),
        ('authorized',      'executing'),
        ('authorized',      'outcome_unknown'),
        ('authorized',      'quarantined'),
        ('executing',       'confirmed'),
        ('executing',       'failed'),
        ('executing',       'outcome_unknown'),
        ('executing',       'quarantined'),
        ('outcome_unknown', 'executing'),
        ('outcome_unknown', 'quarantined'),
        ('confirmed',       'committed'),
        ('committed',       'quarantined')
      )) NOT VALID;
  END IF;
END $$;

DO $$
BEGIN
  ALTER TABLE action_transitions VALIDATE CONSTRAINT action_transitions_pair_check;
EXCEPTION WHEN check_violation THEN
  RAISE NOTICE 'action_transitions_pair_check: Altzeilen verletzen den CHECK; Constraint bleibt NOT VALID (neue Zeilen werden geprüft).';
END $$;

-- 4. Deferred Konsistenz-Trigger -----------------------------------------
-- Prüft am Transaktionsende, dass der Snapshot actions.status exakt dem
-- letzten Historieneintrag entspricht. Deferred, damit Zwischenstände
-- innerhalb einer Transaktion erlaubt sind.
CREATE OR REPLACE FUNCTION trg_action_lifecycle_consistent()
RETURNS trigger LANGUAGE plpgsql SET search_path = public AS $$
DECLARE
  v_status text;
  v_last text;
BEGIN
  IF TG_TABLE_NAME = 'actions' AND TG_OP = 'UPDATE' THEN
    IF NEW.status IS NOT DISTINCT FROM OLD.status THEN
      RETURN NULL;  -- reine Feld-/Result-Änderung: Lifecycle unberührt
    END IF;
  END IF;

  SELECT status INTO v_status FROM actions WHERE action_id = NEW.action_id;
  IF NOT FOUND THEN
    RETURN NULL;  -- Zeile wurde in derselben Tx gelöscht
  END IF;

  SELECT new_status INTO v_last
    FROM action_transitions
   WHERE action_id = NEW.action_id
   ORDER BY seq DESC
   LIMIT 1;

  IF NOT FOUND THEN
    IF v_status <> 'proposed' THEN
      RAISE EXCEPTION 'lifecycle_divergence: Action % hat Status % ohne Transition',
        NEW.action_id, v_status;
    END IF;
    RETURN NULL;
  END IF;

  IF v_status <> v_last THEN
    RAISE EXCEPTION 'lifecycle_divergence: Action % Status % <> letzte Transition %',
      NEW.action_id, v_status, v_last;
  END IF;
  RETURN NULL;
END; $$;
ALTER FUNCTION trg_action_lifecycle_consistent() OWNER TO stack_owner;

DROP TRIGGER IF EXISTS actions_lifecycle_consistent ON actions;
CREATE CONSTRAINT TRIGGER actions_lifecycle_consistent
  AFTER INSERT OR UPDATE ON actions
  DEFERRABLE INITIALLY DEFERRED
  FOR EACH ROW EXECUTE FUNCTION trg_action_lifecycle_consistent();

DROP TRIGGER IF EXISTS action_transitions_lifecycle_consistent ON action_transitions;
CREATE CONSTRAINT TRIGGER action_transitions_lifecycle_consistent
  AFTER INSERT OR UPDATE ON action_transitions
  DEFERRABLE INITIALLY DEFERRED
  FOR EACH ROW EXECUTE FUNCTION trg_action_lifecycle_consistent();

-- 5. Interne Übergangsfunktion (nicht an Runtime-Rollen vergeben) ---------
-- Lockt die Action-Zeile, prüft den erwarteten Ist-Status und schreibt
-- Transition + Snapshot atomar. Die Paarprüfung erfolgt zusätzlich über den
-- CHECK aus Schritt 3 (Verteidigung in der Tiefe).
CREATE OR REPLACE FUNCTION fn_apply_transition(
  p_action_id text, p_expected_old text, p_new text
) RETURNS text
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public
AS $$
DECLARE
  v_status text;
BEGIN
  SELECT status INTO v_status FROM actions WHERE action_id = p_action_id FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'lifecycle_missing: Action % unbekannt', p_action_id;
  END IF;
  IF v_status <> p_expected_old THEN
    RAISE EXCEPTION 'lifecycle_conflict: Action % ist %, erwartet %',
      p_action_id, v_status, p_expected_old;
  END IF;

  INSERT INTO action_transitions (action_id, old_status, new_status)
    VALUES (p_action_id, p_expected_old, p_new);
  UPDATE actions SET status = p_new WHERE action_id = p_action_id;
  RETURN p_new;
END; $$;
ALTER FUNCTION fn_apply_transition(text, text, text) OWNER TO stack_owner;
REVOKE ALL ON FUNCTION fn_apply_transition(text, text, text) FROM PUBLIC;

-- 6. Rollen-spezifische Wrapper ------------------------------------------
-- Gate darf ausschliesslich die Validierungs-/Entscheidungskanten fahren.
CREATE OR REPLACE FUNCTION fn_gate_transition(p_action_id text, p_new text)
RETURNS text
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public
AS $$
DECLARE
  v_status text;
BEGIN
  SELECT status INTO v_status FROM actions WHERE action_id = p_action_id FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'lifecycle_missing: Action % unbekannt', p_action_id;
  END IF;
  IF NOT (
       (v_status = 'proposed'  AND p_new IN ('validated', 'rejected'))
    OR (v_status = 'validated' AND p_new IN ('authorized', 'denied', 'rejected'))
  ) THEN
    RAISE EXCEPTION 'lifecycle_forbidden: Gate darf % -> % nicht', v_status, p_new;
  END IF;
  RETURN fn_apply_transition(p_action_id, v_status, p_new);
END; $$;
ALTER FUNCTION fn_gate_transition(text, text) OWNER TO stack_owner;
REVOKE ALL ON FUNCTION fn_gate_transition(text, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION fn_gate_transition(text, text) TO stack_gate;

-- Recovery darf ausschliesslich Reconcile-/Quarantäne-Kanten fahren.
CREATE OR REPLACE FUNCTION fn_recovery_transition(p_action_id text, p_new text)
RETURNS text
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public
AS $$
DECLARE
  v_status text;
BEGIN
  SELECT status INTO v_status FROM actions WHERE action_id = p_action_id FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'lifecycle_missing: Action % unbekannt', p_action_id;
  END IF;
  IF NOT (
       (v_status = 'authorized'      AND p_new IN ('outcome_unknown', 'quarantined'))
    OR (v_status = 'executing'       AND p_new IN ('outcome_unknown', 'quarantined'))
    OR (v_status = 'outcome_unknown' AND p_new = 'quarantined')
    OR (v_status = 'committed'       AND p_new = 'quarantined')
  ) THEN
    RAISE EXCEPTION 'lifecycle_forbidden: Recovery darf % -> % nicht', v_status, p_new;
  END IF;
  RETURN fn_apply_transition(p_action_id, v_status, p_new);
END; $$;
ALTER FUNCTION fn_recovery_transition(text, text) OWNER TO stack_owner;
REVOKE ALL ON FUNCTION fn_recovery_transition(text, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION fn_recovery_transition(text, text) TO stack_recovery;

-- 7. Geschützter Demo-Write: Lifecycle-Guard + dynamische Startkante -----
CREATE OR REPLACE FUNCTION fn_execute_write(
  p_action_id text, p_run_id text, p_record_id text, p_new_status text,
  p_expected_version int, p_idempotency_key text, p_payload_hash text,
  p_event_id text, p_run_sequence bigint, p_prev_event_hash text,
  p_guard_actor text, p_test_hook text
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
  IF v_act.idempotency_payload_hash <> p_payload_hash THEN
    RAISE EXCEPTION 'idempotency_conflict: key % anderer Payload', p_idempotency_key;
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
  INSERT INTO outbox_events (event_id, run_id, action_id, sequence, event_type,
    resource_version, payload_hash, previous_event_hash)
    VALUES (p_event_id, v_act.run_id, p_action_id, p_run_sequence, 'state_committed',
      v_new_version, p_payload_hash, p_prev_event_hash);
  RETURN v_result;
END;
$$;
ALTER FUNCTION fn_execute_write(text, text, text, text, int, text, text, text, bigint, text, text, text)
  OWNER TO stack_owner;
REVOKE ALL ON FUNCTION fn_execute_write(text, text, text, text, int, text, text, text, bigint, text, text, text)
  FROM PUBLIC;
GRANT EXECUTE ON FUNCTION fn_execute_write(text, text, text, text, int, text, text, text, bigint, text, text, text)
  TO stack_worker;

-- 8. Geschützter Demo-Read: Lifecycle-Guard + idempotenter Replay ---------
CREATE OR REPLACE FUNCTION fn_execute_read(
  p_action_id text, p_guard_actor text, p_payload_hash text
) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public
AS $$
DECLARE
  v_act actions%ROWTYPE;
  v_auth authorization_records%ROWTYPE;
  v_run_status text;
  v_rec records%ROWTYPE;
  v_result jsonb;
BEGIN
  SELECT * INTO v_act FROM actions WHERE action_id = p_action_id FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'auth_missing: keine Action %', p_action_id;
  END IF;
  IF v_act.action <> 'demo_read' THEN
    RAISE EXCEPTION 'auth_mismatch: keine lesbare Action %', p_action_id;
  END IF;
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
  IF v_act.idempotency_key <> (v_act.run_id || ':' || p_action_id)
     OR v_auth.args_hash <> p_payload_hash THEN
    RAISE EXCEPTION 'auth_mismatch: Payload weicht vom Record ab';
  END IF;
  -- Read ist effect-frei und terminal bei confirmed: Wiederholung liefert das
  -- persistierte Ergebnis, ohne erneut zu lesen oder Historie zu duplizieren.
  IF v_act.result IS NOT NULL THEN
    RETURN v_act.result;
  END IF;
  IF v_act.status <> 'authorized' THEN
    RAISE EXCEPTION 'lifecycle_reject: Action % ist %', p_action_id, v_act.status;
  END IF;
  SELECT status INTO v_run_status FROM runs WHERE run_id = v_act.run_id FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'auth_missing: run % fehlt', v_act.run_id;
  END IF;
  IF v_run_status <> 'active' THEN
    RAISE EXCEPTION 'run_inactive: run % ist %', v_act.run_id, v_run_status;
  END IF;
  SELECT * INTO v_rec FROM records WHERE record_id = v_auth.target;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'stale_version|%|-1|missing', v_auth.target;
  END IF;
  v_result := jsonb_build_object('record_id', v_rec.record_id, 'status', v_rec.status,
                                 'version', v_rec.version);
  UPDATE actions SET status = 'confirmed', result = v_result, result_written_at = now()
   WHERE action_id = p_action_id;
  INSERT INTO action_transitions (action_id, old_status, new_status) VALUES
    (p_action_id, 'authorized', 'executing'),
    (p_action_id, 'executing', 'confirmed');
  RETURN v_result;
END;
$$;
ALTER FUNCTION fn_execute_read(text, text, text) OWNER TO stack_owner;
REVOKE ALL ON FUNCTION fn_execute_read(text, text, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION fn_execute_read(text, text, text) TO stack_worker;
