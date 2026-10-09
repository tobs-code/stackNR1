-- 005_phase1_boundary: DB-erzwungene Sicherheitsgrenze (ADR-001, F7).
-- Läuft als Owner-Admin (Superuser). Idempotent (OR REPLACE / IF EXISTS).
--
-- Prinzip: Runtime-Rollen verlieren direkte DML-Rechte auf geschützte
-- Tabellen. Geschützte Writes laufen nur über SECURITY-DEFINER-Funktionen
-- (Owner: stack_owner), die Zielbindung (F1), Autorisierung, Run-Status (F2),
-- CAS und Idempotenz in EINER Transaktion erzwingen. Direkte Umgehung per
-- Runtime-Credentials scheitert an fehlenden Grants (F7-N1..N4).
-- Owner/Superuser bleibt ausserhalb des Bedrohungsmodells.

-- 1. Direkte DML-Rechte der Worker-Rolle zurückschneiden -----------------
REVOKE INSERT, UPDATE, DELETE ON actions FROM stack_worker;
REVOKE INSERT, UPDATE, DELETE ON records FROM stack_worker;
REVOKE INSERT, UPDATE, DELETE ON action_transitions FROM stack_worker;
REVOKE INSERT, UPDATE, DELETE ON state_transitions FROM stack_worker;
REVOKE INSERT, UPDATE, DELETE ON outbox_events FROM stack_worker;
REVOKE INSERT, UPDATE, DELETE ON evidence_ledger FROM stack_worker;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM stack_worker;
-- Gate-/Recovery-Grants bleiben unverändert (Gate autorisiert, Recovery quarantiert).

-- 2. INSERT-Statuswächter auf actions (F7-N4) ----------------------------
-- Direkte INSERTs sind nur für nicht-terminale Startzustände erlaubt
-- ('proposed' Repo-Pfad, 'authorized'/'denied' Gate-Pfad). Terminalzustände
-- ('committed', 'confirmed', ...) entstehen nur über den geschützten
-- Ausführungspfad (Funktion, Owner-Kontext). Gilt für alle Rollen inkl.
-- Owner — privilegierte Fixtures müssen den Trigger explizit deaktivieren.
CREATE OR REPLACE FUNCTION trg_actions_insert_guard()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.status NOT IN ('proposed', 'authorized', 'denied') THEN
    RAISE EXCEPTION 'actions: direkter INSERT mit terminalem Status verboten (%)', NEW.status;
  END IF;
  RETURN NEW;
END; $$;
ALTER FUNCTION trg_actions_insert_guard() OWNER TO stack_owner;
DROP TRIGGER IF EXISTS actions_insert_guard ON actions;
CREATE TRIGGER actions_insert_guard
  BEFORE INSERT ON actions FOR EACH ROW EXECUTE FUNCTION trg_actions_insert_guard();

-- 3a. Geschützter Demo-Write (F1/F2/F7) -----------------------------------
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
  INSERT INTO action_transitions (action_id, old_status, new_status) VALUES
    (p_action_id, 'authorized', 'executing'),
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

-- 3b. Geschützter Demo-Read (effect-frei, aber autorisierungsgebunden) ---
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

-- 3c. Ledger-Anhang für den Event-Writer (konsistent oder Fehler) --------
CREATE OR REPLACE FUNCTION fn_ledger_append(
  p_event_id text, p_run_id text, p_sequence bigint, p_event_hash text, p_prev_hash text
) RETURNS text
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public
AS $$
DECLARE
  v_id text;
  v_hash text;
  v_prev text;
BEGIN
  INSERT INTO evidence_ledger (event_id, run_id, sequence, event_hash, prev_hash)
    VALUES (p_event_id, p_run_id, p_sequence, p_event_hash, p_prev_hash)
    ON CONFLICT (event_id) DO NOTHING RETURNING event_id INTO v_id;
  IF FOUND THEN
    RETURN v_id;
  END IF;
  SELECT event_hash, prev_hash INTO v_hash, v_prev
    FROM evidence_ledger WHERE event_id = p_event_id;
  IF NOT FOUND OR v_hash <> p_event_hash OR v_prev <> p_prev_hash THEN
    RAISE EXCEPTION 'ledger_divergence bei %', p_event_id;
  END IF;
  RETURN p_event_id;
END;
$$;
ALTER FUNCTION fn_ledger_append(text, text, bigint, text, text) OWNER TO stack_owner;
REVOKE ALL ON FUNCTION fn_ledger_append(text, text, bigint, text, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION fn_ledger_append(text, text, bigint, text, text) TO stack_worker;

-- 3d. TEST-ONLY Selbstabschaltung (D4 kill_mid_tx). Owner ist Superuser,
-- damit der Signal-Versand unabhängig vom Aufrufer-Kontext funktioniert.
-- Heute schon für Worker-DSNs erreichbar (direktes SQL); kein neues Recht.
CREATE OR REPLACE FUNCTION fn_test_kill_self() RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public
AS $$
BEGIN
  PERFORM pg_terminate_backend(pg_backend_pid());
END;
$$;
ALTER FUNCTION fn_test_kill_self() OWNER TO control_stack;
REVOKE ALL ON FUNCTION fn_test_kill_self() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION fn_test_kill_self() TO stack_worker, stack_owner;
