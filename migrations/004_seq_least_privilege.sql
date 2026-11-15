-- 004_seq_least_privilege: Sequenzrechte je Runtime-Pfad (statt blanket).
-- Bedarf: action_transitions_seq ← gate/worker/recovery (alle schreiben
-- Lifecycle-Transitions); state_transitions_seq ← nur worker.
-- Künftige Sequenzen erhalten KEINE Default-Grants (fail closed: neuer Pfad
-- scheitert laut statt mit zu breiten Rechten).
REVOKE ALL ON ALL SEQUENCES IN SCHEMA public
  FROM stack_gate, stack_worker, stack_recovery;
ALTER DEFAULT PRIVILEGES FOR ROLE stack_owner IN SCHEMA public
  REVOKE ALL ON SEQUENCES FROM stack_gate, stack_worker, stack_recovery;

DO $$
DECLARE r RECORD;
BEGIN
  FOR r IN SELECT sequencename FROM pg_sequences WHERE schemaname='public' LOOP
    IF r.sequencename LIKE 'action_transitions%' THEN
      EXECUTE format('GRANT USAGE, SELECT ON SEQUENCE public.%I'
                     ' TO stack_gate, stack_worker, stack_recovery', r.sequencename);
    ELSIF r.sequencename LIKE 'state_transitions%' THEN
      EXECUTE format('GRANT USAGE, SELECT ON SEQUENCE public.%I TO stack_worker',
                     r.sequencename);
    END IF;
  END LOOP;
END $$;
