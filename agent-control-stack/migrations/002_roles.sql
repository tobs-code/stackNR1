-- 002_roles: Least Privilege (Rev. 4 §4 C1). Läuft als Superuser/Owner-Admin.
-- Logische Rollen aus der Spec; hier als LOGIN-Rollen für echte
-- Verbindungstests. Passwörter: TEST-ONLY (Prod: Secret-Store, eigene Passwörter).
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='stack_owner') THEN
    CREATE ROLE stack_owner NOLOGIN;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='stack_gate') THEN
    CREATE ROLE stack_gate LOGIN PASSWORD 'testpw_gate';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='stack_worker') THEN
    CREATE ROLE stack_worker LOGIN PASSWORD 'testpw_worker';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='stack_recovery') THEN
    CREATE ROLE stack_recovery LOGIN PASSWORD 'testpw_recovery';
  END IF;
END $$;

-- Eigentümerschaft: alles stack_owner (Tabellen + Sequenzen).
DO $$
DECLARE r RECORD;
BEGIN
  FOR r IN SELECT tablename FROM pg_tables WHERE schemaname='public'
           AND tablename NOT LIKE 'schema_migrations' LOOP
    EXECUTE format('ALTER TABLE public.%I OWNER TO stack_owner', r.tablename);
  END LOOP;
  FOR r IN SELECT sequencename FROM pg_sequences WHERE schemaname='public' LOOP
    EXECUTE format('ALTER SEQUENCE public.%I OWNER TO stack_owner', r.sequencename);
  END LOOP;
END $$;

-- PUBLIC: keine Tabellenrechte, kein CREATE im Schema.
REVOKE ALL ON SCHEMA public FROM PUBLIC;
GRANT USAGE ON SCHEMA public TO stack_gate, stack_worker, stack_recovery;
REVOKE ALL ON ALL TABLES IN SCHEMA public FROM PUBLIC;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM PUBLIC;
ALTER DEFAULT PRIVILEGES FOR ROLE stack_owner IN SCHEMA public
  REVOKE ALL ON TABLES FROM PUBLIC;
ALTER DEFAULT PRIVILEGES FOR ROLE stack_owner IN SCHEMA public
  REVOKE ALL ON SEQUENCES FROM PUBLIC;

-- Sequenzen (BIGSERIAL): INSERT-Pfade brauchen USAGE,SELECT.
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public
  TO stack_gate, stack_worker, stack_recovery;
ALTER DEFAULT PRIVILEGES FOR ROLE stack_owner IN SCHEMA public
  GRANT USAGE, SELECT ON SEQUENCES TO stack_gate, stack_worker, stack_recovery;

-- runs / records
GRANT SELECT ON runs TO stack_gate, stack_worker, stack_recovery;
GRANT SELECT ON records TO stack_gate, stack_worker, stack_recovery;
GRANT UPDATE ON records TO stack_worker;  -- nur CAS-Write

-- actions: gate INSERT-only (kein UPDATE/DELETE!), worker R/W, recovery Status.
GRANT SELECT, INSERT ON actions TO stack_gate;
GRANT SELECT, INSERT, UPDATE ON actions TO stack_worker;
GRANT SELECT, UPDATE ON actions TO stack_recovery;

-- authorization_records: gate INSERT-only, worker+recovery nur SELECT.
GRANT SELECT, INSERT ON authorization_records TO stack_gate;
GRANT SELECT ON authorization_records TO stack_worker, stack_recovery;

-- policy_decisions / transitions / outbox / jobs
GRANT SELECT, INSERT ON policy_decisions TO stack_gate;
GRANT SELECT ON policy_decisions TO stack_recovery;
GRANT SELECT, INSERT ON action_transitions TO stack_gate, stack_worker, stack_recovery;
GRANT SELECT, INSERT ON state_transitions TO stack_worker;
GRANT SELECT ON state_transitions TO stack_recovery;
GRANT INSERT, SELECT ON outbox_events TO stack_worker;
GRANT SELECT ON outbox_events TO stack_recovery;
GRANT SELECT, INSERT, UPDATE ON recovery_jobs TO stack_recovery;
