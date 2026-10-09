-- 006_owner_schema_usage: Der Tabellen-Owner braucht USAGE auf Schema public.
-- 002 entzog PUBLIC das Schema-Recht; auf DBs, die NICHT stack_owner gehören
-- (z. B. control_stack), fehlte es danach auch dem Owner — RI-Checks im
-- Owner-Kontext scheiterten mit "permission denied for schema public".
-- Auf control_stack_test fiel das nie auf, weil stack_owner dort DB-Owner ist.
-- Kein neues Recht für Runtime-Rollen (least privilege unverändert).
GRANT USAGE ON SCHEMA public TO stack_owner;
