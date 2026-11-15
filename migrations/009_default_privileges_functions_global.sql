-- 009_default_privileges_functions_global: 008 war wirkungslos, wird hier ersetzt.
-- Befund (Review, PostgreSQL 16): ALTER DEFAULT PRIVILEGES ... IN SCHEMA public
-- ... REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC erzeugt keine pg_default_acl-Zeile
-- und ändert nichts (verifiziert: neue Funktionen blieben PUBLIC-ausführbar).
-- Die globale Form (ohne IN SCHEMA) wirkt: Default wird Owner-only.
-- 008 bleibt als Historie bestehen; diese Datei ist maßgeblich.
-- Tabellen/Sequenzen brauchen nichts: deren Built-in-Default ist bereits
-- Owner-only (die 002/004-PUBLIC-Revokes waren wirkungslos, aber harmlos).
-- Explizite GRANTs (wie in 005) bleiben möglich und nötig.
ALTER DEFAULT PRIVILEGES FOR ROLE stack_owner
  REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;
ALTER DEFAULT PRIVILEGES FOR ROLE control_stack
  REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;
