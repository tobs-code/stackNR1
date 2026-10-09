-- 008_default_privileges_closed: künftige Objekte fail closed (F7-Härtung).
-- 002/004 schlossen Defaults für stack_owner-erzeugte Tabellen/Sequenzen;
-- für Funktionen (und für den Creator control_stack) galten weiter die
-- PostgreSQL-Defaults (u. a. EXECUTE TO PUBLIC auf neuen Funktionen).
-- Jede künftige privilegierte Funktion erhielte sonst öffentliche
-- Ausführungsrechte. Explizite GRANTs (wie in 005) bleiben möglich und nötig.
ALTER DEFAULT PRIVILEGES FOR ROLE stack_owner IN SCHEMA public
  REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;
ALTER DEFAULT PRIVILEGES FOR ROLE control_stack IN SCHEMA public
  REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;
ALTER DEFAULT PRIVILEGES FOR ROLE control_stack IN SCHEMA public
  REVOKE ALL ON TABLES FROM PUBLIC;
ALTER DEFAULT PRIVILEGES FOR ROLE control_stack IN SCHEMA public
  REVOKE ALL ON SEQUENCES FROM PUBLIC;
