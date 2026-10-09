-- 007_test_kill_grant: EXECUTE-Recht für den verschachtelten DEFINER-Aufruf
-- fn_execute_write (Owner stack_owner) → fn_test_kill_self nachholen.
-- Die 005-Fassung mit nur stack_worker war auf control_stack_test bereits
-- appliziert, bevor der stack_owner-Grant ergänzt wurde; Migrations-Dateien
-- werden nie erneut ausgeführt, daher hier als eigene Migration.
-- TEST-ONLY Oberfläche (D4 kill_mid_tx), kein neues Runtime-Recht.
GRANT EXECUTE ON FUNCTION fn_test_kill_self() TO stack_worker, stack_owner;
