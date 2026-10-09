"""Fehlerkampagne (docs/campaign.md): Trigger-Injektion C1–C5, Race A4,
Retry-Konsistenz D2, Grant-Matrix D6, Verifier-Schreibschutz (E).

Trigger-Setup läuft als Owner (dokumentierte Ausnahme); alle
Sicherheits-Assertions prüfen echten DB-Zustand mit Runtime-Rollen.
"""
import os
import uuid

import psycopg
import pytest

from control_stack.execution.broker import execute
from control_stack.gate.executor import authorize
from control_stack.policy.client import OPAClient
from control_stack.recovery import reconcile
from control_stack.state.repository import StaleVersionError

ADMIN = ("dbname=control_stack_test user=control_stack password=testpw"
         " host=127.0.0.1 port=5433 connect_timeout=5")
GATE = ("dbname=control_stack_test user=stack_gate password=testpw_gate"
        " host=127.0.0.1 port=5433 connect_timeout=5")
WORKER = ("dbname=control_stack_test user=stack_worker password=testpw_worker"
          " host=127.0.0.1 port=5433 connect_timeout=5")
OPA = os.environ.get("CONTROL_STACK_OPA_URL", "http://127.0.0.1:8181")
ACTOR = "agent-1"
ARGS = {"record_id": "rec-1", "status": "approved"}


def _admin():
    return psycopg.connect(ADMIN, autocommit=True)


@pytest.fixture()
def live():
    from control_stack.mig.runner import migrate
    migrate(ADMIN)
    with _admin() as c:
        for t in ("evidence_checkpoints", "evidence_ledger", "recovery_jobs",
                  "outbox_events", "state_transitions", "action_transitions",
                  "policy_decisions", "authorization_records", "actions",
                  "records", "runs"):
            c.execute(f"DELETE FROM {t}")
        rid = f"run-{uuid.uuid4().hex[:8]}"
        c.execute("INSERT INTO runs (run_id, owner) VALUES (%s,'t')", (rid,))
        c.execute("INSERT INTO records (record_id) VALUES ('rec-1')")
    return OPAClient(OPA, policy_version="test-v1"), rid


def _auth(opa, rid):
    p = {"action_id": str(uuid.uuid4()), "run_id": rid,
         "action": "demo_update_record", "target": "rec-1",
         "arguments": dict(ARGS), "expected_resource_version": 0}
    return authorize(GATE, opa, p, ACTOR, ["records.write"])


def _fault(table: str, timing: str):
    """Owner-Ausnahme: Trigger mit injiziertem Fehler. Gibt Drop-Callback."""
    name = f"fault_{table}_{uuid.uuid4().hex[:6]}"
    with _admin() as c:
        c.execute("CREATE OR REPLACE FUNCTION fault_raise() RETURNS trigger"
                  " LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'injected fault'; END; $$")
        c.execute(f"CREATE TRIGGER {name} BEFORE {timing} ON {table}"
                  " FOR EACH ROW EXECUTE FUNCTION fault_raise()")
    return name


def _drop(name: str, table: str):
    with _admin() as c:
        c.execute(f"DROP TRIGGER IF EXISTS {name} ON {table}")


def _assert_full_rollback(aid: str):
    with _admin() as c, c.cursor() as cur:
        cur.execute("SELECT version FROM records WHERE record_id='rec-1'")
        assert cur.fetchone()[0] == 0
        cur.execute("SELECT status, result FROM actions WHERE action_id=%s", (aid,))
        st, result = cur.fetchone()
        assert st == "authorized" and result is None
        for t in ("state_transitions", "outbox_events"):
            cur.execute(f"SELECT COUNT(*) FROM {t}")
            assert cur.fetchone()[0] == 0, t
        cur.execute("SELECT new_status FROM action_transitions WHERE action_id=%s"
                    " ORDER BY seq", (aid,))
        assert [r[0] for r in cur.fetchall()] == ["validated", "authorized"]


@pytest.mark.parametrize("table,timing", [
    ("records", "UPDATE"),              # C1 nach CAS
    ("actions", "UPDATE"),              # C2 Result-Write
    ("action_transitions", "INSERT"),   # C3
    ("state_transitions", "INSERT"),    # C4
    ("outbox_events", "INSERT"),        # C5
])
def test_tx_boundary_faults_roll_back(live, table, timing):
    opa, rid = live
    rec = _auth(opa, rid)
    aid = str(rec.action_id)
    trg = _fault(table, timing)
    try:
        with pytest.raises(Exception):
            execute(WORKER, aid, dict(ARGS), ACTOR)
    finally:
        _drop(trg, table)
    _assert_full_rollback(aid)


def test_auth_execute_race_cas_conflict(live):
    """A4: Ressource ändert sich zwischen authorize() und execute()."""
    opa, rid = live
    rec = _auth(opa, rid)
    with _admin() as c:  # konkurrierender Pfad
        c.execute("UPDATE records SET version=1 WHERE record_id='rec-1'")
    with pytest.raises(StaleVersionError):
        execute(WORKER, str(rec.action_id), dict(ARGS), ACTOR)
    with _admin() as c, c.cursor() as cur:
        cur.execute("SELECT version FROM records WHERE record_id='rec-1'")
        assert cur.fetchone()[0] == 1  # nur der fremde Write, kein zweiter Effect
        cur.execute("SELECT COUNT(*) FROM state_transitions")
        assert cur.fetchone()[0] == 0


def test_reconcile_after_commit_beats_version_drift(live):
    """D2: Commit+Result schlägt spätere Versionsdrift (Replay, kein Retry)."""
    opa, rid = live
    rec = _auth(opa, rid)
    first = execute(WORKER, str(rec.action_id), dict(ARGS), ACTOR)
    with _admin() as c:
        c.execute("UPDATE records SET version=9 WHERE record_id='rec-1'")
    insp = reconcile(ADMIN, str(rec.action_id), rid)
    assert insp.outcome == "replayed" and insp.result == first


S = {"SELECT"}; SI = {"SELECT", "INSERT"}; SIU = {"SELECT", "INSERT", "UPDATE"}
SIUU = {"SELECT", "INSERT", "UPDATE"}  # recovery_jobs/checkpoints (UPDATE=Status/Head)
SU = {"SELECT", "UPDATE"}

FULL_MATRIX = {
    # Tabelle: gate / worker / recovery (Phase 1, ADR-001: DB-erzwungene Grenze;
    # geschützte Writes nur über DEFINER-Funktionen, direkte Worker-DML entzogen)
    "runs": (S, S, S),
    "records": (S, S, S),
    "actions": (SI, S, SU),
    "authorization_records": (SI, S, S),
    "policy_decisions": (SI, set(), S),
    "action_transitions": (SI, S, SI),
    "state_transitions": (set(), S, S),
    "outbox_events": (set(), S, S),
    "recovery_jobs": (set(), set(), SIUU),
    "evidence_ledger": (S, S, S),  # gate+worker+recovery: SELECT; Writes nur via Funktion
    "evidence_checkpoints": (set(), S, SIUU),
}


def test_grant_matrix_exact(live):
    """D6 vollständig: alle Runtime-Rollen × alle Tabellen + Sequenzen."""
    live  # noqa: B018 — Fixture für DB-Setup
    with _admin() as c, c.cursor() as cur:
        for table, (g, w, r) in FULL_MATRIX.items():
            for role, want in (("stack_gate", g), ("stack_worker", w),
                               ("stack_recovery", r)):
                cur.execute(
                    "SELECT privilege_type FROM information_schema.role_table_grants"
                    " WHERE grantee=%s AND table_schema='public' AND table_name=%s",
                    (role, table))
                got = {x[0] for x in cur.fetchall()}
                assert got == want, (role, table, got)
        cur.execute(
            "SELECT sequence_name FROM information_schema.sequences"
            " WHERE sequence_schema='public'")
        cur.execute(
            "SELECT sequence_name FROM information_schema.sequences"
            " WHERE sequence_schema='public'")
        # 004 + 005: nur benötigte Sequenzen je Rolle (least privilege).
        # Worker schreibt nur über DEFINER-Funktionen (Owner-Kontext) und
        # braucht deshalb keine Sequenzrechte mehr.
        want_seq = {
            "stack_gate": {"action_transitions_seq_seq"},
            "stack_worker": set(),
            "stack_recovery": {"action_transitions_seq_seq"},
        }
        for (seq,) in cur.fetchall():
            for role in ("stack_gate", "stack_worker", "stack_recovery"):
                cur.execute("SELECT has_sequence_privilege(%s, %s, 'USAGE'),"
                            " has_sequence_privilege(%s, %s, 'SELECT'),"
                            " has_sequence_privilege(%s, %s, 'UPDATE')",
                            (role, seq, role, seq, role, seq))
                if seq in want_seq[role]:
                    assert cur.fetchone() == (True, True, False), (role, seq)
                else:
                    assert cur.fetchone() == (False, False, False), (role, seq)


def test_verifier_never_writes(live):
    """E: fehlgeschlagene Verifikation hinterlässt Ledger unverändert."""
    from control_stack.evidence import VerificationError, process_all, verify_run
    opa, rid = live
    with _admin() as c:
        c.execute("INSERT INTO records (record_id) VALUES ('rec-2')")
    p = {"action_id": str(uuid.uuid4()), "run_id": rid,
         "action": "demo_update_record", "target": "rec-2",
         "arguments": {"record_id": "rec-2", "status": "rejected"},
         "expected_resource_version": 0}
    rec2 = authorize(GATE, opa, p, ACTOR, ["records.write"])
    execute(WORKER, str(rec2.action_id), dict(p["arguments"]), ACTOR,
            run_sequence=1, prev_event_hash="0" * 64)
    process_all(WORKER)
    with _admin() as c, c.cursor() as cur:
        cur.execute("SELECT event_id, event_hash FROM evidence_ledger ORDER BY sequence")
        before = [tuple(r) for r in cur.fetchall()]
        cur.execute("UPDATE evidence_ledger SET event_hash=%s WHERE sequence=1",
                    ("d" * 64,))
    with pytest.raises(VerificationError):
        verify_run(WORKER, rid)
    with pytest.raises(VerificationError):
        verify_run(WORKER, rid)  # zweiter Lauf: gleicher Befund, keine Reparatur
    with _admin() as c, c.cursor() as cur:
        cur.execute("SELECT event_id, event_hash FROM evidence_ledger ORDER BY sequence")
        after = [tuple(r) for r in cur.fetchall()]
    assert len(after) == len(before) == 1
    assert after[0][0] == before[0][0] and after[0][1] == "d" * 64
