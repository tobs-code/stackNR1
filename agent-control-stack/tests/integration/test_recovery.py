"""Recovery: Zustand rekonstruieren, nie doppelt wirken. Echte DB."""
import os
import threading
import time
import uuid

import psycopg
import pytest

from control_stack.execution.broker import OutcomeUnknown, execute
from control_stack.gate.executor import authorize
from control_stack.policy.client import OPAClient
from control_stack.recovery import reconcile

DSN = os.environ.get(
    "CONTROL_STACK_TEST_DSN",
    "dbname=control_stack user=control_stack password=testpw host=127.0.0.1 port=5433 connect_timeout=5",
)
OPA = os.environ.get("CONTROL_STACK_OPA_URL", "http://127.0.0.1:8181")
SCHEMA = os.path.abspath(os.path.join(
    os.path.dirname(__file__), "..", "..", "src", "control_stack", "state", "schema.sql"))

ACTOR = "agent-1"
ARGS = {"record_id": "rec-1", "status": "approved"}


def _db():
    return psycopg.connect(DSN, autocommit=True)


@pytest.fixture()
def live():
    # Phase 1: Ausführungs-Grenze (DEFINER-Funktionen) muss migriert sein.
    from control_stack.mig.runner import migrate
    migrate(DSN)
    with _db() as c:
        c.execute(open(SCHEMA, encoding="utf-8").read())
        for t in ("recovery_jobs", "outbox_events", "state_transitions",
                  "action_transitions",
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
    return authorize(DSN, opa, p, ACTOR, ["records.write"])


def test_committed_replays_result_no_second_effect(live):
    opa, rid = live
    rec = _auth(opa, rid)
    first = execute(DSN, str(rec.action_id), dict(ARGS), ACTOR)
    insp = reconcile(DSN, str(rec.action_id), rid)
    assert insp.outcome == "replayed" and insp.result == first
    with _db() as c, c.cursor() as cur:
        cur.execute("SELECT version FROM records WHERE record_id='rec-1'")
        assert cur.fetchone()[0] == 1
        cur.execute("SELECT COUNT(*) FROM state_transitions")
        assert cur.fetchone()[0] == 1


def test_interrupted_before_commit_allows_single_retry(live):
    opa, rid = live
    rec = _auth(opa, rid)  # autorisiert, nie ausgeführt
    insp = reconcile(DSN, str(rec.action_id), rid)
    assert insp.outcome == "retry_allowed"
    res = execute(DSN, str(rec.action_id), dict(ARGS), ACTOR)
    assert res["new_version"] == 1
    with _db() as c, c.cursor() as cur:
        cur.execute("SELECT version FROM records WHERE record_id='rec-1'")
        assert cur.fetchone()[0] == 1


def test_diverged_resource_quarantines_no_retry(live):
    opa, rid = live
    rec = _auth(opa, rid)
    with _db() as c:
        c.execute("UPDATE records SET version=7 WHERE record_id='rec-1'")
    insp = reconcile(DSN, str(rec.action_id), rid)
    assert insp.outcome == "quarantined"
    with _db() as c, c.cursor() as cur:
        cur.execute("SELECT status FROM actions WHERE action_id=%s",
                    (str(rec.action_id),))
        assert cur.fetchone()[0] == "quarantined"
        cur.execute("SELECT kind FROM recovery_jobs WHERE action_id=%s",
                    (str(rec.action_id),))
        assert cur.fetchone()[0] == "quarantine"


def test_tampered_record_reconciles_to_quarantine(live):
    """Feldbindung: actions.target weicht vom Record ab → quarantined."""
    opa, rid = live
    rec = _auth(opa, rid)
    with _db() as c:
        c.execute("UPDATE actions SET target='rec-9' WHERE action_id=%s",
                  (str(rec.action_id),))
    insp = reconcile(DSN, str(rec.action_id), rid)
    assert insp.outcome == "quarantined"


def test_tampered_auth_record_hash_reconciles_to_quarantine(live):
    """Hashbindung: Feld in authorization_records ändern (Owner-Eingriff im
    Test), canonical_hash NICHT anpassen → Rekonstruktionsprüfung schlägt
    fehl → quarantined statt retry_allowed."""
    opa, rid = live
    rec = _auth(opa, rid)
    with _db() as c:
        c.execute("UPDATE authorization_records SET permissions=%s WHERE action_id=%s",
                  (["records.read"], str(rec.action_id),))
    insp = reconcile(DSN, str(rec.action_id), rid)
    assert insp.outcome == "quarantined"
    with _db() as c, c.cursor() as cur:
        cur.execute("SELECT status FROM actions WHERE action_id=%s",
                    (str(rec.action_id),))
        assert cur.fetchone()[0] == "quarantined"
        cur.execute("SELECT version FROM records WHERE record_id='rec-1'")
        assert cur.fetchone()[0] == 0  # kein Effect aus dem Retry-Pfad


def test_unknown_action_quarantines(live):
    _, rid = live
    assert reconcile(DSN, str(uuid.uuid4()), rid).outcome == "quarantined"


def test_kill_mid_flight_exactly_one_effect(live):
    """Backend während execute() terminieren (COMMIT-ACK evtl. verloren).
    Egal ob der Commit durchkam oder nicht: am Ende genau 1 Effect."""
    opa, rid = live
    rec = _auth(opa, rid)
    aid = str(rec.action_id)
    outcome: dict = {}

    def run():
        try:
            outcome["res"] = execute(DSN, aid, dict(ARGS), ACTOR)
        except OutcomeUnknown as e:
            outcome["unknown"] = e
        except Exception as e:  # noqa: BLE001 — inkl. OperationalError
            outcome["err"] = e

    t = threading.Thread(target=run)
    t.start()
    with _db() as c, c.cursor() as cur:
        cur.execute("SELECT pg_backend_pid()")
        me = cur.fetchone()[0]
        deadline = time.time() + 5
        killed = False
        while t.is_alive() and time.time() < deadline:
            cur.execute(
                "SELECT pid FROM pg_stat_activity WHERE usename='control_stack'"
                " AND pid <> %s AND query ILIKE '%%records%%'", (me,))
            for (pid,) in cur.fetchall():
                cur.execute("SELECT pg_terminate_backend(%s)", (pid,))
                killed = True
            time.sleep(0.005)
    t.join(timeout=30)
    assert not t.is_alive(), "execute hängt nach Backend-Kill"

    insp = reconcile(DSN, aid, rid)
    if insp.outcome == "retry_allowed":
        execute(DSN, aid, dict(ARGS), ACTOR)
        insp = reconcile(DSN, aid, rid)
    assert insp.outcome == "replayed", (insp, outcome.keys(), killed)
    with _db() as c, c.cursor() as cur:
        cur.execute("SELECT version FROM records WHERE record_id='rec-1'")
        assert cur.fetchone()[0] == 1
        cur.execute("SELECT COUNT(*) FROM state_transitions WHERE action_id=%s",
                    (aid,))
        assert cur.fetchone()[0] == 1
        cur.execute("SELECT result FROM actions WHERE action_id=%s", (aid,))
        assert cur.fetchone()[0] is not None
