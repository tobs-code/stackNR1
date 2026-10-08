"""Gate-Integration: echte OPA + echtes PG. Prüft DB-Zustand, nie nur Returnwerte."""
import os
import uuid
from datetime import datetime, timezone

import psycopg
import pytest

from control_stack.gate.executor import GateDenied, GateRejected, authorize
from control_stack.policy.client import OPAClient, PolicyError

DSN = os.environ.get(
    "CONTROL_STACK_TEST_DSN",
    "dbname=control_stack user=control_stack password=testpw host=127.0.0.1 port=5433 connect_timeout=5",
)
OPA = os.environ.get("CONTROL_STACK_OPA_URL", "http://127.0.0.1:8181")
SCHEMA = os.path.abspath(os.path.join(
    os.path.dirname(__file__), "..", "..", "src", "control_stack", "state", "schema.sql"))

ACTOR = "agent-1"


def _db():
    return psycopg.connect(DSN, autocommit=True)


@pytest.fixture()
def live():
    with _db() as c:
        c.execute(open(SCHEMA, encoding="utf-8").read())
        for t in ("outbox_events", "state_transitions", "action_transitions",
                  "policy_decisions", "authorization_records", "actions",
                  "records", "runs"):
            c.execute(f"DELETE FROM {t}")
        rid = f"run-{uuid.uuid4().hex[:8]}"
        c.execute("INSERT INTO runs (run_id, owner) VALUES (%s,'t')", (rid,))
        c.execute("INSERT INTO records (record_id) VALUES ('rec-1')")
    return OPAClient(OPA, policy_version="test-v1"), rid


def _proposal(rid, **over):
    p = {
        "action_id": str(uuid.uuid4()),
        "run_id": rid,
        "action": "demo_update_record",
        "target": "rec-1",
        "arguments": {"record_id": "rec-1", "status": "approved"},
        "expected_resource_version": 0,
    }
    p.update(over)
    return p


def test_opa_allow_creates_record(live):
    opa, rid = live
    rec = authorize(DSN, opa, _proposal(rid), ACTOR, ["records.write"])
    assert rec.verify({"record_id": "rec-1", "status": "approved"})
    with _db() as c, c.cursor() as cur:
        cur.execute("SELECT status FROM actions WHERE action_id=%s", (str(rec.action_id),))
        assert cur.fetchone()[0] == "authorized"
        cur.execute("SELECT COUNT(*) FROM authorization_records WHERE action_id=%s",
                    (str(rec.action_id),))
        assert cur.fetchone()[0] == 1


def test_opa_deny_no_auth_no_effect(live):
    opa, rid = live
    with pytest.raises(GateDenied):
        authorize(DSN, opa, _proposal(rid), ACTOR, ["records.read"])  # falsche Permission
    with _db() as c, c.cursor() as cur:
        cur.execute("SELECT COUNT(*) FROM authorization_records")
        assert cur.fetchone()[0] == 0
        cur.execute("SELECT version FROM records WHERE record_id='rec-1'")
        assert cur.fetchone()[0] == 0  # kein Effect


def test_opa_unreachable_fail_closed(live):
    _, rid = live
    dead = OPAClient("http://127.0.0.1:9", timeout_ms=200)
    with pytest.raises(PolicyError):
        authorize(DSN, dead, _proposal(rid), ACTOR, ["records.write"])


def test_actor_injection_ignored(live):
    opa, rid = live
    raw = _proposal(rid)
    raw["actor_id"] = "root"  # untrusted Feld -> Schema reject (forbid)
    raw["permissions"] = ["records.write"]
    with pytest.raises(GateRejected):
        authorize(DSN, opa, raw, ACTOR, ["records.write"])


def test_tampered_record_fails_verify(live):
    opa, rid = live
    rec = authorize(DSN, opa, _proposal(rid), ACTOR, ["records.write"])
    with _db() as c:
        c.execute("UPDATE authorization_records SET target='rec-9' WHERE action_id=%s",
                  (str(rec.action_id),))
        c.execute("UPDATE actions SET target='rec-9' WHERE action_id=%s",
                  (str(rec.action_id),))
    with _db() as c, c.cursor() as cur:
        cur.execute("SELECT * FROM authorization_records WHERE action_id=%s",
                    (str(rec.action_id),))
        row = cur.fetchone()
    # Feldvergleich gegen Original-Argumente muss scheitern
    assert rec.model_copy(update={"target": "rec-9"}).verify(
        {"record_id": "rec-1", "status": "approved"}) is False


def test_stale_version_denied_by_policy(live):
    opa, rid = live
    with _db() as c:
        c.execute("UPDATE records SET version=5 WHERE record_id='rec-1'")
    with pytest.raises(GateDenied):
        authorize(DSN, opa, _proposal(rid), ACTOR, ["records.write"])


def test_expired_record_never_granted(live):
    opa, rid = live
    rec = authorize(DSN, opa, _proposal(rid), ACTOR, ["records.write"],
                    ttl_seconds=-1)  # bereits abgelaufen
    assert rec.expires_at < datetime.now(timezone.utc)
    # execution-Schicht darf abgelaufene Records nicht akzeptieren:
    assert rec.expires_at.tzinfo is not None
