"""Worker-Prozessgrenze (I1): Subprozess + eigene DSN + kein Gate→Broker-Import."""
import ast
import json
import os
import subprocess
import sys
import uuid

import psycopg
import pytest

from control_stack.gate.executor import authorize
from control_stack.policy.client import OPAClient

ADMIN = ("dbname=control_stack_test user=control_stack password=testpw"
         " host=127.0.0.1 port=5433 connect_timeout=5")
WORKER = ("dbname=control_stack_test user=stack_worker password=testpw_worker"
          " host=127.0.0.1 port=5433 connect_timeout=5")
GATE = ("dbname=control_stack_test user=stack_gate password=testpw_gate"
        " host=127.0.0.1 port=5433 connect_timeout=5")
OPA = os.environ.get("CONTROL_STACK_OPA_URL", "http://127.0.0.1:8181")
ACTOR = "agent-1"
SRC = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "src"))


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


def _spawn(req: dict, dsn: str | None = WORKER) -> tuple[int, dict]:
    env = dict(os.environ)
    env["PYTHONPATH"] = SRC + os.pathsep + env.get("PYTHONPATH", "")
    if dsn is None:
        env.pop("CONTROL_STACK_WORKER_DSN", None)
    else:
        env["CONTROL_STACK_WORKER_DSN"] = dsn
    p = subprocess.run(
        [sys.executable, "-m", "control_stack.worker.server"],
        input=json.dumps(req) + "\n", capture_output=True, text=True,
        env=env, timeout=60)
    return p.returncode, json.loads(p.stdout.strip().splitlines()[-1])


def _auth(opa, rid):
    p = {"action_id": str(uuid.uuid4()), "run_id": rid,
         "action": "demo_update_record", "target": "rec-1",
         "arguments": {"record_id": "rec-1", "status": "approved"},
         "expected_resource_version": 0}
    return authorize(GATE, opa, p, ACTOR, ["records.write"])


def test_worker_subprocess_executes_with_own_credentials(live):
    opa, rid = live
    rec = _auth(opa, rid)
    rc, resp = _spawn({"op": "execute", "action_id": str(rec.action_id),
                       "arguments": {"record_id": "rec-1", "status": "approved"},
                       "actor_id": ACTOR})
    assert rc == 0 and resp["ok"] is True
    assert resp["result"]["new_version"] == 1
    with _admin() as c, c.cursor() as cur:
        cur.execute("SELECT version FROM records WHERE record_id='rec-1'")
        assert cur.fetchone()[0] == 1


def test_worker_subprocess_denies_tampered_args(live):
    opa, rid = live
    rec = _auth(opa, rid)
    rc, resp = _spawn({"op": "execute", "action_id": str(rec.action_id),
                       "arguments": {"record_id": "rec-1", "status": "rejected"},
                       "actor_id": ACTOR})
    assert rc == 1 and resp["ok"] is False
    assert resp["class"] == "ExecutionDenied"


def test_worker_unknown_op_rejected(live):
    live  # noqa: B018
    rc, resp = _spawn({"op": "drop_database"})
    assert rc == 2 and resp["ok"] is False


def test_worker_without_dsn_fails_closed(live):
    live  # noqa: B018
    rc, resp = _spawn({"op": "execute"}, dsn=None)
    assert rc == 2 and resp["ok"] is False


def test_gate_never_imports_broker():
    """Gate-Prozess darf kein Ausführungspfad sein: statischer Import-Check."""
    for mod in ("gate/executor.py", "gate/validation.py", "gate/capabilities.py",
                "policy/client.py", "policy/decision.py"):
        path = os.path.join(SRC, "control_stack", mod)
        tree = ast.parse(open(path, encoding="utf-8").read())
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and (node.module or "").startswith(
                    "control_stack.execution"):
                pytest.fail(f"{mod} importiert execution")
            if isinstance(node, ast.Import):
                for a in node.names:
                    assert not a.name.startswith("control_stack.execution"), mod
