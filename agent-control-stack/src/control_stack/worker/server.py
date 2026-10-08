"""Worker-Prozess (I1): separater OS-Prozess, eigene Credentials, IPC-Vertrag.

Protokoll (jeweils genau eine JSON-Zeile auf stdin/stdout):
  Request:  {"op":"execute","action_id":...,"arguments":{...},"actor_id":...,
             "event_id":...,"run_sequence":N,"prev_event_hash":...}
  Response: {"ok":true,"result":{...}|{"replay":...}}
            {"ok":false,"error":"...","class":"ExecutionDenied|OutcomeUnknown|..."}
  Unbekannte op ⇒ {"ok":false,...}, Exit 2. DSN ausschliesslich aus
  CONTROL_STACK_WORKER_DSN (eigene Worker-Credentials, nie Gate-DSN).

Der Gate-Prozess ruft broker.execute() NIEMALS direkt auf (per Import-Check
getestet); produktiver Pfad ist immer dieser Subprozess.
"""
from __future__ import annotations

import json
import os
import sys


def main() -> int:
    dsn = os.environ.get("CONTROL_STACK_WORKER_DSN", "")
    if not dsn:
        sys.stdout.write(json.dumps({"ok": False, "error": "keine Worker-DSN",
                                     "class": "ConfigError"}) + "\n")
        return 2
    try:
        req = json.loads(sys.stdin.readline() or "")
    except Exception:
        sys.stdout.write(json.dumps({"ok": False, "error": "ungültiger Request",
                                     "class": "ProtocolError"}) + "\n")
        return 2
    if not isinstance(req, dict) or req.get("op") != "execute":
        sys.stdout.write(json.dumps({"ok": False, "error": "unbekannte op",
                                     "class": "ProtocolError"}) + "\n")
        return 2
    try:
        from .runner import run_execute
        result = run_execute(dsn, req)
        sys.stdout.write(json.dumps({"ok": True, "result": result}) + "\n")
        return 0
    except Exception as e:  # noqa: BLE001 — Fehlerklasse an Aufrufer melden
        sys.stdout.write(json.dumps({"ok": False, "error": str(e),
                                     "class": type(e).__name__}) + "\n")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
