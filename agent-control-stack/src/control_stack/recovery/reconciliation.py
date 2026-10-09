"""Recovery-State-Inspektion: reinen DB-Zustand ermitteln, nie aus
Client-Exceptions schließen. Anker: action_id + serverseitiger Idempotency-Key.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

import psycopg

from ..contracts import RECORD_FIELDS, canon, canonical_hash, expires_at_iso

Outcome = Literal["replayed", "retry_allowed", "quarantined"]


@dataclass(frozen=True)
class Inspection:
    outcome: Outcome
    result: dict | None
    reason: str


def _has_consistent_effect(cur: psycopg.Cursor, action: dict) -> bool:
    """Prüft, ob genau dieser Action ein konsistenter Ressourcen-Effect
    zugeordnet ist: Transition mit passendem Run, Ziel sowie alter/neuer
    Version aus dem gespeicherten Resultat. Teilspuren (z. B. nur
    record_id/new_version bei abweichendem Rest) genügen nicht."""
    try:
        result = dict(action["result"])
        want_record = result.get("record_id")
        want_old = result.get("old_version")
        want_new = result.get("new_version")
    except (TypeError, ValueError):
        return False
    if want_record is None or want_old is None or want_new is None:
        return False
    cur.execute(
        "SELECT COUNT(*) AS n FROM state_transitions"
        " WHERE action_id=%s AND run_id=%s AND record_id=%s"
        " AND old_version=%s AND new_version=%s",
        (action["action_id"], action["run_id"],
         want_record, want_old, want_new))
    row = cur.fetchone()
    return row is not None and row["n"] == 1


def inspect_action(cur: psycopg.Cursor, action_id: str) -> Inspection:
    """Klassifiziert anhand persistierter Daten (Record + Action + Resource).

    - committed + result  → replayed (kein neuer Effect)
    - sonst ausführbar (auth Record vorhanden, gültig, nicht abgelaufen,
      Ressource auf erwarteter Version) → retry_allowed (genau ein Versuch
      über den idempotenten Pfad)
    - widersprüchlich/nicht rekonstruierbar → quarantined
    """
    cur.execute("SELECT * FROM actions WHERE action_id=%s", (action_id,))
    action = cur.fetchone()
    if action is None:
        return Inspection("quarantined", None, "action unbekannt")
    if action["status"] == "committed" and action["result"] is not None:
        # F4: Status-Snapshot + Resultat sind KEIN Nachweis. Replay nur, wenn
        # die konsistente Effektspur (state_transitions mit passendem
        # record_id/new_version) denselben Effect belegt — sonst Quarantäne.
        if _has_consistent_effect(cur, action):
            return Inspection("replayed", dict(action["result"]), "commit persistiert")
        return Inspection("quarantined", None,
                          "committed ohne konsistenten Effektnachweis")
    if action["status"] == "committed":
        return Inspection("quarantined", None,
                          "committed ohne Ergebnis: widersprüchlich")
    cur.execute("SELECT * FROM authorization_records WHERE action_id=%s",
                (action_id,))
    rec = cur.fetchone()
    if rec is None:
        return Inspection("quarantined", None, "kein Authorization Record")
    # Volle Bindungsprüfung wie der Worker: Record-Felder gegen Action-Zeile
    # + kanonischer Hash neu rekonstruiert. Retry nur bei gültiger Bindung.
    if (rec["action"] != action["action"] or rec["target"] != action["target"]
            or rec["args_hash"] != action["args_hash"]
            or rec["expected_resource_version"] != action["expected_resource_version"]):
        return Inspection("quarantined", None,
                          "Record weicht von Action-Zeile ab (Tamper?)")
    import json as _json
    try:
        fields = {
            "action": rec["action"], "target": rec["target"],
            "args_hash": rec["args_hash"], "actor_id": rec["actor_id"],
            "permissions_sorted": sorted(rec["permissions"]),
            "expected_resource_version": rec["expected_resource_version"],
            "preconditions_canon": _json.loads(canon(dict(rec["preconditions"]))),
            "policy_version": rec["policy_version"],
            "context_hash": rec["context_hash"], "action_id": str(action["action_id"]),
            "expires_at_iso": expires_at_iso(rec["expires_at"]),
        }
        assert set(fields) == set(RECORD_FIELDS)
        if canonical_hash(fields) != rec["canonical_hash"]:
            return Inspection("quarantined", None,
                              "Record-Hash ungültig (Tamper?)")
    except Exception:
        return Inspection("quarantined", None, "Record nicht rekonstruierbar")
    cur.execute("SELECT clock_timestamp() > %s AS expired", (rec["expires_at"],))
    if cur.fetchone()["expired"]:
        return Inspection("quarantined", None, "Autorisierung abgelaufen")
    cur.execute("SELECT version FROM records WHERE record_id=%s",
                (action["target"],))
    res = cur.fetchone()
    if res is None:
        return Inspection("quarantined", None, "Zielressource fehlt")
    if res["version"] != action["expected_resource_version"]:
        # Ressource wurde anderweitig verändert: kein blinder Retry.
        # Ob der eigene Effect darin steckt, ist über Key + Transition prüfbar:
        cur.execute(
            "SELECT COUNT(*) AS n FROM state_transitions WHERE action_id=%s",
            (action_id,))
        if cur.fetchone()["n"] > 0:
            cur.execute(
                "SELECT result FROM actions WHERE action_id=%s", (action_id,))
            r = cur.fetchone()
            if r and r["result"] is not None:
                return Inspection("replayed", dict(r["result"]),
                                  "Effect in Transition nachgewiesen")
        return Inspection("quarantined", None,
                          "Ressourcenversion abgewichen, Effect nicht zuordenbar")
    return Inspection("retry_allowed", None, "sauberer Retry über idempotenten Pfad")
