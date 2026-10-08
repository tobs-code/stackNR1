"""Kanonisierung (Rev. 4, C1): genau EINE Implementierung.

- JCS: json.dumps mit sort_keys=True, separators=(",", ":"),
  ensure_ascii=False, UTF-8. Keine Floats in Verträgen (nur str/int/bool/
  dict/list/None) — Determinismus byte-identisch.
- SHA-256 über UTF-8-Bytes der kanonischen Form, hex.
- expires_at: UTC, Format YYYY-MM-DDTHH:MM:SSZ (Sekunden, Z-Suffix).

Seiteneffektfrei: kein DB, kein OPA, kein Clock-Zugriff ausser Übergabe.
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any


def canon(obj: Any) -> bytes:
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def args_hash(arguments: dict) -> str:
    return sha256_hex(canon(arguments))


def expires_at_iso(dt: datetime) -> str:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    dt = dt.astimezone(timezone.utc).replace(microsecond=0)
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


# Verbindliches Record-Feldset (Rev. 4 §1 I3). canonical_hash ist
# NIEMALS Bestandteil der Eingabe (keine Zirkularität).
RECORD_FIELDS = (
    "action", "target", "args_hash", "actor_id", "permissions_sorted",
    "expected_resource_version", "preconditions_canon",
    "policy_version", "context_hash", "action_id", "expires_at_iso",
)


def record_fields(
    *,
    action: str,
    target: str,
    arguments: dict,
    actor_id: str,
    permissions: list[str],
    expected_resource_version: int,
    preconditions: dict,
    policy_version: str,
    context_hash: str,
    action_id: str,
    expires_at: datetime,
) -> dict:
    return {
        "action": action,
        "target": target,
        "args_hash": args_hash(arguments),
        "actor_id": actor_id,
        "permissions_sorted": sorted(permissions),
        "expected_resource_version": expected_resource_version,
        "preconditions_canon": json.loads(canon(preconditions)),
        "policy_version": policy_version,
        "context_hash": context_hash,
        "action_id": action_id,
        "expires_at_iso": expires_at_iso(expires_at),
    }


def canonical_hash(fields: dict) -> str:
    unexpected = set(fields) - set(RECORD_FIELDS)
    missing = set(RECORD_FIELDS) - set(fields)
    if unexpected or missing:
        raise ValueError(f"record fieldset mismatch: missing={missing} extra={unexpected}")
    if "canonical_hash" in fields:
        raise ValueError("canonical_hash darf nicht Eingabe sein (zirkulär)")
    return sha256_hex(canon(fields))
