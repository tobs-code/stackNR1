"""Abnahme 1 (Rev. 4): Kanonisierung, Hash-Rekonstruktion, Statusübergänge."""
from datetime import datetime, timezone

import pytest

from control_stack.contracts import (
    AuthorizationRecord,
    canonical_hash,
    is_allowed,
    record_fields,
    transition,
)


def _base_kwargs(**over):
    kw = dict(
        action="demo_update_record",
        target="record-123",
        arguments={"record_id": "record-123", "status": "approved"},
        actor_id="agent-1",
        permissions=["records.write"],
        expected_resource_version=17,
        preconditions={"run_active": True},
        policy_version="sha256:abc",
        context_hash="0" * 64,
        action_id="11111111-1111-1111-1111-111111111111",
        expires_at=datetime(2026, 10, 9, tzinfo=timezone.utc),
    )
    kw.update(over)
    return kw


def _record(**over):
    kw = _base_kwargs(**over)
    args = kw.pop("arguments")
    fields = record_fields(**kw, arguments=args)
    return AuthorizationRecord(
        action_id=kw["action_id"],
        canonical_hash=canonical_hash(fields),
        action=kw["action"],
        target=kw["target"],
        args_hash=fields["args_hash"],
        actor_id=kw["actor_id"],
        permissions=kw["permissions"],
        expected_resource_version=kw["expected_resource_version"],
        preconditions=kw["preconditions"],
        policy_version=kw["policy_version"],
        context_hash=kw["context_hash"],
        expires_at=kw["expires_at"],
    ), kw, args


def test_roundtrip_ok():
    rec, _, args = _record()
    assert rec.verify(args) is True


def test_determinism_byte_identical():
    k1 = _base_kwargs(); k1["arguments"] = {"b": 1, "a": 2}
    k2 = _base_kwargs(); k2["arguments"] = {"a": 2, "b": 1}
    f1 = record_fields(**k1)
    f2 = record_fields(**k2)
    assert f1["args_hash"] == f2["args_hash"]
    assert canonical_hash(f1) == canonical_hash(f2)


def test_canonical_hash_rejects_self_input():
    k = _base_kwargs(); k["arguments"] = {"x": 1}
    f = record_fields(**k)
    with pytest.raises(ValueError):
        canonical_hash({**f, "canonical_hash": "x"})


def test_each_bound_field_tamper_detected():
    rec, kw, args = _record()
    # args manipuliert
    assert rec.verify({"record_id": "record-123", "status": "rejected"}) is False
    # jedes Record-Feld einzeln manipuliert (gegen Original-args prüfen)
    for field, bad in [
        ("action", "demo_read"),
        ("target", "record-999"),
        ("actor_id", "attacker"),
        ("expected_resource_version", 18),
        ("policy_version", "sha256:evil"),
        ("context_hash", "f" * 64),
    ]:
        tampered = rec.model_copy(update={field: bad})
        assert tampered.verify(args) is False, field
    # permissions-Reihenfolge egal, Inhalt nicht
    assert rec.model_copy(update={"permissions": ["records.write"]}).verify(args) is True
    assert rec.model_copy(update={"permissions": ["records.read"]}).verify(args) is False
    # preconditions manipuliert
    assert rec.model_copy(update={"preconditions": {"run_active": False}}).verify(args) is False


def test_illegal_transitions_fail_closed():
    assert is_allowed("proposed", "validated")
    assert is_allowed("confirmed", "committed")
    for old, new in [
        ("proposed", "authorized"),
        ("proposed", "executing"),
        ("validated", "executing"),
        ("authorized", "committed"),
        ("failed", "committed"),  # Rev.1-Missverständnis bleibt verboten
        ("quarantined", "executing"),
        ("denied", "executing"),
        ("committed", "executing"),
        ("bogus", "executing"),
    ]:
        assert not is_allowed(old, new), (old, new)
        with pytest.raises(ValueError):
            transition(old, new)


def test_full_lifecycle_path():
    seq = ["proposed", "validated", "authorized", "executing", "confirmed", "committed"]
    for a, b in zip(seq, seq[1:]):
        assert transition(a, b) == b
