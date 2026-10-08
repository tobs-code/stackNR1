"""Serverseitiges Capability-Verzeichnis (Spiegel der Policy, nicht Quelle).

Autoritativ bleibt OPA (required_permission in Rego). Diese Tabelle dient
nur der frühen Schema-Ablehnung unbekannter Aktionen im Gate.
"""
from __future__ import annotations

CAPABILITIES: dict[str, dict] = {
    "demo_read": {"permission": "records.read", "write": False},
    "demo_update_record": {"permission": "records.write", "write": True},
}


def is_capable(action: str) -> bool:
    return action in CAPABILITIES
