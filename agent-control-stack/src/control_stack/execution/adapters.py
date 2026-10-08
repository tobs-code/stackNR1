"""Effect-Adapter: reine Abbildung validierter Argumente auf Write-Parameter.

Kein DB-, kein OPA-Zugriff. Der Adapter vertraut niemandem — er wird nur
vom Broker nach erfolgreicher Autorisierungsprüfung aufgerufen.
"""
from __future__ import annotations


class AdapterError(ValueError):
    pass


def demo_update_params(arguments: dict) -> dict:
    try:
        record_id = arguments["record_id"]
        status = arguments["status"]
    except KeyError as e:
        raise AdapterError(f"fehlendes Argument: {e}") from e
    if not isinstance(record_id, str) or not record_id:
        raise AdapterError("record_id ungültig")
    if status not in ("approved", "rejected"):
        raise AdapterError("status ungültig")
    if set(arguments) != {"record_id", "status"}:
        raise AdapterError("unerwartete Argumente")
    return {"record_id": record_id, "new_status": status}
