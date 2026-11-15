"""OPA-Client, fail closed. Keine Retries, kein lokaler Fallback.

Deny bei: Timeout, Netzwerk-/HTTP-Fehler, ungültiges JSON, fehlendes oder
nicht-boolisches allow, vorhandenen Violations. Nur exakt
allow==True + violations==[] wird als granted gewertet.
"""
from __future__ import annotations

import httpx

from .decision import Decision


class PolicyError(Exception):
    pass


class OPAClient:
    def __init__(self, base_url: str, timeout_ms: int = 500,
                 policy_version: str = "local-dev",
                 transport: httpx.BaseTransport | None = None):
        self._authz_url = base_url.rstrip("/") + "/v1/data/control/authz/allow"
        self._viol_url = base_url.rstrip("/") + "/v1/data/control/invariants/violation"
        self._timeout = timeout_ms / 1000.0
        self._version = policy_version
        self._transport = transport

    def _post(self, url: str, payload: dict) -> object:
        try:
            with httpx.Client(transport=self._transport,
                              timeout=self._timeout) as c:
                r = c.post(url, json=payload)
        except Exception as e:
            raise PolicyError(f"opa unreachable: {e}") from e
        if r.status_code != 200:
            raise PolicyError(f"opa http {r.status_code}")
        try:
            return r.json()
        except Exception as e:
            raise PolicyError(f"opa invalid json: {e}") from e

    @staticmethod
    def _result(body: object, what: str) -> object:
        if not isinstance(body, dict) or "result" not in body:
            raise PolicyError(f"opa {what}: unerwartetes Schema")
        return body["result"]

    def decide(self, opa_input: dict) -> Decision:
        allow_raw = self._result(
            self._post(self._authz_url, {"input": opa_input}), "authz")
        if not isinstance(allow_raw, bool):
            raise PolicyError("opa authz: allow ist kein bool")
        viol_raw = self._result(
            self._post(self._viol_url, {"input": opa_input}), "invariants")
        if not isinstance(viol_raw, list) or not all(isinstance(v, str) for v in viol_raw):
            raise PolicyError("opa invariants: violation ist keine str-Liste")
        return Decision(allow=allow_raw, violations=tuple(viol_raw),
                        policy_version=self._version)
