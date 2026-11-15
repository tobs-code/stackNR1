"""OPA-Entscheidung: striktes Ergebnis, kein Fallback."""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Decision:
    allow: bool
    violations: tuple[str, ...]
    policy_version: str

    @property
    def granted(self) -> bool:
        return self.allow and not self.violations
