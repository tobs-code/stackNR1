"""Aktions- und Autorisierungsverträge (Rev. 4). Seiteneffektfrei."""
from __future__ import annotations

from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

ActionName = Literal["demo_read", "demo_update_record"]


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class DemoReadArgs(Strict):
    record_id: str = Field(min_length=1)


class DemoUpdateArgs(Strict):
    record_id: str = Field(min_length=1)
    status: Literal["approved", "rejected"]


class ActionProposal(Strict):
    """LLM-Vorschlag. actor_id NICHT enthalten — setzt das Gate (Spec §2)."""

    action_id: UUID
    run_id: str = Field(min_length=1)
    action: ActionName
    target: str = Field(min_length=1)
    arguments: dict
    expected_resource_version: int = Field(ge=0)

    def validated_arguments(self) -> DemoReadArgs | DemoUpdateArgs:
        if self.action == "demo_read":
            return DemoReadArgs.model_validate(self.arguments)
        return DemoUpdateArgs.model_validate(self.arguments)


class AuthorizationRecord(Strict):
    """Persistierter Freigabe-Record (Spec §4, Rev. 4 C1)."""

    action_id: UUID
    canonical_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    action: ActionName
    target: str
    args_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    actor_id: str = Field(min_length=1)
    permissions: list[str]
    expected_resource_version: int = Field(ge=0)
    preconditions: dict
    policy_version: str = Field(min_length=1)
    context_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    expires_at: datetime

    def verify(self, arguments: dict) -> bool:
        """Feldvergleich + Hash-Rekonstruktion. False = Reject."""
        from .canonical import args_hash, canonical_hash, record_fields

        try:
            fields = record_fields(
                action=self.action,
                target=self.target,
                arguments=arguments,
                actor_id=self.actor_id,
                permissions=self.permissions,
                expected_resource_version=self.expected_resource_version,
                preconditions=self.preconditions,
                policy_version=self.policy_version,
                context_hash=self.context_hash,
                action_id=str(self.action_id),
                expires_at=self.expires_at,
            )
        except (ValueError, TypeError):
            return False
        if fields["args_hash"] != self.args_hash:
            return False
        try:
            return canonical_hash(fields) == self.canonical_hash
        except ValueError:
            return False


class ActionResult(Strict):
    record_id: str
    old_version: int
    new_version: int
    status: str
