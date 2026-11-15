"""contracts: reine Typen + Kanonisierung + Statusmaschine. Keine Seiteneffekte."""
from .actions import (
    ActionProposal,
    ActionResult,
    AuthorizationRecord,
    DemoReadArgs,
    DemoUpdateArgs,
)
from .canonical import (
    RECORD_FIELDS,
    args_hash,
    canon,
    canonical_hash,
    expires_at_iso,
    record_fields,
    sha256_hex,
)
from .transitions import ALLOWED, PAIRS, is_allowed, transition

__all__ = [
    "RECORD_FIELDS",
    "ALLOWED",
    "PAIRS",
    "ActionProposal",
    "ActionResult",
    "AuthorizationRecord",
    "DemoReadArgs",
    "DemoUpdateArgs",
    "args_hash",
    "canon",
    "canonical_hash",
    "expires_at_iso",
    "is_allowed",
    "record_fields",
    "sha256_hex",
    "transition",
]
