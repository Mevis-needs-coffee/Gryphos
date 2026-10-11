"""Explicit operator approval for consequential tool actions.

Approval is bound to an exact action via a SHA-256 fingerprint over the
canonical (tool, target, arguments) tuple. A decision applies only to that
precise action and is single-use: if any security-relevant parameter changes,
a new approval is required. Missing or malformed state defaults to deny.
Model-generated text is never treated as authorization.

Approval is also governed by a five-level risk policy:

- Level 0 — internal evidence parsing and explanation (offline).
- Level 1 — restricted, read-only local inspection.
- Level 2 — network-active checks (Nmap, HTTP, TLS).
- Level 3 — more intrusive authorized assessment, with tighter constraints.
- Level 4 — system modifications / privileged actions, disabled by default.

Levels 0-1 run without a prompt because they have no side effects beyond
reading local state. Levels 2-4 always require explicit operator approval, and
the prompt shows the exact action and its expected impact before asking. The
interface defaults to "no".
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import UTC, datetime

# Risk-based approval policy -------------------------------------------------

MIN_APPROVAL_LEVEL = 0
MAX_APPROVAL_LEVEL = 4
# At and above this level, explicit operator approval is mandatory.
APPROVAL_REQUIRED_FROM_LEVEL = 2
# Level 4 (system modification) is disabled unless deliberately enabled.
DEFAULT_MAX_ENABLED_LEVEL = 3

_APPROVAL_LEVELS: dict[int, dict[str, str]] = {
    0: {
        "name": "Level 0 — internal",
        "purpose": "Internal evidence parsing and explanation.",
        "impact": "Offline only: reads already-collected evidence; no side effects.",
    },
    1: {
        "name": "Level 1 — local read-only",
        "purpose": "Restricted, read-only local inspection.",
        "impact": (
            "Reads local host state only; no writes, no network traffic, "
            "no privilege changes."
        ),
    },
    2: {
        "name": "Level 2 — network-active",
        "purpose": "Network-active checks (Nmap, HTTP, TLS inspection).",
        "impact": "Sends network traffic to one in-scope target.",
    },
    3: {
        "name": "Level 3 — intrusive",
        "purpose": "More intrusive authorized assessment tools.",
        "impact": (
            "Tighter constraints; opens a connection to one in-scope target and "
            "may elicit a service-triggered response."
        ),
    },
    4: {
        "name": "Level 4 — system modification",
        "purpose": "System modifications and privileged actions.",
        "impact": "Can modify the local system; disabled by default.",
    },
}


def validate_level(level: object) -> int:
    """Return `level` as a valid 0-4 approval level, or raise ValueError."""
    if isinstance(level, bool) or not isinstance(level, int):
        raise ValueError(f"Approval level must be an integer, got {level!r}.")
    if not (MIN_APPROVAL_LEVEL <= level <= MAX_APPROVAL_LEVEL):
        raise ValueError(
            f"Approval level must be between {MIN_APPROVAL_LEVEL} and "
            f"{MAX_APPROVAL_LEVEL}, got {level}."
        )
    return level


def level_name(level: int) -> str:
    return _APPROVAL_LEVELS[validate_level(level)]["name"]


def level_purpose(level: int) -> str:
    return _APPROVAL_LEVELS[validate_level(level)]["purpose"]


def level_impact(level: int) -> str:
    return _APPROVAL_LEVELS[validate_level(level)]["impact"]


def requires_approval(level: int) -> bool:
    """True when this level mandates explicit operator approval (levels 2-4)."""
    return validate_level(level) >= APPROVAL_REQUIRED_FROM_LEVEL


def level_allowed(level: int, max_enabled: int = DEFAULT_MAX_ENABLED_LEVEL) -> bool:
    """True when the level is enabled, i.e. not above the configured ceiling.

    Level 4 is disabled by default because the default ceiling is 3.
    """
    return validate_level(level) <= validate_level(max_enabled)


def action_fingerprint(tool: str, target: str, args: dict) -> str:
    """Canonical fingerprint for one exact proposed action."""
    canonical = json.dumps(
        {"tool": tool, "target": target, "args": args},
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


@dataclass
class ApprovalRequest:
    tool: str
    target: str
    args: dict
    purpose: str
    display: str
    network_active: bool
    timeout: int
    output_limit: int
    risk: str
    side_effects: str
    approval_level: int = APPROVAL_REQUIRED_FROM_LEVEL
    reason: str = ""  # model's justification; display-only, not fingerprinted
    fingerprint: str = ""
    requested_at: str = ""

    def __post_init__(self) -> None:
        validate_level(self.approval_level)
        if not self.fingerprint:
            self.fingerprint = action_fingerprint(self.tool, self.target, self.args)
        if not self.requested_at:
            self.requested_at = datetime.now(UTC).isoformat()

    @property
    def approval_required(self) -> bool:
        return requires_approval(self.approval_level)

    def to_record(self) -> dict:
        return {
            "tool": self.tool,
            "target": self.target,
            "args": self.args,
            "purpose": self.purpose,
            "display": self.display,
            "network_active": self.network_active,
            "timeout": self.timeout,
            "risk": self.risk,
            "approval_level": self.approval_level,
            "approval_level_name": level_name(self.approval_level),
            "side_effects": self.side_effects,
            "reason": self.reason,
            "fingerprint": self.fingerprint,
            "requested_at": self.requested_at,
        }


@dataclass
class ApprovalDecision:
    fingerprint: str
    approved: bool
    decided_at: str
    consumed: bool = False

    def consume(self) -> bool:
        """Mark single-use. Returns False if already consumed (deny reuse)."""
        if self.consumed or not self.approved:
            return False
        self.consumed = True
        return True


@dataclass
class ApprovalManager:
    """Records approvals; enforces fingerprint match and single use."""

    decisions: dict[str, ApprovalDecision] = field(default_factory=dict)

    def record(self, request: ApprovalRequest, approved: bool) -> ApprovalDecision:
        decision = ApprovalDecision(
            fingerprint=request.fingerprint,
            approved=bool(approved),
            decided_at=datetime.now(UTC).isoformat(),
        )
        self.decisions[request.fingerprint] = decision
        return decision

    def authorize(self, request: ApprovalRequest) -> bool:
        """Return True only for an approved, unconsumed, exact-match action.

        Any missing, malformed, mismatched, or reused state denies execution.
        """
        decision = self.decisions.get(request.fingerprint)
        if decision is None:
            return False  # default deny
        if decision.fingerprint != request.fingerprint:
            return False
        return decision.consume()
