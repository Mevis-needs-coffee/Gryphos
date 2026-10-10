"""Explicit operator approval for consequential tool actions.

Approval is bound to an exact action via a SHA-256 fingerprint over the
canonical (tool, target, arguments) tuple. A decision applies only to that
precise action and is single-use: if any security-relevant parameter changes,
a new approval is required. Missing or malformed state defaults to deny.
Model-generated text is never treated as authorization.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import UTC, datetime


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
    reason: str = ""  # model's justification; display-only, not fingerprinted
    fingerprint: str = ""
    requested_at: str = ""

    def __post_init__(self) -> None:
        if not self.fingerprint:
            self.fingerprint = action_fingerprint(self.tool, self.target, self.args)
        if not self.requested_at:
            self.requested_at = datetime.now(UTC).isoformat()

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
