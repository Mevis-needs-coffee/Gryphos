"""Core tool interfaces, shared validation, and command execution.

Defines the single contract every registered tool must satisfy: metadata
(name, description, purpose), input schema, scope requirements, risk category,
passive/active classification, network activity, timeout/output limits,
approval policy, implementation, and a structured result format. Argument
validation rejects anything outside the declared schema, so the model can
never inject flags, commands, or executables.
"""

from __future__ import annotations

import shutil
import subprocess
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime

from ..approval import (
    APPROVAL_REQUIRED_FROM_LEVEL,
    requires_approval,
    validate_level,
)

RISK_LEVELS = ("informational", "low", "medium", "high", "critical")
APPROVAL_POLICIES = ("explicit", "none")
ACTIVITIES = ("passive", "active")


class ToolError(RuntimeError):
    """Raised for tool validation or execution problems (safe to show users)."""


class ToolDependencyError(ToolError):
    """A required external binary/module is missing (install hint attached)."""


@dataclass
class ProcResult:
    returncode: int | None
    output: str
    timed_out: bool = False


def bounded(text: str, limit: int) -> str:
    if limit and len(text) > limit:
        return text[:limit]
    return text


def run_process(
    argv: list[str],
    timeout: int,
    max_output_chars: int,
) -> ProcResult:
    """Run a fixed argument list without a shell; bounded by timeout/output.

    Timeouts and unexpected subprocess failures surface as safe results rather
    than crashes, so the agent loop can continue or stop deliberately.
    """
    try:
        completed = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
            shell=False,
        )
    except subprocess.TimeoutExpired as exc:
        partial = exc.stdout or b""
        if isinstance(partial, bytes):
            partial = partial.decode("utf-8", errors="replace")
        return ProcResult(
            returncode=None,
            output=f"Timed out after {timeout}s.\n{partial}".strip()[:max_output_chars],
            timed_out=True,
        )
    except OSError as exc:
        return ProcResult(returncode=None, output=f"Could not run command: {exc}".strip())
    output = (completed.stdout or "")
    if completed.stderr:
        output += ("\n" if output and not output.endswith("\n") else "") + completed.stderr
    return ProcResult(returncode=completed.returncode, output=output[:max_output_chars])


def resolve_binary(name: str, install_hint: str) -> str:
    """Resolve an external binary, or raise a ToolDependencyError."""
    binary = shutil.which(name)
    if not binary:
        raise ToolDependencyError(f"{name} is not installed. {install_hint}")
    return binary


def duration_since(started: datetime) -> float:
    return (datetime.now(UTC) - started).total_seconds()


@dataclass
class ToolResult:
    tool: str
    target: str
    display: str
    returncode: int | None
    output: str
    network_active: bool
    started_at: str = ""
    duration_seconds: float | None = None
    data: dict = field(default_factory=dict)
    error: str | None = None
    activity: str = "active"  # "passive" (no system/network side effects) or "active"

    def to_evidence(self) -> dict:
        item = {
            "kind": "tool_result",
            "tool": self.tool,
            "target": self.target,
            "command": self.display,
            "returncode": self.returncode,
            "network_active": self.network_active,
            "activity": self.activity,
            "output": self.output,
        }
        if self.started_at:
            item["started_at"] = self.started_at
        if self.duration_seconds is not None:
            item["duration_seconds"] = round(self.duration_seconds, 3)
        if self.data:
            item["data"] = self.data
        if self.error:
            item["error"] = self.error
        return item


@dataclass
class ToolSpec:
    name: str
    description: str
    purpose: str
    input_schema: dict
    risk: str
    side_effects: str
    network_active: bool
    approval_policy: str  # "explicit" for anything consequential; "none" for passive
    timeout: int
    max_output_chars: int
    execute: Callable[..., ToolResult]
    activity: str = "active"  # "passive" (local, read-only, no network) or "active"
    approval_level: int = APPROVAL_REQUIRED_FROM_LEVEL  # risk-based policy, 0-4
    scope_requirements: str = ""
    result_schema: dict = field(default_factory=dict)
    show: Callable[[dict], str] | None = None  # render exact action for approval/display

    def __post_init__(self) -> None:
        if self.risk not in RISK_LEVELS:
            raise ValueError(f"Unknown risk level {self.risk!r}")
        if self.approval_policy not in APPROVAL_POLICIES:
            raise ValueError(f"Unknown approval policy {self.approval_policy!r}")
        if self.activity not in ACTIVITIES:
            raise ValueError(f"Unknown activity classification {self.activity!r}")
        validate_level(self.approval_level)
        # Keep the coarse policy, activity, and network flag consistent with the
        # fine-grained risk level so a tool can never under-declare its risk.
        if self.approval_level >= APPROVAL_REQUIRED_FROM_LEVEL:
            if self.approval_policy != "explicit":
                raise ValueError(
                    f"Tool {self.name!r} is level {self.approval_level} and must use "
                    "approval_policy='explicit'."
                )
            if self.activity != "active":
                raise ValueError(
                    f"Tool {self.name!r} is level {self.approval_level} and must be active."
                )
        else:
            if self.approval_policy != "none":
                raise ValueError(
                    f"Tool {self.name!r} is level {self.approval_level} and must use "
                    "approval_policy='none'."
                )
            if self.network_active:
                raise ValueError(
                    f"Tool {self.name!r} is level {self.approval_level} and cannot be "
                    "network-active."
                )

    @property
    def requires_approval(self) -> bool:
        """True when this tool mandates explicit operator approval (levels 2-4)."""
        return requires_approval(self.approval_level)

    def describe(self) -> dict:
        return {
            "name": self.name,
            "description": self.description,
            "purpose": self.purpose,
            "input_schema": self.input_schema,
            "risk": self.risk,
            "side_effects": self.side_effects,
            "network_active": self.network_active,
            "activity": self.activity,
            "approval_policy": self.approval_policy,
            "approval_level": self.approval_level,
            "scope_requirements": self.scope_requirements,
            "result_schema": self.result_schema,
            "timeout": self.timeout,
            "max_output_chars": self.max_output_chars,
        }

    def display_action(self, args: dict) -> str:
        if self.show is not None:
            return self.show(args)
        return f"{self.name}({args})"


def validate_args(spec: ToolSpec, args: dict) -> dict:
    """Validate proposed arguments against the tool's schema.

    Rejects unknown properties, missing required fields, wrong types, and
    values outside declared enum/min/max constraints. Returns the sanitized
    argument dict.
    """
    if not isinstance(args, dict):
        raise ToolError("Tool arguments must be a JSON object.")
    schema = spec.input_schema
    props = schema.get("properties", {})
    allowed = set(props)
    if schema.get("additionalProperties") is False:
        unknown = set(args) - allowed
        if unknown:
            raise ToolError(
                f"Unknown argument(s) for {spec.name}: {', '.join(sorted(unknown))}. "
                f"Allowed: {', '.join(sorted(allowed)) or '(none)'}."
            )
    for req in schema.get("required", []):
        if req not in args or args[req] in (None, ""):
            raise ToolError(f"Missing required argument '{req}' for {spec.name}.")

    cleaned: dict = {}
    for key, meta in props.items():
        if key not in args:
            continue
        value = args[key]
        expected = meta.get("type")
        if expected == "string" and not isinstance(value, str):
            raise ToolError(f"Argument '{key}' for {spec.name} must be a string.")
        if expected == "integer":
            if isinstance(value, bool) or not isinstance(value, int):
                raise ToolError(f"Argument '{key}' for {spec.name} must be an integer.")
            if "minimum" in meta and value < meta["minimum"]:
                raise ToolError(f"Argument '{key}' for {spec.name} must be >= {meta['minimum']}.")
            if "maximum" in meta and value > meta["maximum"]:
                raise ToolError(f"Argument '{key}' for {spec.name} must be <= {meta['maximum']}.")
        if expected == "boolean" and not isinstance(value, bool):
            raise ToolError(f"Argument '{key}' for {spec.name} must be a boolean.")
        enum = meta.get("enum")
        if enum is not None and value not in enum:
            raise ToolError(
                f"Argument '{key}' for {spec.name} must be one of: {', '.join(map(str, enum))}."
            )
        cleaned[key] = value
    return cleaned
