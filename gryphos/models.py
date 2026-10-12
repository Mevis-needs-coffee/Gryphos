"""Structured agent decision schemas and the strict response parser.

Every model response is parsed into exactly one of these decision kinds:
`tool_call`, `final`, `clarification`, `error`, `flag` (CTF solving), or
`replan` (CTF solving). Malformed output is rejected safely — it is never
interpreted as a command.
"""

from __future__ import annotations

import json
import re
from typing import Literal

from pydantic import BaseModel, Field, ValidationError, field_validator

SEVERITIES = ("informational", "low", "medium", "high", "critical")
CONFIDENCES = ("low", "medium", "high")


class DecisionParseError(ValueError):
    """Raised when model output cannot be parsed into a valid decision."""

    def __init__(self, message: str, raw: str = ""):
        super().__init__(message)
        self.raw = raw


class Finding(BaseModel):
    title: str = Field(min_length=1, max_length=200)
    severity: Literal["informational", "low", "medium", "high", "critical"] = "informational"
    confidence: Literal["low", "medium", "high"] = "medium"
    detail: str = Field(default="", max_length=4000)
    remediation: str = Field(default="", max_length=4000)

    @field_validator("title", "detail", "remediation", mode="before")
    @classmethod
    def _strip(cls, v: object) -> object:
        return v.strip() if isinstance(v, str) else v


class ToolCallDecision(BaseModel):
    kind: Literal["tool_call"]
    tool: str = Field(min_length=1, max_length=64)
    args: dict[str, object] = Field(default_factory=dict)
    reason: str = Field(default="", max_length=2000)
    hypothesis: str = Field(default="", max_length=500)  # optional working theory (CTF solver)

    @field_validator("reason", "hypothesis", mode="before")
    @classmethod
    def _strip(cls, v: object) -> object:
        return v.strip() if isinstance(v, str) else v


class FinalDecision(BaseModel):
    kind: Literal["final"]
    message: str = Field(min_length=1)
    findings: list[Finding] = Field(default_factory=list)

    @field_validator("message", mode="before")
    @classmethod
    def _strip(cls, v: object) -> object:
        return v.strip() if isinstance(v, str) else v


class ClarificationDecision(BaseModel):
    kind: Literal["clarification"]
    question: str = Field(min_length=1, max_length=2000)

    @field_validator("question", mode="before")
    @classmethod
    def _strip(cls, v: object) -> object:
        return v.strip() if isinstance(v, str) else v


class ErrorDecision(BaseModel):
    kind: Literal["error"]
    message: str = Field(min_length=1, max_length=2000)

    @field_validator("message", mode="before")
    @classmethod
    def _strip(cls, v: object) -> object:
        return v.strip() if isinstance(v, str) else v


class FlagDecision(BaseModel):
    """A proposed flag candidate (CTF solving only).

    The value is only ever a *candidate*: the controller records it and the flag
    verifier decides whether it can be trusted. A proposal is never success.
    """

    kind: Literal["flag"]
    flag: str = Field(min_length=1, max_length=512)
    source: str = Field(default="", max_length=500)
    confidence: Literal["low", "medium", "high"] = "medium"

    @field_validator("flag", "source", mode="before")
    @classmethod
    def _strip(cls, v: object) -> object:
        return v.strip() if isinstance(v, str) else v


class ReplanDecision(BaseModel):
    """A request to replace the remaining task plan (CTF solving only).

    The controller rebuilds the open portion of the plan from these task
    descriptions; superseded open tasks are marked blocked. An empty list is
    rejected so a replan always makes progress.
    """

    kind: Literal["replan"]
    tasks: list[str] = Field(min_length=1, max_length=20)
    reason: str = Field(default="", max_length=2000)

    @field_validator("tasks", mode="before")
    @classmethod
    def _strip_tasks(cls, v: object) -> object:
        if isinstance(v, list):
            cleaned = [item.strip() if isinstance(item, str) else item for item in v]
            if any(c == "" for c in cleaned):
                raise ValueError("replan tasks must be non-empty")
            return cleaned
        return v

    @field_validator("reason", mode="before")
    @classmethod
    def _strip(cls, v: object) -> object:
        return v.strip() if isinstance(v, str) else v


AgentDecision = (
    ToolCallDecision
    | FinalDecision
    | ClarificationDecision
    | ErrorDecision
    | FlagDecision
    | ReplanDecision
)

_FENCE_RE = re.compile(r"^\s*```(?:json)?\s*\n?(.*?)\n?\s*```\s*$", re.DOTALL | re.IGNORECASE)


def extract_json_text(content: str) -> str:
    """Reduce raw model output to the candidate JSON text.

    Handles Markdown fences and surrounding prose. Returns the best candidate
    string; the caller still has to `json.loads` it.
    """
    text = (content or "").strip()
    if not text:
        return ""
    fence = _FENCE_RE.match(text)
    if fence:
        text = fence.group(1).strip()
    try:
        json.loads(text)
        return text
    except json.JSONDecodeError:
        pass
    # Fall back to the outermost brace span.
    start = text.find("{")
    end = text.rfind("}")
    if start != -1 and end > start:
        return text[start : end + 1]
    return text


def parse_decision(content: str) -> AgentDecision:
    """Parse model output into a validated AgentDecision.

    Raises DecisionParseError with a diagnostic (never the API key) when the
    output is malformed or schema-invalid.
    """
    raw = content or ""
    candidate = extract_json_text(raw)
    if not candidate:
        raise DecisionParseError("Model returned an empty response.", raw=raw)
    try:
        value = json.loads(candidate)
    except json.JSONDecodeError as exc:
        raise DecisionParseError(
            f"Model returned malformed JSON (line {exc.lineno}, col {exc.colno}).",
            raw=raw,
        ) from exc
    if not isinstance(value, dict):
        raise DecisionParseError("Model response must be a single JSON object.", raw=raw)
    kind = value.get("kind")
    if kind not in {"tool_call", "final", "clarification", "error", "flag", "replan"}:
        raise DecisionParseError(
            f"Unknown decision kind {kind!r}; expected tool_call, final, "
            "clarification, error, flag, or replan.",
            raw=raw,
        )
    try:
        if kind == "tool_call":
            return ToolCallDecision.model_validate(value)
        if kind == "final":
            return FinalDecision.model_validate(value)
        if kind == "clarification":
            return ClarificationDecision.model_validate(value)
        if kind == "flag":
            return FlagDecision.model_validate(value)
        if kind == "replan":
            return ReplanDecision.model_validate(value)
        return ErrorDecision.model_validate(value)
    except ValidationError as exc:
        problems = "; ".join(
            f"{'.'.join(str(p) for p in err['loc']) or 'value'}: {err['msg']}"
            for err in exc.errors()
        )
        raise DecisionParseError(f"Decision schema invalid — {problems}", raw=raw) from exc
