"""Persistent assessment sessions.

Each session records objective, scope snapshot, model, ordered conversation
history, tool proposals, approval decisions, executed actions, raw tool output,
parsed evidence, findings, errors/warnings, the final assessment, and report
paths. Writes are atomic (temp file + os.replace) and size-bounded; secrets are
redacted before anything is persisted. Corrupt, partial, or oversized files are
skipped safely when listing/loading. Loading is strictly read-only: historical
actions are never replayed and historical approvals are never treated as
current authorization.
"""

from __future__ import annotations

import json
import logging
import os
import re
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from .logging_setup import redact

log = logging.getLogger("gryphos.session")

MAX_SESSION_FILE_BYTES = 5 * 1024 * 1024  # hard cap enforced on load and save
MAX_TEXT_CHARS = 20_000  # per string field kept when persisting
MAX_LIST_ITEMS = 500  # most-recent items kept per recorded list
_HARD_TEXT_CHARS = 2_000  # last-resort cap when a record still will not fit
_TRUNCATED = "…[truncated]"
_SESSION_ID_RE = re.compile(r"^s-\d{8}-\d{6}-[0-9a-f]{8}$")

# Recorded lists that are trimmed (oldest first) when a session is too large.
_RECORD_LISTS = (
    "history", "evidence", "tool_runs", "proposals", "approvals", "errors", "findings",
    "flag_candidates",
)


def _clean_string(text: str) -> str:
    """Redact known secret patterns and bound the length of a persisted string."""
    redacted = redact(text)
    if len(redacted) > MAX_TEXT_CHARS:
        return redacted[:MAX_TEXT_CHARS] + _TRUNCATED
    return redacted


def _truncate(text: object) -> object:
    """Bound a single string field to the hard cap (used as a last resort)."""
    if isinstance(text, str) and len(text) > _HARD_TEXT_CHARS:
        return text[:_HARD_TEXT_CHARS] + _TRUNCATED
    return text


def _sanitize(value):
    """Recursively redact secrets and bound string lengths before persistence."""
    if isinstance(value, str):
        return _clean_string(value)
    if isinstance(value, dict):
        return {k: _sanitize(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_sanitize(v) for v in value]
    return value


def utc_now_iso() -> str:
    return datetime.now(UTC).isoformat()


def new_session_id() -> str:
    stamp = datetime.now(UTC).strftime("%Y%m%d-%H%M%S")
    return f"s-{stamp}-{uuid.uuid4().hex[:8]}"


@dataclass
class Session:
    session_id: str
    objective: str
    scope_snapshot: tuple[str, ...]
    model: str
    created_at: str = field(default_factory=utc_now_iso)
    completed_at: str | None = None
    target: str | None = None
    history: list[dict] = field(default_factory=list)
    proposals: list[dict] = field(default_factory=list)
    approvals: list[dict] = field(default_factory=list)
    tool_runs: list[dict] = field(default_factory=list)
    evidence: list[dict] = field(default_factory=list)
    errors: list[dict] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    findings: list[dict] = field(default_factory=list)
    final_assessment: str | None = None
    report_json: str | None = None
    report_markdown: str | None = None
    report_context: dict | None = None
    # Optional CTF solve fields (populated only by the solver; None elsewhere).
    challenge: dict | None = None
    solve_plan: dict | None = None
    flag_candidates: list[dict] = field(default_factory=list)

    def record_history(self, role: str, content: str) -> None:
        self.history.append({"role": role, "content": content, "at": utc_now_iso()})

    def record_evidence(self, item: dict) -> None:
        """Record one ordered evidence item (any kind) in the assessment log."""
        self.evidence.append(item)

    def record_tool_run(self, evidence_item: dict) -> None:
        self.tool_runs.append(evidence_item)

    def record_error(self, source: str, message: str) -> None:
        self.errors.append({"source": source, "message": message, "at": utc_now_iso()})

    def complete(self) -> None:
        self.completed_at = utc_now_iso()

    def _records(self) -> dict:
        """Recorded lists, newest-last, capped to the most recent items."""
        return {
            "history": self.history[-MAX_LIST_ITEMS:],
            "proposals": self.proposals[-MAX_LIST_ITEMS:],
            "approvals": self.approvals[-MAX_LIST_ITEMS:],
            "tool_runs": self.tool_runs[-MAX_LIST_ITEMS:],
            "evidence": self.evidence[-MAX_LIST_ITEMS:],
            "errors": self.errors[-MAX_LIST_ITEMS:],
            "warnings": self.warnings[-MAX_LIST_ITEMS:],
            "findings": self.findings[-MAX_LIST_ITEMS:],
            "flag_candidates": self.flag_candidates[-MAX_LIST_ITEMS:],
        }

    def to_dict(self) -> dict:
        payload = {
            "schema": "gryphos-session/2",
            "session_id": self.session_id,
            "created_at": self.created_at,
            "completed_at": self.completed_at,
            "objective": self.objective,
            "target": self.target,
            "scope_snapshot": list(self.scope_snapshot),
            "model": self.model,
            **self._records(),
            "final_assessment": self.final_assessment,
            "report_json": self.report_json,
            "report_markdown": self.report_markdown,
            "report_context": self.report_context,
            "challenge": self.challenge,
            "solve_plan": self.solve_plan,
        }
        # Redact secrets and bound string lengths before anything is written.
        return _sanitize(payload)

    @classmethod
    def from_dict(cls, data: dict) -> Session:
        """Load a session, tolerating the legacy pre-session format.

        Loading is read-only: historical approvals are restored as inert records
        and are never rebuilt into an active `ApprovalManager`.
        """
        session_id = data.get("session_id") or "legacy-" + str(data.get("started_at", "unknown"))[:19]
        scope = data.get("scope_snapshot") or data.get("target") or ()
        if isinstance(scope, str):
            scope = (scope,)
        # A v2 record has an explicit tool_runs list; the legacy format stores a
        # single flat `evidence` list and no tool_runs key.
        is_v2 = "tool_runs" in data
        raw_evidence = data.get("evidence") or []
        if is_v2:
            tool_runs = data.get("tool_runs") or []
            evidence_stream = raw_evidence
            if not tool_runs:
                # Recover executed actions from the evidence stream if the
                # dedicated list was not persisted separately.
                tool_runs = [e for e in evidence_stream if e.get("kind") == "tool_result"]
            final_text = data.get("final_assessment")
        else:
            # Legacy format: flat evidence list mixing tool results and final text.
            tool_runs = [e for e in raw_evidence if e.get("kind") == "tool_result"]
            final_items = [e for e in raw_evidence if e.get("kind") == "final"]
            final_text = final_items[-1].get("message") if final_items else None
            evidence_stream = raw_evidence
        return cls(
            session_id=session_id,
            objective=data.get("objective", "(unknown)"),
            scope_snapshot=tuple(scope) if scope else (),
            model=data.get("model", "(unknown)"),
            created_at=data.get("created_at") or data.get("started_at") or utc_now_iso(),
            completed_at=data.get("completed_at"),
            target=data.get("target"),
            history=data.get("history") or [],
            proposals=data.get("proposals") or [],
            approvals=data.get("approvals") or [],
            tool_runs=tool_runs,
            evidence=evidence_stream,
            errors=data.get("errors") or [],
            warnings=data.get("warnings") or [],
            findings=data.get("findings") or [],
            final_assessment=final_text,
            report_json=data.get("report_json"),
            report_markdown=data.get("report_markdown"),
            report_context=data.get("report_context"),
            challenge=data.get("challenge"),
            solve_plan=data.get("solve_plan"),
            flag_candidates=data.get("flag_candidates") or [],
        )


class SessionStore:
    """Directory-backed session persistence with atomic writes."""

    def __init__(self, directory: Path):
        self.directory = Path(directory)
        self.directory.mkdir(parents=True, exist_ok=True)

    def _path(self, session_id: str) -> Path:
        return self.directory / f"{session_id}.json"

    def _serialize(self, data: dict) -> str:
        return json.dumps(data, indent=2, default=str)

    def _enforce_size(self, data: dict) -> str:
        """Trim the oldest records until the payload fits, then hard-cap strings.

        Guarantees a bounded, still-valid JSON if at all possible. Never raises on
        size: reliability (a saved session) is preferred over completeness.
        """
        payload = self._serialize(data)
        if len(payload.encode("utf-8")) <= MAX_SESSION_FILE_BYTES:
            return payload
        for _ in range(MAX_LIST_ITEMS * len(_RECORD_LISTS) + 50):
            if len(payload.encode("utf-8")) <= MAX_SESSION_FILE_BYTES:
                return payload
            growable = [k for k in _RECORD_LISTS if data.get(k)]
            if not growable:
                break
            key = max(growable, key=lambda k: len(data[k]))
            data[key] = data[key][1:]  # drop the oldest entry
            payload = self._serialize(data)
        # Last resort: shrink strings and drop the (regenerable) report context.
        data["report_context"] = None
        data["final_assessment"] = _truncate(data.get("final_assessment"))
        payload = self._serialize(data)
        log.warning("Session exceeded size limit after trimming; stored a reduced record.")
        return payload

    def save(self, session: Session) -> Path:
        path = self._path(session.session_id)
        payload = self._enforce_size(session.to_dict())
        tmp = path.with_suffix(".json.tmp")
        try:
            tmp.write_text(payload, encoding="utf-8")
            os.replace(tmp, path)  # atomic on the same filesystem
        except OSError:
            try:
                if tmp.exists():
                    tmp.unlink()
            except OSError:
                pass
            raise
        return path

    def list_sessions(self) -> list[dict]:
        """List loadable sessions, newest first. Corrupt files are skipped."""
        entries: list[dict] = []
        for path in sorted(self.directory.glob("*.json"), reverse=True):
            if path.name.endswith(".json.tmp"):
                continue
            try:
                if path.stat().st_size > MAX_SESSION_FILE_BYTES:
                    log.warning("Skipping oversized session file %s", path.name)
                    continue
                data = json.loads(path.read_text(encoding="utf-8"))
                if not isinstance(data, dict):
                    raise ValueError("not a JSON object")
            except (OSError, ValueError) as exc:
                log.warning("Skipping unreadable session file %s: %s", path.name, exc)
                entries.append({
                    "session_id": path.stem,
                    "created_at": "(unreadable)",
                    "objective": f"corrupt or unreadable file: {type(exc).__name__}",
                    "path": str(path),
                    "corrupt": True,
                })
                continue
            entries.append({
                "session_id": data.get("session_id", path.stem),
                "created_at": data.get("created_at") or data.get("started_at", "?"),
                "objective": data.get("objective", "(unknown)"),
                "target": data.get("target"),
                "model": data.get("model"),
                "path": str(path),
                "corrupt": False,
            })
        return entries

    def load(self, session_id: str) -> Session:
        """Load one session. Raises FileNotFoundError/ValueError on problems."""
        if (
            not _SESSION_ID_RE.match(session_id)
            and not session_id.startswith("legacy-")
            and not re.match(r"^[A-Za-z0-9._-]+$", session_id)
        ):
            # Allow legacy report stems too (session-YYYYMMDD-HHMMSS).
            raise ValueError("Invalid session id.")
        path = self._path(session_id)
        if not path.exists():
            # Legacy report files use a different stem.
            legacy = self.directory / f"{session_id}.json"
            if legacy.exists():
                path = legacy
            else:
                raise FileNotFoundError(f"No session named {session_id!r}.")
        if path.stat().st_size > MAX_SESSION_FILE_BYTES:
            raise ValueError(f"Session file {path.name} exceeds the size limit.")
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ValueError(f"Session file {path.name} is corrupt: {exc}") from exc
        if not isinstance(data, dict):
            raise ValueError(f"Session file {path.name} is corrupt: not a JSON object.")
        return Session.from_dict(data)
