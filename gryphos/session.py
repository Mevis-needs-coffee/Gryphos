"""Persistent assessment sessions.

Each session records objective, scope snapshot, model, conversation history,
proposals, approvals, tool executions, findings, errors, and the final
assessment. Writes are atomic (temp file + os.replace). Corrupt or partial
files are skipped safely when listing/loading. Historical approvals are never
replayed: loading a session is read-only.
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

log = logging.getLogger("gryphos.session")

MAX_SESSION_FILE_BYTES = 5 * 1024 * 1024  # skip absurdly large files on load
_SESSION_ID_RE = re.compile(r"^s-\d{8}-\d{6}-[0-9a-f]{8}$")


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
    errors: list[dict] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    findings: list[dict] = field(default_factory=list)
    final_assessment: str | None = None
    report_json: str | None = None
    report_markdown: str | None = None

    def record_history(self, role: str, content: str) -> None:
        self.history.append({"role": role, "content": content, "at": utc_now_iso()})

    def record_tool_run(self, evidence_item: dict) -> None:
        self.tool_runs.append(evidence_item)

    def record_error(self, source: str, message: str) -> None:
        self.errors.append({"source": source, "message": message, "at": utc_now_iso()})

    def complete(self) -> None:
        self.completed_at = utc_now_iso()

    def to_dict(self) -> dict:
        return {
            "schema": "gryphos-session/2",
            "session_id": self.session_id,
            "created_at": self.created_at,
            "completed_at": self.completed_at,
            "objective": self.objective,
            "target": self.target,
            "scope_snapshot": list(self.scope_snapshot),
            "model": self.model,
            "history": self.history,
            "proposals": self.proposals,
            "approvals": self.approvals,
            "tool_runs": self.tool_runs,
            "errors": self.errors,
            "warnings": self.warnings,
            "findings": self.findings,
            "final_assessment": self.final_assessment,
            "report_json": self.report_json,
            "report_markdown": self.report_markdown,
        }

    @classmethod
    def from_dict(cls, data: dict) -> Session:
        """Load a session, tolerating the legacy pre-session format."""
        session_id = data.get("session_id") or "legacy-" + str(data.get("started_at", "unknown"))[:19]
        scope = data.get("scope_snapshot") or data.get("target") or ()
        if isinstance(scope, str):
            scope = (scope,)
        tool_runs = data.get("tool_runs") or []
        evidence = data.get("evidence") or []
        if not tool_runs and evidence:
            # Legacy format: flat evidence list mixing tool results and final text.
            tool_runs = [e for e in evidence if e.get("kind") == "tool_result"]
            final_items = [e for e in evidence if e.get("kind") == "final"]
            final_text = final_items[-1].get("message") if final_items else None
        else:
            final_text = data.get("final_assessment")
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
            errors=data.get("errors") or [],
            findings=data.get("findings") or [],
            final_assessment=final_text,
            report_json=data.get("report_json"),
            report_markdown=data.get("report_markdown"),
        )


class SessionStore:
    """Directory-backed session persistence with atomic writes."""

    def __init__(self, directory: Path):
        self.directory = Path(directory)
        self.directory.mkdir(parents=True, exist_ok=True)

    def _path(self, session_id: str) -> Path:
        return self.directory / f"{session_id}.json"

    def save(self, session: Session) -> Path:
        path = self._path(session.session_id)
        payload = json.dumps(session.to_dict(), indent=2, default=str)
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
