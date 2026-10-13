"""CTF challenge, task-plan, and flag records.

These are controller-owned data structures. They never contain model-authored
commands; they describe an explicitly configured challenge and the recorded
progress toward solving it. The model only ever sees a bounded rendering of
these objects and can only propose structured decisions against them.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from .webconfig import WebConfig, WebConfigError

# The nine challenge families the solver understands. A challenge must declare
# exactly one; the category seeds the initial task plan and the solver prompt.
CHALLENGE_CATEGORIES: tuple[str, ...] = (
    "misc",
    "encoding",
    "crypto",
    "forensics",
    "stego",
    "web",
    "network",
    "reverse_engineering",
    "binary_exploitation",
)

# One-line description used in the plan seed and the solver system prompt.
CATEGORY_GUIDANCE: dict[str, str] = {
    "misc": "mixed puzzle; identify the artifact and the intended transformation.",
    "encoding": "recognize and reverse text/byte encodings (base64, hex, rot, etc.).",
    "crypto": "recover plaintext from ciphertext; avoid brute force without a plan.",
    "forensics": "recover data from a provided artifact (image, pcap, archive, memory).",
    "stego": "find data hidden inside another file; look for appended/embedded payloads.",
    "web": "analyze a local/authorized web challenge description and provided files.",
    "network": "analyze a provided capture or network description; no live scanning.",
    "reverse_engineering": "understand a provided binary/source artifact's behavior.",
    "binary_exploitation": "analyze a provided artifact for the intended memory flaw.",
}

# Challenge lifecycle, from configuration to terminal state.
CHALLENGE_STATUSES: tuple[str, ...] = (
    "pending",
    "running",
    "solved",
    "unsolved",
    "failed",
)

# A single flag-candidate verification state. Only "verified" means success.
FLAG_STATUSES: tuple[str, ...] = (
    "unverified",  # recorded, not yet checked
    "format_invalid",  # failed the heuristic format gate
    "incorrect",  # checked and rejected
    "verified",  # confirmed by a verifier
)


def utc_now_iso() -> str:
    return datetime.now(UTC).isoformat()


@dataclass
class FlagCandidate:
    """One proposed flag value and the outcome of its verification."""

    value: str
    source: str = ""
    confidence: str = "medium"  # low | medium | high
    status: str = "unverified"
    verifier: str = ""
    detail: str = ""
    detected_at: str = field(default_factory=utc_now_iso)

    def to_dict(self) -> dict:
        return {
            "value": self.value,
            "source": self.source,
            "confidence": self.confidence,
            "status": self.status,
            "verifier": self.verifier,
            "detail": self.detail,
            "detected_at": self.detected_at,
        }


@dataclass
class Hypothesis:
    """A candidate explanation the solver is testing, with its evidence."""

    statement: str
    status: str = "active"  # active | confirmed | refuted
    evidence: list[str] = field(default_factory=list)
    created_at: str = field(default_factory=utc_now_iso)

    def to_dict(self) -> dict:
        return {
            "statement": self.statement,
            "status": self.status,
            "evidence": list(self.evidence),
            "created_at": self.created_at,
        }


@dataclass
class Challenge:
    """An explicitly configured, self-contained CTF challenge.

    `root` is the challenge directory. Every file the solver reads must resolve
    inside it; the controller enforces that at execution time.
    """

    id: str
    name: str
    category: str
    description: str = ""
    task: str = ""
    root: Path = field(default_factory=lambda: Path("."))
    flag_format: str | None = None  # optional regex; None uses the default matcher
    submit: dict | None = None  # optional CTFd-style {"url","token","field"}
    files: tuple[str, ...] = ()
    web: WebConfig | None = None  # optional authorized web origin (Phase 3)
    status: str = "pending"

    def __post_init__(self) -> None:
        self.root = Path(self.root)
        if self.category not in CHALLENGE_CATEGORIES:
            raise ValueError(
                f"Unknown challenge category {self.category!r}. "
                f"Expected one of: {', '.join(CHALLENGE_CATEGORIES)}."
            )
        if self.status not in CHALLENGE_STATUSES:
            raise ValueError(
                f"Unknown challenge status {self.status!r}. "
                f"Expected one of: {', '.join(CHALLENGE_STATUSES)}."
            )

    @property
    def guidance(self) -> str:
        return CATEGORY_GUIDANCE.get(self.category, "")

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "category": self.category,
            "description": self.description,
            "task": self.task,
            "root": str(self.root),
            "flag_format": self.flag_format,
            "submit": dict(self.submit) if self.submit else None,
            "files": list(self.files),
            "web": self.web.to_dict() if self.web else None,
            "status": self.status,
        }

    @classmethod
    def from_dict(cls, data: dict, root: Path) -> Challenge:
        web: WebConfig | None = None
        if data.get("web") is not None:
            try:
                web = WebConfig.from_dict(data["web"])
            except WebConfigError as exc:
                raise ValueError(f"invalid web block: {exc}") from exc
        return cls(
            id=str(data["id"]).strip(),
            name=str(data.get("name") or data["id"]).strip(),
            category=str(data.get("category", "")).strip(),
            description=str(data.get("description", "")),
            task=str(data.get("task", "")),
            root=Path(root),
            flag_format=data.get("flag_format") or None,
            submit=data.get("submit") or None,
            files=tuple(str(f) for f in (data.get("files") or [])),
            web=web,
            status=str(data.get("status", "pending")),
        )
