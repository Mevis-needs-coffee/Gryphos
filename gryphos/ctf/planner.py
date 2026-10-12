"""Persistent task plan for a solve run.

The plan is controller-owned and model-influenced only through explicit,
validated decisions. It records what the solver intends to do, what it has done,
and why a step failed or is blocked, so progress survives across steps and is
persisted in the session (and rendered in the report).
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .models import CATEGORY_GUIDANCE, Challenge, utc_now_iso

TASK_STATUSES: tuple[str, ...] = (
    "pending",
    "running",
    "completed",
    "failed",
    "blocked",
)


@dataclass
class TaskItem:
    id: str
    description: str
    rationale: str = ""
    status: str = "pending"
    note: str = ""
    updated_at: str = field(default_factory=utc_now_iso)

    def __post_init__(self) -> None:
        if self.status not in TASK_STATUSES:
            raise ValueError(
                f"Unknown task status {self.status!r}. "
                f"Expected one of: {', '.join(TASK_STATUSES)}."
            )

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "description": self.description,
            "rationale": self.rationale,
            "status": self.status,
            "note": self.note,
            "updated_at": self.updated_at,
        }


@dataclass
class TaskPlan:
    """An ordered, persistent plan of tasks."""

    items: list[TaskItem] = field(default_factory=list)
    _counter: int = 0

    def add(self, description: str, rationale: str = "", status: str = "pending") -> TaskItem:
        self._counter += 1
        task = TaskItem(
            id=f"T{self._counter}",
            description=description,
            rationale=rationale,
            status=status,
        )
        self.items.append(task)
        return task

    def get(self, task_id: str) -> TaskItem | None:
        return next((t for t in self.items if t.id == task_id), None)

    def set_status(self, task_id: str, status: str, note: str = "") -> TaskItem:
        task = self.get(task_id)
        if task is None:
            raise KeyError(f"No task {task_id!r} in the plan.")
        if status not in TASK_STATUSES:
            raise ValueError(f"Unknown task status {status!r}.")
        task.status = status
        if note:
            task.note = note
        task.updated_at = utc_now_iso()
        return task

    def next_open(self) -> TaskItem | None:
        """Return the running task, else the first pending task."""
        for status in ("running", "pending"):
            for task in self.items:
                if task.status == status:
                    return task
        return None

    def counts(self) -> dict[str, int]:
        out = {status: 0 for status in TASK_STATUSES}
        for task in self.items:
            out[task.status] = out.get(task.status, 0) + 1
        return out

    def replan(self, tasks: list[tuple[str, str]]) -> list[TaskItem]:
        """Supersede the open work with a new task list.

        Every `pending`/`running` task is marked `blocked` (the previous approach
        did not pan out); the new tasks are appended. Completed work is kept.
        """
        for task in self.items:
            if task.status in ("pending", "running"):
                task.status = "blocked"
                task.note = "superseded by replan"
                task.updated_at = utc_now_iso()
        added = [self.add(desc, rationale) for desc, rationale in tasks]
        return added

    def render(self, max_items: int = 40) -> str:
        lines = [f"Task plan ({self.counts()['completed']}/{len(self.items)} completed):"]
        for task in self.items[:max_items]:
            mark = {
                "pending": "[ ]",
                "running": "[~]",
                "completed": "[x]",
                "failed": "[!]",
                "blocked": "[-]",
            }.get(task.status, "[?]")
            line = f"{mark} {task.id}: {task.description}"
            if task.note:
                line += f" ({task.note})"
            lines.append(line)
        if len(self.items) > max_items:
            lines.append(f"… {len(self.items) - max_items} more task(s)")
        return "\n".join(lines)

    def to_dict(self) -> dict:
        return {"items": [t.to_dict() for t in self.items], "counter": self._counter}

    @classmethod
    def from_dict(cls, data: dict) -> TaskPlan:
        plan = cls()
        for item in data.get("items", []):
            plan.items.append(
                TaskItem(
                    id=str(item.get("id", "?")),
                    description=str(item.get("description", "")),
                    rationale=str(item.get("rationale", "")),
                    status=str(item.get("status", "pending")),
                    note=str(item.get("note", "")),
                    updated_at=str(item.get("updated_at", utc_now_iso())),
                )
            )
        plan._counter = int(data.get("counter", len(plan.items)))
        return plan


def build_initial_plan(challenge: Challenge) -> TaskPlan:
    """Deterministic first plan derived from the challenge's declared category."""
    plan = TaskPlan()
    plan.add(
        "Enumerate the provided files and identify each artifact's type.",
        "The solver cannot act on artifacts it has not inspected.",
    )
    plan.add(
        CATEGORY_GUIDANCE.get(challenge.category, "Analyze the artifact for the intended solution."),
        f"Category '{challenge.category}' determines the likely attack.",
    )
    plan.add(
        "Analyze the most promising artifact and record concrete observations.",
        "Observations, not guesses, drive the solution.",
    )
    plan.add(
        "Derive a flag candidate and record its source.",
        "A candidate must be traceable to evidence before it is trusted.",
    )
    plan.add(
        "Verify the flag candidate; only a verified flag counts as solved.",
        "Detected-but-unverified strings are not success.",
    )
    return plan
