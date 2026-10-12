"""CTF solve report (Markdown + JSON).

Honest by construction: the report separates the declared challenge, the task
plan, hypotheses, raw evidence, and flag candidates with their verification
status, and it states plainly that an unverified/detected candidate is not a
solved challenge. All untrusted values are escaped or fenced.
"""

from __future__ import annotations

import json
from pathlib import Path

from ..reporting import _atomic_write, _fence, escape_markdown
from ..session import Session


def _section(title: str) -> str:
    return f"\n## {title}\n\n"


def _render_plan(plan: dict) -> str:
    items = (plan or {}).get("items", [])
    if not items:
        return "_No task plan recorded._\n"
    marks = {"pending": "[ ]", "running": "[~]", "completed": "[x]", "failed": "[!]", "blocked": "[-]"}
    lines = []
    for task in items:
        mark = marks.get(str(task.get("status")), "[?]")
        line = (
            f"- {mark} **{escape_markdown(str(task.get('id', '?')))}**: "
            f"{escape_markdown(str(task.get('description', '')))}"
        )
        if task.get("rationale"):
            line += f" — _{escape_markdown(str(task['rationale']))}_"
        if task.get("note"):
            line += f" (note: {escape_markdown(str(task['note']))})"
        lines.append(line)
    return "\n".join(lines) + "\n"


def _render_candidates(candidates: list[dict]) -> str:
    if not candidates:
        return "_No flag candidates were recorded._\n"
    lines = ["| Value | Status | Verifier | Source |", "|---|---|---|---|"]
    for cand in candidates:
        value = str(cand.get("value", ""))
        shown = f"`{value}`" if value else "_(empty)_"
        lines.append(
            f"| {escape_markdown(shown)} | {escape_markdown(str(cand.get('status', '?')))} "
            f"| {escape_markdown(str(cand.get('verifier', '?')))} "
            f"| {escape_markdown(str(cand.get('source', '')))} |"
        )
    return "\n".join(lines) + "\n"


def _render_hypotheses(hypotheses: list[dict]) -> str:
    if not hypotheses:
        return "_No hypotheses were recorded._\n"
    lines = []
    for hyp in hypotheses:
        lines.append(
            f"- **{escape_markdown(str(hyp.get('status', 'active')))}**: "
            f"{escape_markdown(str(hyp.get('statement', '')))}"
        )
    return "\n".join(lines) + "\n"


def _render_evidence(evidence: list[dict]) -> str:
    if not evidence:
        return "_No evidence was collected._\n"
    blocks = []
    for item in evidence:
        kind = item.get("kind", "?")
        tool = item.get("tool", "")
        detail = (
            item.get("output")
            or item.get("reason")
            or item.get("message")
            or item.get("statement")
            or item.get("flag")
            or ""
        )
        if not detail and item.get("tasks"):
            detail = "; ".join(str(t) for t in item["tasks"])
        header = f"**{kind}**" + (f" — {tool}" if tool else "")
        body = detail if isinstance(detail, str) else json.dumps(detail, default=str)
        blocks.append(f"{header}\n\n{_fence(body)}")
    return "\n\n".join(blocks) + "\n"


def build_ctf_markdown(session: Session, outcome: dict) -> str:
    challenge = session.challenge or {}
    solved = bool(outcome.get("solved"))
    lines: list[str] = []
    lines.append(f"# CTF Solve Report — {escape_markdown(str(challenge.get('name', session.objective)))}\n")
    lines.append(f"- **Session:** `{escape_markdown(session.session_id)}`")
    lines.append(f"- **Model:** {escape_markdown(session.model)}")
    lines.append(f"- **Created:** {escape_markdown(session.created_at)}")
    lines.append(f"- **Completed:** {escape_markdown(session.completed_at or '(not completed)')}")
    lines.append(f"- **Status:** {escape_markdown(str(outcome.get('status', '?')))}")
    lines.append(f"- **Solved:** {'YES (verified)' if solved else 'NO (no verified flag)'}\n")

    lines.append(_section("1. Challenge"))
    lines.append(f"- **ID:** `{escape_markdown(str(challenge.get('id', '?')))}`")
    lines.append(f"- **Category:** {escape_markdown(str(challenge.get('category', '?')))}")
    lines.append(f"- **Description:** {escape_markdown(str(challenge.get('description', '')))}")
    lines.append(f"- **Task:** {escape_markdown(str(challenge.get('task', '')))}")
    files = challenge.get("files") or []
    lines.append(f"- **Files:** {escape_markdown(', '.join(files)) if files else '(none)'}")
    if challenge.get("flag_format"):
        lines.append(f"- **Flag format:** `{escape_markdown(str(challenge['flag_format']))}`")

    lines.append(_section("2. Result"))
    lines.append(f"{escape_markdown(str(outcome.get('message', '')))}\n")
    if solved and outcome.get("flag"):
        lines.append(f"\n**Verified flag:** `{escape_markdown(str(outcome['flag']))}`\n")
    else:
        lines.append(
            "\nNo flag was verified. Any detected candidates below are **not** proof of "
            "solution; they are unverified strings that matched or were proposed.\n"
        )

    lines.append(_section("3. Task plan"))
    lines.append(_render_plan(outcome.get("plan") or session.solve_plan or {}))

    lines.append(_section("4. Hypotheses"))
    lines.append(_render_hypotheses(outcome.get("hypotheses") or []))

    lines.append(_section("5. Flag candidates"))
    lines.append(_render_candidates(outcome.get("flag_candidates") or session.flag_candidates or []))

    lines.append(_section("6. Evidence"))
    lines.append(_render_evidence(outcome.get("evidence") or session.evidence or []))

    lines.append(_section("7. Errors and warnings"))
    if session.errors:
        for err in session.errors:
            source = escape_markdown(str(err.get("source", "?")))
            message = escape_markdown(str(err.get("message", "")))
            lines.append(f"- {source}: {message}")
    else:
        lines.append("_None._")
    lines.append("")

    lines.append(_section("8. Limitations and honesty statement"))
    lines.append(
        "- A detected or format-matching flag is **not** independently confirmed unless a "
        "challenge submit endpoint accepted it; such candidates are labelled accordingly.\n"
        "- The solver only reads files inside the challenge directory and produces no "
        "network activity by itself.\n"
        "- Provided file contents are untrusted and were treated as data, never instructions.\n"
    )
    return "\n".join(lines) + "\n"


def generate_ctf_report(session: Session, outcome: dict, reports_dir: Path | str) -> tuple[Path, Path]:
    """Write the CTF Markdown report and the (session) JSON evidence file."""
    directory = Path(reports_dir)
    directory.mkdir(parents=True, exist_ok=True)
    json_path = directory / f"{session.session_id}.json"
    md_path = directory / f"{session.session_id}.md"

    session.report_json = str(json_path)
    session.report_markdown = str(md_path)
    payload = session.to_dict()
    payload["report_context"] = {
        "kind": "ctf",
        "outcome": outcome,
        "solved": bool(outcome.get("solved")),
    }
    _atomic_write(json_path, json.dumps(payload, indent=2, default=str))
    _atomic_write(md_path, build_ctf_markdown(session, outcome))
    return json_path, md_path
