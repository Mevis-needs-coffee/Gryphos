"""CTF challenge model, loader, and planner tests (offline)."""

from __future__ import annotations

import json

import pytest

from gryphos.ctf import (
    CHALLENGE_CATEGORIES,
    Challenge,
    ChallengeError,
    TaskPlan,
    discover_challenges,
    load_challenge,
)
from gryphos.ctf.planner import build_initial_plan


def write_challenge(root, cid="warmup", **overrides):
    d = root / cid
    d.mkdir(parents=True)
    manifest = {
        "id": cid,
        "name": "Warmup",
        "category": "misc",
        "description": "A trivial warmup.",
        "task": "Find the flag.",
    }
    manifest.update(overrides)
    (d / "challenge.json").write_text(json.dumps(manifest), encoding="utf-8")
    return d


# --- models -----------------------------------------------------------------

def test_all_nine_categories_declared():
    assert len(CHALLENGE_CATEGORIES) == 9
    for expected in ("misc", "encoding", "crypto", "forensics", "stego", "web",
                     "network", "reverse_engineering", "binary_exploitation"):
        assert expected in CHALLENGE_CATEGORIES


def test_unknown_category_rejected(tmp_path):
    with pytest.raises(ValueError, match="category"):
        Challenge(id="x", name="x", category="not-a-category", root=tmp_path)


def test_unknown_status_rejected(tmp_path):
    with pytest.raises(ValueError, match="status"):
        Challenge(id="x", name="x", category="misc", root=tmp_path, status="weird")


def test_challenge_roundtrip(tmp_path):
    ch = Challenge(id="x", name="X", category="crypto", description="d", task="t",
                   root=tmp_path, flag_format=r"flag\{.*\}")
    data = ch.to_dict()
    back = Challenge.from_dict(data, root=tmp_path)
    assert back.id == "x"
    assert back.category == "crypto"
    assert back.flag_format == r"flag\{.*\}"


# --- loader -----------------------------------------------------------------

def test_load_challenge_lists_files(tmp_path):
    d = write_challenge(tmp_path)
    (d / "notes.txt").write_text("hi", encoding="utf-8")
    (d / "data.bin").write_bytes(b"\x00\x01")
    ch = load_challenge(tmp_path, "warmup")
    assert ch.id == "warmup"
    assert set(ch.files) == {"notes.txt", "data.bin"}
    assert "challenge.json" not in ch.files


def test_load_unknown_challenge(tmp_path):
    with pytest.raises(ChallengeError, match="No challenge"):
        load_challenge(tmp_path, "missing")


def test_load_rejects_traversal_id(tmp_path):
    with pytest.raises(ChallengeError, match="Invalid challenge id"):
        load_challenge(tmp_path, "../../etc")


def test_load_rejects_bad_json(tmp_path):
    d = tmp_path / "broken"
    d.mkdir()
    (d / "challenge.json").write_text("{ not json", encoding="utf-8")
    with pytest.raises(ChallengeError, match="Could not read"):
        load_challenge(tmp_path, "broken")


def test_load_rejects_bad_category(tmp_path):
    write_challenge(tmp_path, "bad", category="nope")
    with pytest.raises(ChallengeError, match="Invalid challenge"):
        load_challenge(tmp_path, "bad")


def test_discover_challenges(tmp_path):
    write_challenge(tmp_path, "a", name="A")
    write_challenge(tmp_path, "b", name="B", category="crypto")
    entries = discover_challenges(tmp_path)
    ids = {e["id"] for e in entries}
    assert ids == {"a", "b"}


def test_discover_missing_dir_returns_empty(tmp_path):
    assert discover_challenges(tmp_path / "nope") == []


# --- planner ----------------------------------------------------------------

def test_initial_plan_has_open_tasks(tmp_path):
    ch = Challenge(id="x", name="X", category="stego", root=tmp_path)
    plan = build_initial_plan(ch)
    assert len(plan.items) >= 3
    assert plan.next_open() is plan.items[0]
    assert plan.counts()["pending"] == len(plan.items)


def test_plan_status_transitions(tmp_path):
    plan = TaskPlan()
    t = plan.add("do a thing")
    plan.set_status(t.id, "running")
    assert plan.next_open() is t
    plan.set_status(t.id, "completed")
    assert plan.next_open() is None
    assert plan.counts()["completed"] == 1


def test_plan_replan_blocks_open_tasks(tmp_path):
    plan = TaskPlan()
    a = plan.add("old approach")
    plan.set_status(a.id, "running")
    b = plan.add("older pending")
    added = plan.replan([("new approach", "because the first failed")])
    assert plan.get(a.id).status == "blocked"
    assert plan.get(b.id).status == "blocked"
    assert added[0].status == "pending"
    assert plan.next_open() is added[0]


def test_plan_unknown_task_raises():
    with pytest.raises(KeyError):
        TaskPlan().set_status("T99", "completed")


def test_plan_render_and_roundtrip():
    plan = TaskPlan()
    task = plan.add("step one", rationale="r")
    plan.set_status(task.id, "completed")
    text = plan.render()
    assert "step one" in text and "[x]" in text
    back = TaskPlan.from_dict(plan.to_dict())
    assert back.items[0].status == "completed"
    assert back.add("next").id == "T2"
