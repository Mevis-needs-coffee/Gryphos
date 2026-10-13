"""Autonomous CTF solving (Phase 1).

A dedicated, bounded solver for explicitly configured challenges. It reuses the
project's trust boundaries (untrusted model, controller-validated tool calls,
execution-time scope checks) and adds a challenge model, a persistent task plan,
flag detection/verification, and a CTF report.

Public surface (stable for the CLI and tests):
    Challenge, CHALLENGE_CATEGORIES, FlagCandidate
    load_challenge, discover_challenges
    TaskPlan, TaskItem, Hypothesis
    FlagFormat, detect_flags, verify_flag, HeuristicFlagVerifier
    Solver, SolveOutcome, run_solver
"""

from __future__ import annotations

from .flag import (
    FlagFormat,
    FlagVerdict,
    HeuristicFlagVerifier,
    detect_flags,
    verify_flag,
)
from .loader import ChallengeError, discover_challenges, load_challenge
from .models import CHALLENGE_CATEGORIES, Challenge, FlagCandidate, Hypothesis
from .netconfig import TargetConfig, TargetConfigError
from .planner import TaskItem, TaskPlan
from .solver import SolveOutcome, Solver, run_solver
from .webconfig import WebConfig, WebConfigError

__all__ = [
    "CHALLENGE_CATEGORIES",
    "Challenge",
    "ChallengeError",
    "FlagCandidate",
    "FlagFormat",
    "FlagVerdict",
    "HeuristicFlagVerifier",
    "Hypothesis",
    "SolveOutcome",
    "Solver",
    "TargetConfig",
    "TargetConfigError",
    "TaskItem",
    "TaskPlan",
    "WebConfig",
    "WebConfigError",
    "detect_flags",
    "discover_challenges",
    "load_challenge",
    "run_solver",
    "verify_flag",
]
