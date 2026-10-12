# Gryphos — Autonomous CTF Solver (Phase 1)

Extends Gryphos from an approval-based assessment assistant into a bounded,
autonomous solver for explicitly configured CTF challenges. Phase 1 implements
the full solve pipeline; remote flag submission and cross-challenge persistence
are the only explicitly deferred parts.

## Scope of work

Preserve every existing feature and all 271 passing tests. Add a dedicated
`gryphos/ctf/` package, a `solve` CLI command, structured session extensions, a
CTF report, and an offline test suite. The solver reuses the existing trust
boundaries: the model is untrusted, tool calls are validated by application
code, scope is enforced at execution time, and every decision is one of the
strictly validated kinds (plus a new `flag` kind).

## Phase 1 implementation checklist

- [x] `gryphos/ctf/models.py` — Challenge model (id, name, category, description,
      task, root, flag format, optional CTFd-style submit config, provided files),
      9 categories (misc, encoding, crypto, forensics, stego, web, network,
      reverse_engineering, binary_exploitation), status lifecycle, solution
      record, task-item / hypothesis / observation records.
- [x] `gryphos/models.py` — new `FlagDecision` (`kind: "flag"`, `flag`, `source`,
      `confidence`) and `parse_decision` support for the `flag` kind.
- [x] `gryphos/ctf/loader.py` — `challenges/<id>/challenge.json` loader with
      validation, file listing, path confinement, strict category checking.
- [x] `gryphos/ctf/planner.py` — persistent task plan (pending/running/completed/
      failed/blocked), initial plan from the challenge spec, status transitions,
      replanning hooks, serializable summary for session/report/prompt.
- [x] `gryphos/ctf/flag.py` — flag-format model, candidate detection from tool
      output, heuristic verifier (default, offline: keyword + length + charset),
      optional HTTP verifier (CTFd-style, only when configured + enabled), each
      result records status (`verified`/`incorrect`/`format_invalid`/
      `unverified`), verifier name, and evidence.
- [x] `gryphos/ctf/tools.py` — solver tool registry built on `ToolSpec`/`ToolResult`/
      `validate_args`: a read-only `challenge_file` tool (bounded, confined to the
      challenge root, no shell, no traversal) plus the offline
      `summarize_evidence` lens. The main assessment registry is untouched.
- [x] `gryphos/ctf/solver.py` — bounded autonomous loop: step limit, wall-clock
      budget, per-tool timeout/output bounds, canonical-fingerprint
      anti-repetition (actions and flag candidates), consecutive-failure abort,
      transient-LLM resume, hypotheses/evidence/techniques/errors recording, task
      plan updates, flag detection + verification, graceful stops with a digest,
      and a final report.
- [x] `gryphos/session.py` — optional `challenge`, `solve_plan`, `flag_candidates`
      fields (backward-compatible load, redacted and bounded like everything else).
- [x] `gryphos/config.py` — `GRYPHOS_CTF_CHALLENGES_DIR`, `GRYPHOS_CTF_MAX_STEPS`,
      `GRYPHOS_CTF_REMOTE_VERIFY` (bounded-int/bool-style settings, safe defaults).
- [x] `gryphos/cli.py` — `solve <challenge-id>` command (loads the challenge,
      runs the solver, writes the CTF report, persists the session) wired into
      the command table and `help`.
- [x] `gryphos/reporting.py` (or `gryphos/ctf/report.py`) — CTF Markdown report:
      challenge summary, task plan with statuses, hypotheses/evidence,
      techniques tried, errors/warnings, flag candidates with verification
      status, and an honest conclusion ("solved"/"unsolved — state that the flag
      was not proven"). Never claims success without verified evidence.
- [x] Safety invariant for the loop: the solver only ever acts on the configured
      challenge (its own directory + the configured tools); it never infers
      targets, never runs arbitrary shell, treats all file contents as untrusted,
      and refuses to record a solved flag without a verifier result.
- [x] Offline tests under `tests/test_ctf_*.py`: planning, replanning, tool
      selection, failure recovery, repeated-action rejection, budget exhaustion,
      flag detection, verifier results, persistence, out-of-scope path traversal.
- [x] Docs: update `docs/ARCHITECTURE.md` and this plan; keep `README.md` in sync.
      Run the full suite + Ruff.

## Explicitly deferred (Phase 2+)

- Remote/CTFd submission beyond the optional, config-gated HTTP verifier.
- Challenge-progress caching, "unlock" dependency graphs, and scoring.
- Reverse/exploit tool classes that execute target-provided programs.