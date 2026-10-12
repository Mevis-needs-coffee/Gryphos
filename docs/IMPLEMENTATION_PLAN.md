# Gryphos — Implementation Plan

## Audit of the existing repository (Phase 0)

Inspected 2026-10-10. The repository is a small working starter:

| File | State |
|---|---|
| `main.py` | Typer app + interactive REPL; commands: help, models, model, scope, assess, exit. Report writing inlined in the REPL. |
| `gryphos/config.py` | `Settings` dataclass from env; numeric parsing crashes with a raw `ValueError` on garbage input; no API base/timeout/retry settings. |
| `gryphos/llm.py` | OpenRouter client via `openai`; `list_models()`; `decide()` returns raw dict; JSON parsing handles fences and prose; error handling covers auth/rate-limit/generic APIError only (no 400/403/timeout/context-length distinction); no catalog caching; no model-ID validation. |
| `gryphos/agent.py` | Bounded loop (max steps), approval via `Confirm` (default no), duplicate nmap detection, scope re-check of proposed target. |
| `gryphos/scope.py` | `ipaddress`-based; literal IP only; CIDR scope membership check. Works correctly. |
| `gryphos/tools.py` | Single tool `nmap_basic` with fixed argv, `shell=False`, timeout, output truncation. Works correctly. |
| `requirements.txt` | openai, python-dotenv, rich, typer, requests — all installed in `.venv` (Python 3.14.7). pytest added as dev dependency. pydantic 2.14 present transitively via openai; used for decision schemas. |
| `reports/` | Three prior sessions (old flat format: started_at/model/objective/target/evidence). Must be preserved and remain loadable. |
| `.env` | Exists locally with a live key. Never overwrite, never log, never commit (already gitignored). |
| Git | Not a git repository on this filesystem. |

Baseline verification: modules import, `validate_target` accepts `127.0.0.1` and rejects hostnames and out-of-scope IPs; nmap 7.99 present at `/usr/bin/nmap`. No automated tests existed.

### Actual defects / gaps found

1. `config.py` crashes on non-numeric env values; no configurable API base, request timeout, retries, time budget, or catalog cache.
2. `llm.py` accepts any `provider/model` string as a model; no catalog validation, no caching, no distinction between 400/401/403/429/5xx/timeout/context-length errors.
3. Decision parsing raises `RuntimeError` for everything; no `clarification`/`error` decision kinds; no bounded repair retry.
4. `agent.py` has no total time budget, no consecutive-failure abort, no clarification flow, no session persistence, hard-coded to `nmap_basic`, approval is not fingerprinted to exact arguments (a model could change args after approval within the same prompt shape — currently mitigated only because args are fixed, but the new multi-tool world needs fingerprints).
5. CLI rejects ordinary conversational input with `Unknown command`; missing `clear`, `status`, `sessions`, `history`, `report`, `config`, `tools`; report generation is inlined and omits approvals, findings structure, limitations.
6. No sessions module, no atomic writes, no corrupt-file handling, no way to list/inspect past sessions.
7. No logging/observability, no secret redaction helpers.
8. No tests, no architecture documentation.

## Ordered implementation checklist

- [x] P0: audit, this plan
- [x] P1a: `config.py` — safe numeric parsing with bounds, new settings (api_base, request_timeout, max_retries, time_budget, catalog_cache_ttl), never print secrets
- [x] P1b: `llm.py` — model catalog fetch + in-memory TTL cache, exact-ID selection with validation and last-known-good preservation, classified API errors, structured `decide()` returning typed decisions, bounded JSON repair retry
- [x] P2a: `models.py` — Pydantic decision schema (`tool_call`/`final`/`clarification`/`error`), strict JSON extraction parser (fences, prose, malformed rejection)
- [x] P2b: `agent.py` — bounded loop with step limit, total time budget, duplicate-call fingerprints, consecutive-failure abort, clarification prompts, refusal/cancel handling, session recording hooks, registry-only tool dispatch
- [x] P4/P5a: `gryphos/tools.py` — `ToolSpec` registry (name, purpose, schema, network_active, side effects, timeout, output limit, risk, approval policy, executor); preserved `nmap_basic`; new `http_headers`, `tls_cert`, `http_redirects`, `summarize_evidence` (passive); every network tool enforces literal-IP scope; URL policy = literal in-scope IP only; manual redirect hops each re-validated
- [x] P12 (Phase Four): modular `gryphos/tools/` package — split `tools.py` into `base.py` (interfaces, validation, bounded process runner), `net.py` (shared bound HTTP/TLS helpers), one module per tool, and `registry.py`; each tool declares name/description/purpose/input schema/scope requirements/risk/passive-active/network activity/timeout/output limit/approval policy/side effects/result schema/executor/exact-action display; added passive tools `local_ports`, `local_audit`, `source_scan`, `dependency_audit`, `secret_detect` (secret values redacted and never retained); added active `web_tech` (bounded, results labelled inferred); unknown tool names rejected, model can never name an executable or build a command
- [x] P13 (Phase Four): `gryphos/analysis.py` — Tool 10 offline evidence analysis: `normalize_observations`, `correlate`, `detect_contradictions`, `compare_sessions`, and the passive `summarize_evidence` spec; `reporting.py` surfaces correlation (§7a) and contradictions (§7b) in Markdown and JSON; `scope.py` gains `classify_ip` reserved-address diagnostics; `tools/__init__.py` re-exports the stable legacy API
- [x] P5b: `approval.py` — approval requests with SHA-256 fingerprints over canonical (tool, args, target), default deny, single use, new approval required when any security-relevant arg changes
- [x] P5c: `scope.py` — IPv4/IPv6 deliberate handling, normalization, ambiguity rejection, URL authorization helper
- [x] P14 (Phase Five): approval + scope enforcement — `approval.py` gains a risk-based policy (levels 0-4, `requires_approval`, `level_allowed`, `level_name`/`level_purpose`/`level_impact`, `ApprovalRequest.approval_level`); `ToolSpec.approval_level` with consistency validation and a registry gated by `GRYPHOS_MAX_APPROVAL_LEVEL` (default 3, level 4 disabled); new Level 3 `tcp_banner` (single connect, unprompted banner only, connected peer re-validated); `scope.py` gains `ScopeManager` (baseline/effective + change history, expansion requires the explicit `EXPAND-SCOPE` operator token), `is_subset`, `describe_change`, `resolve_and_validate`, and `validate_connected_peer`; URL/TCP tools re-validate every redirect hop and the connected peer; agent rejects tools above the ceiling and renders level name/purpose/impact in the approval prompt (default no); CLI `scope`/`scope narrow`/`scope set`/`scope reset` with token-guarded expansion and effective-scope wiring
- [x] P15 (Phase Six): session memory — sessions persist id, timezone-aware timestamps, objective, model, scope snapshot, ordered conversation history, tool proposals, approval decisions, executed actions + actual output, the full ordered evidence stream (`Session.evidence`), parsed `data`, findings, errors/warnings, final analysis, report paths, and `report_context`; `save` is atomic, **size-bounded** (most-recent list caps, per-string caps, oldest-first trimming), and **redacts secrets** before writing; `reporting` emits the session record itself as `<id>.json` so store and report writers never clobber each other; corrupt/oversized/legacy files load safely; loading is strictly read-only (no replay, no approval revival); CLI adds `inspect <id>` (read-only); `registry.py` lazy-imports `summarize_evidence_spec` to break a pre-existing import cycle
- [x] P16 (Phase Eight): agent reasoning + evidence correlation — the system prompt brands a **reasoning discipline** (understand the objective → check the confirmed evidence first → name the specific missing information → choose the least intrusive useful step → justify it → conclude honestly); the agent injects a deterministic **`confirmed_evidence` digest** (`analysis.summarize_evidence` offline, no re-execution) into every `decide` payload so steps and finals are grounded in recorded facts; tool proposals with an **empty justification (`reason`) are rejected** by the controller before validation/approval/execution; the loop **resumes on bounded transient API failures** (rate_limit/timeout/connection/server_error, ≤2 resumptions, recorded as session warnings) and otherwise concludes safely with an **evidence-based fallback final** — a deterministic digest labelled "not an AI interpretation" that says plainly when nothing can be concluded; early stops (`steps_exhausted`/`time_budget`/failure-streak abort) now include the collected-evidence digest and write `final_assessment`
- [x] P17 (Phase Nine): professional reporting — consistent 12-section Markdown + JSON singleton; **every dynamic value is Markdown-escaped** (`escape_markdown`: `\`, backticks, `[`/`]`, `<`/`>` escaped, newlines collapsed; `escape_code` for code spans; multi-line prose rendered as a longer always-safe fence) so hostile banners/headers/model responses cannot inject links, code spans, HTML, or forged structure; the report explicitly states an absence of open ports on a bounded probe does **not** mean the system is secure, asserts no CVE identifiers/affected versions, and labels findings as **unverified hypotheses** — separating observed facts, model interpretations, potential risks, and checks not performed; sections carry severity/confidence, remediation, timestamps, session ID, and the raw tool evidence, not only a model summary
- [x] P18 (Phase Ten — CTF Phase 1): autonomous CTF solving — new `gryphos/ctf/` package: `models.py` (Challenge across 9 categories, status lifecycle, `FlagCandidate`, `Hypothesis`), `loader.py` (`challenges/<id>/challenge.json`, id/path confinement, discovery), `planner.py` (persistent `TaskPlan`/`TaskItem` with pending/running/completed/failed/blocked and `replan`), `flag.py` (`FlagFormat`, `detect_flags`, offline `HeuristicFlagVerifier`, opt-in `HttpFlagVerifier`, `verify_flag`), `tools.py` (confined read-only `challenge_file` + `summarize_evidence`, separate from the assessment registry), `solver.py` (bounded loop: step/wall-clock/tool/output limits, canonical fingerprints for actions and flag candidates, consecutive-failure abort, bounded transient-LLM resume, hypotheses/evidence recording, graceful stops) and `report.py` (honest CTF report); new `FlagDecision` (`kind:"flag"`) and `ReplanDecision` (`kind:"replan"`) plus an optional `hypothesis` on tool calls, all accepted by `parse_decision`; optional `challenge`/`solve_plan`/`flag_candidates` on `Session`; config `GRYPHOS_CTF_CHALLENGES_DIR`, `GRYPHOS_CTF_MAX_STEPS`, `GRYPHOS_CTF_REMOTE_VERIFY`; CLI `solve <id>` (lists challenges with no id) writing the CTF report and persisting the session. A challenge is only reported solved when a verifier accepts a flag; detection is never success.
- [x] P6: `session.py` — session records (id, ISO-8601 tz timestamps, objective, scope snapshot, model, history, proposals, approvals, tool runs, findings, errors, final assessment, report paths), atomic writes, corrupt-file tolerance, old-format loading, listing
- [x] P7: `reporting.py` — Markdown + JSON reports with executive summary, metadata, scope, methodology, tools, approvals, findings (severity/confidence/evidence), remediation, limitations, errors; confirmed observations separated from model interpretations; untrusted output safely fenced
- [x] P8: `logging_setup.py` — file logging under `logs/`, secret-redaction filter
- [x] P3/P9: `cli.py` REPL — all built-in commands, natural-language routing to agent, typo suggestions, empty-input handling, clean Ctrl+C/EOF shutdown, status/banner; `main.py` thin entry point
- [x] P10: `tests/` — pytest suite covering config, scope, parsing, llm catalog/errors (mocked), approval, tools, agent loop, sessions, reporting, CLI dispatch; run + fix; `requirements-dev.txt`
- [x] P11: `README.md` rewrite, `docs/ARCHITECTURE.md`, `.env.example` update, `.gitignore` for logs

## Acceptance criteria status

Verified via the automated suite (offline) plus targeted live checks where a key
was available:

- **Automated:** `python -m pytest` → 340 passed; `ruff check gryphos/ main.py tests/` → clean.
- **Live OpenRouter (manual, not required by tests):** catalog fetch returned 458
  models with exact IDs and free flags; exact-ID selection succeeded; a concrete
  free model returned valid decision JSON through `_create`; a 429 rate-limit and
  a 404 unavailable-model error were classified correctly; free-tier models
  intermittently returned empty/non-conforming output, which the client reported
  as `invalid_output` with a "try a different model" hint (graceful, as designed).
- **Live CLI:** `python main.py start` handled `status`, `tools`, `scope`,
  `config` (key redacted), `sessions` (loaded 3 pre-existing legacy sessions) and
  `exit` cleanly.

No live assessment was run against a target during this work; the tool-execution
path is covered by mocked tests and scope-enforcement tests.

