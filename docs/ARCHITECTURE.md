# Gryphos — Architecture

This document describes the actual implementation: the agent loop, trust
boundaries, the tool registry, scope checks, the approval process, and the flow
of evidence.

## Module map

| Module | Responsibility |
|---|---|
| `main.py` | Thin Typer entry point (`python main.py start`). |
| `gryphos/cli.py` | Interactive REPL, built-in commands, natural-language routing, report/session UX. |
| `gryphos/config.py` | Env/`.env` settings with bounded numeric validation; never prints secrets. |
| `gryphos/logging_setup.py` | File logging with a secret-redaction filter. |
| `gryphos/llm.py` | OpenRouter client: model catalog + TTL cache, exact-ID selection, classified errors, decision extraction + bounded repair. |
| `gryphos/models.py` | Pydantic decision schemas and the strict JSON parser. |
| `gryphos/agent.py` | Bounded agent loop; orchestration of validation, approval, execution, recording. |
| `gryphos/scope.py` | Scope parsing/enforcement, URL authorization, and reserved-address classification (the security boundary). |
| `gryphos/approval.py` | Approval requests with SHA-256 action fingerprints; single-use, default-deny. |
| `gryphos/tools/` | Modular tool package: `base.py` (interfaces + validation), `net.py` (bounded HTTP/TLS helpers), one module per tool, `registry.py` (`build_registry`). |
| `gryphos/analysis.py` | Offline evidence analysis (Tool 10): normalization, cross-tool correlation, contradiction detection, session comparison, and the passive `summarize_evidence` tool. |
| `gryphos/session.py` | Session records and atomic JSON persistence: full evidence stream, legacy + corrupt-file tolerance, size limits, secret redaction. |
| `gryphos/reporting.py` | Markdown report + JSON evidence generation (includes correlation and contradiction sections). |

## Trust boundaries

```
        UNTRUSTED                         TRUSTED CONTROLLER (application code)
 ┌───────────────────────┐      proposals      ┌──────────────────────────────────────┐
 │  LLM (OpenRouter)     │ ───────────────────▶│  Decision parser (models.py)          │
 │  target banners/      │                     │  Schema validation                    │
 │  scan output/headers  │◀─────────────────── │  Scope check (scope.py)               │
 └───────────────────────┘      evidence        │  Argument validation (tools/base.py) │
                                                 │  Approval (approval.py, human)        │
                                                 │  Registered execution (tools/*)      │
                                                 └──────────────────────────────────────┘
```

- The **LLM is untrusted**. Its output is parsed into one of four decision kinds;
  anything else is rejected. Target responses, banners, and headers are also
  treated as untrusted data, never as instructions.
- **Only the controller** validates arguments, enforces scope, and executes
  tools. The model cannot name an executable, supply flags, or run shell code.
- **The operator is the authorizer.** Approval is required for every
  network-active action and is bound to the exact action.

## Agent loop (`gryphos/agent.py`)

```
validate session target against scope
loop up to max_agent_steps and until time budget:
    digest = summary of confirmed evidence (analysis.summarize_evidence, offline)
    ask LLM for a decision (objective, target, bounded evidence, evidence digest, history)
    ├─ final          → print analysis, record findings, stop
    ├─ error          → record, stop
    ├─ clarification  → ask the operator, record answer, continue
    └─ tool_call
         ├─ tool not registered?              → reject (counts toward failure streak)
         ├─ approval level exceeds ceiling?   → reject
         ├─ no justification (empty reason)?  → reject
         ├─ args fail schema validation?      → reject
         ├─ target out of scope / mismatch?   → reject
         ├─ duplicate of an already-run action? → skip, ask model for analysis
         ├─ network-active? → require approval (default deny)
         │     ├─ declined            → record refusal, do not execute
         │     └─ approved (fingerprint, single-use) → execute
         └─ execute registered tool → record result → reset failure streak
    if consecutive_failures ≥ 3 → abort safely
after loop → steps exhausted (safe stop with collected-evidence digest)
```

The loop follows a **reasoning discipline** (also encoded in the system prompt):
1. understand the objective; 2. check the **confirmed-evidence digest** before
proposing anything; 3. name the specific missing information; 4. choose the
least intrusive useful step — propose a tool **only** when it fills a real gap;
5. justify it (an empty `reason` is rejected by the controller); 6. conclude
honestly, citing recorded evidence and saying plainly when evidence is
insufficient.

Resilience to API failures:

- A transient LLM failure (`rate_limit`, `timeout`, `connection`, `server_error`)
  no longer destroys the run — the same step is resumed up to
  `AGENT_TRANSIENT_RESUME_LIMIT` (2) times, recorded as a session warning.
- Non-transient failures (auth, policy, invalid output) stop immediately.
- On failure the agent returns an **evidence-based fallback final**: a
  deterministic digest of the confirmed evidence, explicitly labelled "not an AI
  interpretation", and states when nothing can be concluded. It never invents
  results.

Bounds and safety rules:

- `max_agent_steps` (default 6, clamped 1–20) and `time_budget_seconds`
  (default 600) cap the loop.
- Identical actions are fingerprinted; repeats are not executed.
- Three consecutive rejected/failed proposals abort the run.
- Every tool error is recorded; the loop continues only when it is safe to.
- `KeyboardInterrupt`/EOF during approval cancels without executing.
- Early stops (`steps_exhausted`, `time_budget`, failure-streak abort) print and
  record the collected-evidence digest in `final_assessment`.

## Decision schema (`gryphos/models.py`)

Four shapes, validated with Pydantic:

```jsonc
{"kind":"tool_call","tool":"nmap_basic","args":{"target":"127.0.0.1"},"reason":"..."}
{"kind":"final","message":"...","findings":[{"title":"...","severity":"low","confidence":"high","detail":"...","remediation":"..."}]}
{"kind":"clarification","question":"..."}
{"kind":"error","message":"..."}
```

The parser (`parse_decision`) accepts plain JSON, JSON in Markdown fences, or a
JSON object embedded in prose. Malformed output, non-object payloads, unknown
kinds, and schema violations raise `DecisionParseError`; the LLM client makes
**one** bounded repair attempt before raising `LLMOutputError`. Invalid output is
never interpreted as a command.

## Tool package and registry (`gryphos/tools/`, `gryphos/analysis.py`)

Every capability is a `ToolSpec` declaring: name, description, purpose, input
schema, risk category, **approval level (0-4)**, side effects, passive/active
classification (`activity`), network flag, approval policy, timeout, output
limit, scope requirements, a structured `result_schema`, an executor, and an
optional `show()` that renders the exact action for approval and display.
`build_registry(settings)` assembles the fixed set, **gated by the configured
approval-level ceiling**, and returns it keyed by name; anything not returned
there can never run. `ToolSpec.__post_init__` enforces that the level, coarse
policy, activity, and network flag agree, so a tool cannot under-declare risk.
`validate_args()` rejects unknown properties, missing required fields, wrong
types, and enum/min/max violations, so the model cannot inject flags,
executables, or commands. Tools never use `shell=True`; binaries are resolved
with `shutil.which` and invoked with fixed argv lists. `tools/__init__.py`
re-exports the stable public API (`ToolError`, `ToolResult`, `ToolSpec`,
`validate_args`, `build_registry`, and the nmap helpers).

Modules: `base.py` (interfaces, validation, bounded process runner), `net.py`
(shared bounded HTTP/TLS helpers), `nmap.py`, `http.py`, `tls.py`, `tech.py`,
`tcp_banner.py`, `local_ports.py`, `local_audit.py`, `source_scan.py`,
`dependency_audit.py`, `secret_detect.py`, and `registry.py`. `analysis.py`
holds Tool 10.

Registered tools and their policy, by approval level:

- **Level 2 — network-active** (approval `explicit`, scope-enforced in code):
  - `nmap_basic` — literal in-scope IP; fixed argv `-n -Pn -sT -sV --top-ports 100 -T2 --reason`.
  - `http_headers` — literal in-scope IP + validated port/scheme; single HEAD request; cookies sanitized.
  - `http_redirects` — literal in-scope IP URL; manual redirect tracing; every hop re-authorized (off-scope or hostname hops blocked).
  - `tls_cert` — literal in-scope IP; optional SNI hostname (validated); certificate verification never disabled; connected peer re-validated.
  - `web_tech` — literal in-scope IP; bounded header + ≤8 KiB body fingerprint; no crawling; results labelled *inferred*; optional WhatWeb with stealth flags.
- **Level 3 — intrusive, tightly constrained** (approval `explicit`):
  - `tcp_banner` — one TCP connection to a literal in-scope IP:port; reads an unprompted banner (no payload sent); tight timeout/output bounds; connected peer re-validated.
- **Level 1 — passive local, read-only** (no network, approval `none`):
  - `local_ports` — `ss -ltunp`; classifies listeners local-only / interface-bound / wildcard-exposed.
  - `local_audit` — one read-only snapshot; modes `services`, `firewall`, `journal`, `lynis`; never elevates privileges.
  - `source_scan` — Bandit over a chosen directory; optional Semgrep with a **local** rules dir only (offline); source code and the `code` field are stripped from results.
  - `dependency_audit` — `pip-audit` on a manifest/lockfile; distinguishes *clean* from *data unavailable*; never upgrades.
  - `secret_detect` — gitleaks `--redact`; secret values, matches, and line text are stripped before output, evidence, logs, or model context; only rule + file:line are reported.
- **Level 0 — offline analysis**: `summarize_evidence` — reads recorded evidence only; produces facts, normalized observations, correlation, and contradictions.
- **Level 4 — system modification**: none ship; disabled by default (the registry
  ceiling defaults to 3; `GRYPHOS_MAX_APPROVAL_LEVEL` may raise it deliberately).

## Approval policy and levels (`gryphos/approval.py`)

Approval is governed by a five-level risk policy:

| Level | Meaning | Approval |
|---|---|---|
| 0 | Internal evidence parsing and explanation | none (offline) |
| 1 | Restricted, read-only local inspection | none (read-only) |
| 2 | Network-active checks (Nmap, HTTP, TLS) | explicit |
| 3 | More intrusive authorized assessment | explicit, tighter constraints |
| 4 | System modifications / privileged actions | explicit, disabled by default |

- `requires_approval(level)` is true for levels 2-4; `level_allowed(level, max)`
  gates registration. Level 4 has no default max (ceiling 3).
- `ApprovalRequest` carries the `approval_level`; the request record and the UI
  include the level name, why the level applies, and the expected impact.
- The prompt always shows the exact action and the expected impact and defaults
  to **no**. Approval is bound to a SHA-256 fingerprint over canonical
  `(tool, target, args)`, single-use, and default-deny; model text is never
  authorization and cannot manufacture or reuse a decision.
- Defense in depth: even if a tool somehow reached the registry, the agent
  refuses any tool whose `approval_level` exceeds `max_approval_level`.

## Evidence analysis (Tool 10, `gryphos/analysis.py`)

Deterministic, offline reasoning over already-collected evidence:

- `normalize_observations` flattens tool results into comparable observations.
- `correlate` groups observations by target with per-target notes.
- `detect_contradictions` flags conflicting cross-tool signals (e.g. an HTTP
  probe succeeding on a port nmap reported closed among the top 100).
- `compare_sessions` diffs two saved sessions by observation key without
  re-executing any tool.
- `summarize_evidence_spec` registers the passive `summarize_evidence` tool.

`reporting.py` surfaces correlation (section 7a) and contradictions (section
7b) in both the Markdown report and the JSON `report_context`.

## Scope enforcement (`gryphos/scope.py`)

- `normalize_ip` accepts a single literal IPv4/IPv6 address; rejects hostnames,
  URLs, CIDR suffixes, bracket forms, ambiguous short forms (`127.1`), and
  IPv4-mapped IPv6.
- `validate_target` requires the address to fall inside a same-version network in
  `GRYPHOS_ALLOWED_TARGETS`. IPv4 and IPv6 are never mixed. On rejection it
  names the reserved class (loopback, link-local, cloud metadata, private,
  CGNAT, documentation/TEST-NET, multicast/future-use) via `classify_ip`, and
  tells the operator to add the address to the scope explicitly.
- `classify_ip` is diagnostic only: being private/link-local is not itself a
  block; an address is reachable only if the scope explicitly permits it.
- `authorize_url` requires an absolute `http`/`https` URL whose host is a literal
  in-scope IP. **Hostnames are rejected** — there is no DNS resolution, which
  removes DNS-rebinding and redirect-to-name bypasses.
- URL tools re-validate every redirect hop through `authorize_url`.
- `resolve_and_validate(host, scope_items)` is the single connection gate: a
  literal IP is checked directly; a hostname is only resolved when a tool
  explicitly allows it, and **every** resolved address must be in scope (a mixed
  answer is rejected) — so a rebinding record cannot slip through. Unresolvable
  hosts are reported, never scanned.
- `validate_connected_peer(peer, scope_items)` re-checks the address actually
  connected to (e.g. after a TLS/TCP connect), catching any TOCTOU gap between
  authorization and connection.
- `ScopeManager` holds the **baseline** (from `GRYPHOS_ALLOWED_TARGETS`) and the
  **effective** scope plus a change history. Narrowing (`is_subset`) is applied
  silently; any expansion beyond the baseline requires the explicit operator
  token `EXPAND_SCOPE_CONFIRMATION` (`EXPAND-SCOPE`). Malformed candidates and
  effective-scope-outside-baseline states are errors. `reset()` restores the
  baseline. `describe_change` explains a proposed change for display.

Scope is checked at execution time, not just in the prompt, and the model cannot
change it — only the operator can, and only through the guarded CLI commands.

## Approval (`gryphos/approval.py`)

- `ApprovalRequest` carries the tool, target, canonical args, display command,
  network flag, limits, risk, side effects, and **approval level**.
- `action_fingerprint` = SHA-256 over canonical `(tool, target, args)`; the
  model's free-text reason is display-only and not fingerprinted.
- `ApprovalManager.record/authorize` enforces a single-use, exact-match decision;
  missing, mismatched, or reused state denies execution (default deny).

Changing the target or any argument produces a different fingerprint and
therefore requires fresh approval. Model output cannot manufacture approval.

## Evidence and sessions (`gryphos/session.py`, `gryphos/reporting.py`)

- A `Session` records id, ISO-8601 timezone-aware timestamps, objective, scope
  snapshot, model, **ordered conversation history**, proposals, **approval
  decisions**, tool runs, the **full ordered evidence stream** (tool results,
  rejections, notes, clarifications, final), errors and warnings, findings,
  final assessment, report paths, and `report_context`.
- `SessionStore.save` writes to a temp file and `os.replace`s it (atomic) and
  is **size-bounded**: recorded lists keep at most `MAX_LIST_ITEMS` recent
  entries, strings are hardened by `MAX_TEXT_CHARS`, and an oversized payload is
  progressively trimmed (oldest first) before being written — a saved, valid
  record is preferred over a failed save. `list_sessions`/`load` tolerate
  corrupt files, oversized files, path traversal, and the legacy flat report
  format. Loading is strictly read-only: actions are never replayed and
  historical approvals are restored as inert records, never as an active
  `ApprovalManager`.
- **Secrets are redacted before persistence.** `logging_setup.redact` masks
  OpenRouter keys, bearer/authorization headers, and `api_key=`-style values in
  *every* string in the session record and in the Markdown report.
- `reporting.generate_reports` writes `<session-id>.json` (the session record
  itself, with an embedded `report_context`) and `<session-id>.md` (12
  sections). Because the JSON is the session record, `SessionStore.save` and
  report generation produce identical, redacted content and never clobber each
  other. Confirmed observations are derived deterministically from tool output;
  model findings are labelled interpretations. Untrusted output is fenced with a
  backtick run longer than any in the content.
- `sessions` lists saved sessions; `inspect <id>` shows a read-only summary of
  a known session (metadata, counts, findings, approvals, errors) without
  regenerating reports or replaying anything.

## Logs vs evidence

Diagnostics go to `logs/gryphos.log` and assessment evidence to `reports/`
(both gitignored). The two are separated: session/report files contain only
redacted assessment evidence and never include debug log lines.

## Error handling (`gryphos/llm.py`, `gryphos/agent.py`)

API failures are classified: `auth` (401), `permission` (403), `rate_limit`
(429), `timeout`/`connection`, `bad_request`/`context_length` (400),
`server_error` (5xx), `invalid_output`, and `catalog_unavailable`. Transient
errors (rate limit, timeout, connection, 5xx) use bounded backoff retries;
side-effecting tool actions are never blindly retried. Messages are actionable
and never include the API key.

## Logging and secrets (`gryphos/logging_setup.py`)

Diagnostics go to `logs/gryphos.log` (gitignored). A `RedactionFilter` masks
OpenRouter keys, bearer/authorization headers, and `api_key=`-style values.
Configuration display (`config`) shows `set (redacted)`.
