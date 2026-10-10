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
| `gryphos/scope.py` | Scope parsing/enforcement and URL authorization (the security boundary). |
| `gryphos/approval.py` | Approval requests with SHA-256 action fingerprints; single-use, default-deny. |
| `gryphos/tools.py` | Tool registry + the five registered tools; argument validation; fixed argv, no shell. |
| `gryphos/session.py` | Session records and atomic JSON persistence; legacy + corrupt-file tolerance. |
| `gryphos/reporting.py` | Markdown report + JSON evidence generation. |

## Trust boundaries

```
        UNTRUSTED                         TRUSTED CONTROLLER (application code)
 ┌───────────────────────┐      proposals      ┌──────────────────────────────────────┐
 │  LLM (OpenRouter)     │ ───────────────────▶│  Decision parser (models.py)          │
 │  target banners/      │                     │  Schema validation                    │
 │  scan output/headers  │◀─────────────────── │  Scope check (scope.py)               │
 └───────────────────────┘      evidence        │  Argument validation (tools.py)      │
                                                │  Approval (approval.py, human)        │
                                                │  Registered execution (tools.py)     │
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
    ask LLM for a decision (with objective, target, bounded evidence, history)
    ├─ final          → print analysis, record findings, stop
    ├─ error          → record, stop
    ├─ clarification  → ask the operator, record answer, continue
    └─ tool_call
         ├─ tool not registered?            → reject (counts toward failure streak)
         ├─ args fail schema validation?    → reject
         ├─ target out of scope / mismatch? → reject
         ├─ duplicate of an already-run action? → skip, ask model for analysis
         ├─ network-active? → require approval (default deny)
         │     ├─ declined            → record refusal, do not execute
         │     └─ approved (fingerprint, single-use) → execute
         └─ execute registered tool → record result → reset failure streak
    if consecutive_failures ≥ 3 → abort safely
after loop → steps exhausted (safe stop)
```

Bounds and safety rules:

- `max_agent_steps` (default 6, clamped 1–20) and `time_budget_seconds`
  (default 600) cap the loop.
- Identical actions are fingerprinted; repeats are not executed.
- Three consecutive rejected/failed proposals abort the run.
- Every tool error is recorded; the loop continues only when it is safe to.
- `KeyboardInterrupt`/EOF during approval cancels without executing.

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

## Tool registry (`gryphos/tools.py`)

Every capability is a `ToolSpec` (name, description, purpose, input schema,
network flag, side effects, timeout, output limit, risk, approval policy,
executor). `build_registry()` binds executors to `Settings`. `validate_args()`
rejects unknown properties and missing required fields. Tools never use
`shell=True`; `nmap_basic` resolves the binary via `shutil.which` and passes a
fixed argv list.

Tools and their scope requirements:

- `nmap_basic` — literal in-scope IP target.
- `http_headers` — literal in-scope IP + validated port/scheme; single HEAD request.
- `http_redirects` — literal in-scope IP URL; manual redirect tracing; every hop
  re-authorized (off-scope or hostname hops blocked).
- `tls_cert` — literal in-scope IP; optional SNI hostname (validated).
- `summarize_evidence` — passive; reads recorded evidence only.

## Scope enforcement (`gryphos/scope.py`)

- `normalize_ip` accepts a single literal IPv4/IPv6 address; rejects hostnames,
  URLs, CIDR suffixes, bracket forms, ambiguous short forms (`127.1`), and
  IPv4-mapped IPv6.
- `validate_target` requires the address to fall inside a same-version network in
  `GRYPHOS_ALLOWED_TARGETS`. IPv4 and IPv6 are never mixed.
- `authorize_url` requires an absolute `http`/`https` URL whose host is a literal
  in-scope IP. **Hostnames are rejected** — there is no DNS resolution, which
  removes DNS-rebinding and redirect-to-name bypasses.
- URL tools re-validate every redirect hop through `authorize_url`.

Scope is checked at execution time, not just in the prompt, and the model cannot
change it.

## Approval (`gryphos/approval.py`)

- `ApprovalRequest` carries the tool, target, canonical args, display command,
  network flag, limits, risk, and side effects.
- `action_fingerprint` = SHA-256 over canonical `(tool, target, args)`; the
  model's free-text reason is display-only and not fingerprinted.
- `ApprovalManager.record/authorize` enforces a single-use, exact-match decision;
  missing, mismatched, or reused state denies execution (default deny).

Changing the target or any argument produces a different fingerprint and
therefore requires fresh approval. Model output cannot manufacture approval.

## Evidence and sessions (`gryphos/session.py`, `gryphos/reporting.py`)

- A `Session` records id, ISO-8601 timestamps, objective, scope snapshot, model,
  history, proposals, approvals, tool runs, errors, findings, final assessment,
  and report paths.
- `SessionStore.save` writes to a temp file and `os.replace`s it (atomic).
  `list_sessions`/`load` tolerate corrupt files, oversized files, path
  traversal, and the legacy flat report format. Loading never replays actions or
  rebuilds approvals.
- `reporting.generate_reports` writes `<session-id>.json` (session + evidence +
  report context) and `<session-id>.md` (12 sections). Confirmed observations are
  derived deterministically from tool output; model findings are labelled
  interpretations. Untrusted output is fenced with a backtick run longer than any
  in the content.

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
