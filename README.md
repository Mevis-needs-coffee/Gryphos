# Gryphos

Gryphos is an **approval-based** terminal assistant for **authorized** security
testing. It uses an OpenRouter-hosted LLM to reason about an assessment, but the
model can only *propose* a small set of pre-registered tools. Every
network-active action is validated against your configured scope and requires
your explicit approval before it runs. The model has no shell access and can
never construct a command.

> **Authorized use only.** Use Gryphos against systems you own or have explicit
> written permission to test: your own lab, CTF environments, or an assessment
> engagement with a signed scope. It is a defensive/reconnaissance assistant,
> **not** an exploitation framework.

## What Gryphos is and is not

**Is:** an interactive, evidence-preserving recon assistant with a strict
approval gate, scope enforcement, a bounded agent loop, and structured JSON +
Markdown reporting.

**Is not:** a vulnerability scanner, an exploitation or brute-force tool, a
credential/persistence/evasion utility, or an autonomous attacker. It cannot run
arbitrary shell commands and will not scan anything outside your scope.

## Features

- Interactive CLI with built-in commands **and** natural-language questions.
- Registered tools only; the model proposes, the controller validates & approves.
- Every active tool enforces scope in application code at execution time.
- Explicit approval for every network-active action (default = deny).
- Bounded agent loop: step limit, total time budget, duplicate-call prevention,
  consecutive-failure abort.
- Persistent sessions and atomic writes; no replay of old actions.
- Markdown reports + JSON evidence, separating confirmed observations from
  model interpretations.
- Structured decision parsing (valid JSON / fenced / prose-wrapped) with a single
  bounded repair attempt; malformed output is never treated as a command.
- Classified API errors (auth, permission, rate limit, timeout, context length,
  server errors) with safe, actionable messages.
- Secret redaction in logs; API keys never printed or persisted.
- Disciplined reasoning: the agent checks a deterministic digest of confirmed
  evidence before each step, must justify every tool proposal (empty `reason` is
  rejected), prefers the least intrusive useful action, recovers from bounded
  transient API failures, and when the AI is unavailable concludes with an
  evidence-only summary rather than inventing results.
- Professional reports that never overstate: untrusted values are Markdown/HTML
  escaped before rendering, an absence of open ports is never called "secure",
  no CVE identifiers are asserted, and every finding is labelled an unverified
  hypothesis distinct from observed facts.
- **Bounded autonomous CTF solving** (`solve <id>`): a persistent task plan, a
  confined read-only file tool, hypotheses/evidence recording, duplicate-action
  and duplicate-flag prevention, step/time/tool budgets, and a flag verifier. A
  challenge is only reported solved when a flag is actually verified — a
  detected-but-unverified string is never success.

## Registered tools

Gryphos exposes a fixed, modular registry of 12 tools, gated by a risk-based
approval policy. Every tool declares an **approval level (0-4)**; levels 2 and
above always require explicit operator approval, and the prompt shows the exact
action and its expected impact before asking (default: no). Level 4 is disabled
by default.

| Level | Meaning |
|---|---|
| 0 | Internal evidence parsing and explanation (offline). |
| 1 | Restricted, read-only local inspection. |
| 2 | Network-active checks (Nmap, HTTP, TLS). |
| 3 | More intrusive authorized assessment, with tighter constraints. |
| 4 | System modifications / privileged actions — **disabled by default**. |

Active network tools require explicit approval and enforce scope in code;
passive local tools are read-only and make no network calls.

| Tool | Level | Activity | Network | Risk | Approval | Purpose |
|---|---|---|---|---|---|---|
| `nmap_basic` | 2 | active | yes | low | explicit | Top-100 TCP connect scan with service detection (`-n -Pn -sT -sV --top-ports 100 -T2 --reason`). |
| `http_headers` | 2 | active | yes | low | explicit | One HTTP HEAD request; reports security headers, tech hints, missing hardening. |
| `http_redirects` | 2 | active | yes | low | explicit | Traces up to 5 redirect hops; every hop must be an in-scope literal IP. |
| `tls_cert` | 2 | active | yes | low | explicit | TLS handshake; certificate subject/issuer/validity/SANs; verification never disabled; re-validates the connected peer. |
| `web_tech` | 2 | active | yes | low | explicit | Bounded header + ≤8 KiB body fingerprint; no crawling; results labelled inferred. |
| `tcp_banner` | 3 | active | yes | medium | explicit | One TCP connect; reads an unprompted banner (no payload sent); re-validates the connected peer. |
| `local_ports` | 1 | passive | no | informational | none | `ss -ltunp`; classifies listeners local-only / interface-bound / wildcard-exposed. |
| `local_audit` | 1 | passive | no | informational | none | One read-only snapshot: `services`, `firewall`, `journal`, `lynis`. Never elevates privileges. |
| `source_scan` | 1 | passive | no | low | none | Bandit (and optional offline Semgrep with a local rules dir); findings are file:line only. |
| `dependency_audit` | 1 | passive | no | informational | none | `pip-audit` on a manifest/lockfile; distinguishes clean from data-unavailable; never upgrades. |
| `secret_detect` | 1 | passive | no | low | none | gitleaks `--redact`; only rule + file:line are reported; values are never retained. |
| `summarize_evidence` | 0 | passive | no | informational | none | Offline summary, correlation, and contradiction detection over recorded evidence. |

Each tool declares its name, purpose, input schema, scope requirements, risk,
approval level, passive/active classification, network activity, timeout, output
limit, approval policy, structured result format, and an exact-action display.
Arguments are validated against fixed schemas; unknown flags/arguments are
rejected and the model can never name an executable or construct a command.
URL-based tools accept **literal in-scope IPs only** (no hostnames), and
redirects to out-of-scope or hostname destinations are blocked.

## Scope and approval

- **Scope is a hard boundary.** Targets must be literal IPv4/IPv6 addresses
  inside `GRYPHOS_ALLOWED_TARGETS`. Hostnames, URLs, CIDR ranges, and ambiguous
  forms are rejected where a single literal IP is required. Scope is re-checked
  in code immediately before every tool runs and on every redirect hop.
- **Scope changes are guarded.** Narrowing the effective scope is allowed; any
  expansion beyond the configured baseline requires an explicit operator
  confirmation token (`EXPAND-SCOPE`). The model can never change scope. Use
  `scope`, `scope narrow <ip,...>`, `scope set <ip,...>`, and `scope reset`.
- **DNS rebinding is structurally avoided.** URL/target hosts must be literal
  IPs (no DNS resolution). Where a host is resolved, *every* resolved address
  must be in scope, and the address actually connected to is re-validated after
  the connection.
- **Approval is never implied.** It is fingerprint-bound, single-use, and
  defaults to deny; a model response can never manufacture authorization.

## Architecture

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md). In short:

```
CLI (gryphos/cli.py) → Agent loop (gryphos/agent.py)
    → LLM client (gryphos/llm.py) → structured decision (gryphos/models.py)
    → validation (scope.py, tools/base.py, approval.py)
    → analysis (gryphos/analysis.py)
    → execution of registered tool → evidence (session.py, reporting.py)
```

## Supported environments

Kali Linux, Ubuntu/Debian, and Windows Subsystem for Linux (WSL), on Python
3.11+. macOS should work as well with `python3-venv` and `nmap` installed via
Homebrew (untested).

## Installation

### Kali Linux

```bash
sudo apt update
sudo apt install -y python3 python3-venv nmap
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
# edit .env and set OPENROUTER_API_KEY and GRYPHOS_ALLOWED_TARGETS
```

> Kali marks the system Python as "externally managed". **Do not** bypass it with
> `--break-system-packages`. Always use the virtual environment shown above.

### Ubuntu / Debian

```bash
sudo apt update
sudo apt install -y python3 python3-venv nmap
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
```

### WSL (Windows Subsystem for Linux)

Install `nmap` inside the WSL distribution, not on Windows:

```bash
sudo apt update && sudo apt install -y python3-venv nmap
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
```

If `nmap` is missing, Gryphos will tell you; the `nmap_basic` tool will not run
until it is installed. Use a WSL-native project directory (e.g. `~/gryphos`)
rather than `/mnt/c/...` for faster installs.

## Configuration

Copy `.env.example` to `.env` and edit it. `.env` is gitignored — never commit
it or share your key.

```env
OPENROUTER_API_KEY=sk-or-v1-...
GRYPHOS_DEFAULT_MODEL=openrouter/free
GRYPHOS_ALLOWED_TARGETS=127.0.0.1/32
```

- `GRYPHOS_ALLOWED_TARGETS` is the authorized scope (comma-separated IPs or CIDRs).
  The default permits only localhost. Do not add public/third-party targets
  without written authorization.
- Numeric safety limits (`GRYPHOS_COMMAND_TIMEOUT`, `GRYPHOS_MAX_OUTPUT_CHARS`,
  `GRYPHOS_MAX_AGENT_STEPS`, `GRYPHOS_REQUEST_TIMEOUT`, `GRYPHOS_MAX_RETRIES`,
  `GRYPHOS_TIME_BUDGET_SECONDS`, `GRYPHOS_MODEL_CACHE_TTL`, `GRYPHOS_CTF_MAX_STEPS`)
  are clamped to safe ranges; invalid values fall back to defaults with a log warning.
- CTF solver settings: `GRYPHOS_CTF_CHALLENGES_DIR` (default `challenges`),
  `GRYPHOS_CTF_MAX_STEPS` (1-100, default 20), `GRYPHOS_CTF_REMOTE_VERIFY`
  (default `false`), and `GRYPHOS_CTF_WEB_ENABLED` (default `true`; a global kill
  switch for the authorized web tools). Remote flag submission only works for
  challenges that declare a `submit` block and is off unless you explicitly enable
  it.

### OpenRouter API key

1. Create a key at <https://openrouter.ai/settings/keys>.
2. Put it in `.env` as `OPENROUTER_API_KEY`. Do not paste it into the terminal,
   share it, or commit it. Gryphos never prints the key (`config` shows
   `set (redacted)`).

### Model selection (exact IDs)

Models must be selected by their **exact OpenRouter model ID**, not a display
name. Use `models` to list available IDs, or find them at
<https://openrouter.ai/models>.

```
model cohere/command-a
model google/gemma-4-31b-it:free
```

A display name such as `Cohere: Command A` is rejected; Gryphos will not fabricate
an ID from it. When a selected ID is not in the current catalog, Gryphos keeps the
previous working model. If the catalog cannot be fetched, you can still select an
ID with a warning.

> Being listed does **not** guarantee a model is currently available or free.
> Free-tier models are frequently rate-limited (HTTP 429) or unavailable; Gryphos
> reports this and lets you switch models.

## Usage

```bash
python main.py start
```

### Built-in commands

| Command | Description |
|---|---|
| `help` | Show command help. |
| `models` | List OpenRouter models (ID + display name + context + free flag). |
| `model <exact-id>` | Select a model by exact OpenRouter ID. |
| `scope` | Show the authorized scope + effective scope and change history. |
| `scope narrow <ip[,ip...]>` | Narrow the effective scope to a subset (applied immediately). |
| `scope set <ip[,ip...]>` | Change scope; expansion beyond the baseline needs the `EXPAND-SCOPE` token. |
| `scope reset` | Restore the effective scope to the configured baseline. |
| `assess [text]` | Run an assessment, optionally with an objective. |
| `solve [id]` | Solve an explicitly configured CTF challenge; with no id, list challenges. |
| `status` | Show current model, scope, tools, and session info. |
| `sessions` | List saved sessions. |
| `inspect <id>` | Inspect a saved session (read-only; never replays actions or approvals). |
| `history` | Show this session's input history. |
| `report [id]` | Regenerate a report for the current or named session. |
| `config` | Show configuration (secrets redacted). |
| `tools` | List registered tools. |
| `clear` | Clear the screen (sessions/reports are kept). |
| `exit` | Quit cleanly. |

Anything else is treated as **natural language** and routed to the agent:

```
gryphos Explain the last scan.
gryphos Check whether my local web server is exposing HTTP headers.
gryphos What should I investigate next?
```

Built-in commands always take precedence. Empty input is ignored. Single-word
typos get suggestions; normal sentences go to the agent.

### Example workflow (localhost)

```bash
source .venv/bin/activate
python main.py start
# Model: openrouter/free   Scope: 127.0.0.1/32
gryphos model cohere/command-a        # optional: pick a model that follows JSON well
gryphos assess check which TCP services are listening on localhost
# Gryphos proposes: nmap -n -Pn -sT -sV --top-ports 100 -T2 --reason 127.0.0.1
# Approve? [y/N]  ->  y
# ...scan runs, model analyzes, JSON + Markdown reports are written
```

### Approval workflow

Every network-active action shows the tool, target, purpose, exact action, risk,
side effects, timeout, and output limit; the default answer is **No**. Approval is
bound to that exact action — if the target or any security-relevant argument
changes, a new approval is required. Declining asks the model to use its existing
evidence; nothing is executed. The model cannot approve itself.

## Solving CTF challenges

Gryphos can also run a bounded, autonomous solver for **explicitly configured,
self-contained** challenges. Each challenge is a directory:

```
challenges/<id>/challenge.json
challenges/<id>/<provided files...>
```

```bash
gryphos solve                 # list configured challenges
gryphos solve example-warmup  # solve one
```

See [`challenges/README.md`](challenges/README.md) for the `challenge.json`
format (id, one of 9 categories, description, task, optional `flag_format`
regex, optional CTFd-style `submit` block, provided files, and an optional `web`
block that authorizes a single web origin).

How the solver stays honest and bounded:

- **Confined tools only.** The solver can read files *inside* the challenge
  directory (`challenge_file`) and summarize its own evidence. Path traversal,
  absolute paths, and symlink escapes are rejected; no shell access.
- **Offline analysis tools.** Beyond file reading, the solver has read-only,
  bounded tools for identification (`file_identify`), encodings
  (`encoding_decode`), archives/compressed streams (`archive_inspect`), images
  (`image_triage`), captures (`pcap_summary`), documents (`document_parse`),
  crypto (`crypto_analyze`), artifact carving (`artifact_extract`), and
  capability discovery (`list_capabilities`). They use system utilities or Python
  libraries *when installed* and fall back to pure-stdlib implementations
  otherwise; Gryphos never installs anything and reports what is missing.
- **Authorized web tools (opt-in).** A challenge may declare a `web` block naming
  exactly one `origin`; only then do `web_fetch`, `web_crawl`, `web_analyze`,
  `web_session`, `web_probe`, and the offline `web_clues` exist. Requests are
  method-, size-, count-, and rate-bounded; the host is re-resolved and every
  address validated per request; cloud-metadata/link-local ranges are always
  blocked; cross-origin redirects are refused unless opted in; and cookies,
  tokens, and credentials are redacted before they reach the model or the report.
  `GRYPHOS_CTF_WEB_ENABLED=false` forces them off globally.
- **A persistent task plan** (pending/running/completed/failed/blocked) is seeded
  from the category, updated every step, and saved with the session and report.
- **Duplicate-action and duplicate-flag prevention** via canonical fingerprints,
  plus step, wall-clock, per-tool timeout/output, and consecutive-failure bounds.
- **Verified flags only.** A flag is reported as **solved** only when a verifier
  accepts it. Detection (a `flag{...}`-shaped string in a file) is recorded as an
  **unverified** candidate, never as success. The default verifier is offline and
  only checks format conformance (the report says so); an opt-in CTFd-style HTTP
  verifier is used only for challenges that declare a `submit` block *and* when
  `GRYPHOS_CTF_REMOTE_VERIFY=true`.
- **Untrusted data, never executed.** Provided file contents and HTTP responses
  are treated as data, never as instructions; unknown binaries, macros, scripts,
  and extracted programs are never run, and extraction targets a discarded
  temporary directory.
- **Triage, not a universal solver.** The analysis tools cover common
  encodings/archives/ciphers; unusual obfuscation, encrypted archives, and
  LSB-extraction tools (e.g. steghide) are reported as leads rather than solved
  automatically (see `docs/CTF_SOLVER.md`).

## Reports and sessions

Each completed assessment writes two files into `reports/`:

- `<session-id>.json` — the full, self-contained session record: id,
  timezone-aware timestamps, objective, model, scope snapshot, ordered
  conversation history, tool proposals, approval decisions, executed actions
  with their actual output, the ordered evidence stream, parsed data, findings,
  errors/warnings, final analysis, report paths, and a `report_context` block.
- `<session-id>.md` — human-readable report (executive summary, metadata, scope,
  methodology, tools executed, approvals, confirmed observations, model findings
  with severity/confidence, remediation, limitations, errors, timestamps).

Session persistence is designed for reliability and safety:

- **Writes are atomic** (temp file + `os.replace`). Corrupt, partial, or
  oversized files are skipped safely when listing and reported cleanly when
  loading.
- **Size limits are applied on save** — recorded lists keep the most-recent
  entries and oversized records are trimmed oldest-first rather than lost.
- **Secrets are redacted** before anything is written (OpenRouter keys,
  bearer/authorization headers, `api_key=`-style values), in both JSON and
  Markdown.
- **Debug logs and evidence are separated**: diagnostics go to `logs/`
  (gitignored), assessment evidence to `reports/` (gitignored); session files
  never contain log lines.
- **Loading is read-only.** Nothing is ever replayed and no historical approval
  is treated as current authorization — every new assessment requires fresh
  fingerprints and explicit approval. Use `sessions` to list and `inspect <id>`
  to examine a previous session.

`reports/` is gitignored so local evidence is not committed. Confirmed
observations are derived deterministically from tool output; model findings are
clearly labelled as interpretations.

## Troubleshooting

| Symptom | Fix |
|---|---|
| `OPENROUTER_API_KEY is not configured` | Copy `.env.example` to `.env` and set the key. |
| HTTP 401 | Key invalid/expired — regenerate it. |
| HTTP 403 | Your key lacks access to the model — choose another. |
| HTTP 429 | Rate limit/quota — wait or switch to another model. |
| HTTP 400 / context length | Choose a model with a larger context window. |
| Model returns invalid structure | Try another model with `model <exact-id>`. |
| `Nmap is not installed` | `sudo apt install nmap`. |
| Scope error | Only add authorized IPs/CIDRs to `GRYPHOS_ALLOWED_TARGETS`. |
| `externally-managed-environment` on Kali | Use a venv (see Installation); do not use `--break-system-packages`. |

## Running tests

Tests are fully offline — no API key or public network required; network tools
are mocked.

```bash
source .venv/bin/activate
pip install -r requirements-dev.txt
python -m pytest
```

Linting (optional):

```bash
pip install ruff
ruff check gryphos/ main.py tests/
```

## Known limitations

- Only the registered tools can run; there is no arbitrary command execution by design.
- URL tools accept literal in-scope IPs only (hostname-based vhosts are not supported).
- `nmap_basic` scans only the top 100 TCP ports; carve this out in reports.
- `web_tech` fingerprints are **inferred** from headers and a small body sample and can be spoofed; treat them as hints.
- `tcp_banner` (Level 3) reads only an unprompted banner; services that require a request send nothing.
- Passive local tools (`local_ports`, `local_audit`) inspect only the host Gryphos runs on; `source_scan`, `dependency_audit`, and `secret_detect` need their external tools (Bandit/Semgrep, pip-audit, gitleaks) installed locally.
- No Level 4 tools ship; the policy and registry gating reserve that level for system modifications, disabled by default.
- Model findings are interpretations, not proof; verify manually.
- Free-tier models may be unavailable, rate-limited, or unable to follow the
  required JSON format; select a different model when prompted.
- No exploitation, credential testing, evasion, or persistence.
- CTF solving is limited to explicitly configured, local challenge directories;
  it never scans networks, never runs shell commands, and only reads files inside
  the challenge directory. A format-matching flag is not independently confirmed
  unless a submit endpoint (opt-in) accepts it.
- CTF analysis tools are offline triage: they cover common encodings, archives,
  ciphers, images, captures, and documents, but unusual obfuscation, encrypted
  archives, and pixel-level stego extraction may be out of reach; they report
  leads instead of guessing. Optional external tools (`binwalk`, `exiftool`,
  `7z`, `tshark`, `PIL`, `scapy`, ...) are used only if installed and are never
  installed by Gryphos.
- Reports can contain sensitive host information — sanitize before sharing.

## Security design and responsible use

- Scope is enforced in application code immediately before execution and on
  every redirect hop; the model cannot modify scope. Scope expansion beyond the
  configured baseline requires an explicit operator confirmation token.
- Approval follows a risk-based level policy (0-4): levels 2+ always require
  explicit approval; the prompt shows the exact action and expected impact and
  defaults to "no". Approval is fingerprint-bound, single-use, and cannot be
  manufactured or reused by model output.
- Destination hosts must be literal in-scope IPs (no DNS); where a host is
  resolved, every address must be in scope and the connected peer is
  re-validated.
- No `shell=True`; all external tools use fixed argument lists with timeouts and
  output limits.
- Secrets are redacted from logs and from persisted sessions/reports; API keys
  are never printed or written to disk.
- See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for trust boundaries.

Use Gryphos only where you are authorized. You are responsible for complying with
all applicable laws and engagement rules.

## License

MIT License. Copyright (c) 2026 Mevis Lobo. See [LICENSE](LICENSE).

Gryphos itself is source-available under MIT, but **using it is governed by the
"Authorized use only" terms above**: you may only assess systems you own or have
explicit written permission to test, and you are responsible for applicable laws
and engagement rules.
