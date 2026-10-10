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

## Registered tools

| Tool | Network | Risk | Approval | Purpose |
|---|---|---|---|---|
| `nmap_basic` | yes | low | explicit | Top-100 TCP connect scan with service detection (`-n -Pn -sT -sV --top-ports 100 -T2 --reason`). |
| `http_headers` | yes | low | explicit | One HTTP HEAD request; reports security headers, tech hints, missing hardening. |
| `http_redirects` | yes | low | explicit | Traces up to 5 redirect hops; every hop must be an in-scope literal IP. |
| `tls_cert` | yes | low | explicit | TLS handshake; certificate subject/issuer/validity/SANs. |
| `summarize_evidence` | no | informational | none | Passively summarizes recorded evidence. |

Arguments are validated against fixed schemas; unknown flags/arguments are
rejected. URL-based tools accept **literal in-scope IPs only** (no hostnames),
and redirects to out-of-scope or hostname destinations are blocked.

## Architecture

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md). In short:

```
CLI (gryphos/cli.py) → Agent loop (gryphos/agent.py)
    → LLM client (gryphos/llm.py) → structured decision (gryphos/models.py)
    → validation (scope.py, tools.py, approval.py)
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
  `GRYPHOS_TIME_BUDGET_SECONDS`, `GRYPHOS_MODEL_CACHE_TTL`) are clamped to safe
  ranges; invalid values fall back to defaults with a log warning.

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
| `scope` | Show the authorized target scope. |
| `assess [text]` | Run an assessment, optionally with an objective. |
| `status` | Show current model, scope, tools, and session info. |
| `sessions` | List saved sessions. |
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

## Reports and sessions

Each completed assessment writes two files into `reports/`:

- `<session-id>.json` — machine-readable session + evidence.
- `<session-id>.md` — human-readable report (executive summary, metadata, scope,
  methodology, tools executed, approvals, confirmed observations, model findings
  with severity/confidence, remediation, limitations, errors, timestamps).

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
- Model findings are interpretations, not proof; verify manually.
- Free-tier models may be unavailable, rate-limited, or unable to follow the
  required JSON format; select a different model when prompted.
- No exploitation, credential testing, evasion, or persistence.
- Reports can contain sensitive host information — sanitize before sharing.

## Security design and responsible use

- Scope is enforced in application code immediately before execution; the model
  cannot modify scope.
- Approval is fingerprint-bound, single-use, and defaults to deny; it cannot be
  manufactured or reused by model output.
- No `shell=True`; all external tools use fixed argument lists with timeouts and
  output limits.
- Secrets are redacted from logs; API keys are never printed or written to reports.
- See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for trust boundaries.

Use Gryphos only where you are authorized. You are responsible for complying with
all applicable laws and engagement rules.

## License

MIT License. Copyright (c) 2026 Mevis Lobo. See [LICENSE](LICENSE).

Gryphos itself is source-available under MIT, but **using it is governed by the
"Authorized use only" terms above**: you may only assess systems you own or have
explicit written permission to test, and you are responsible for applicable laws
and engagement rules.
