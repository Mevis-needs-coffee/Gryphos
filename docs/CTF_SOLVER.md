# Gryphos — Autonomous CTF Solver

Extends Gryphos from an approval-based assessment assistant into a bounded,
autonomous solver for explicitly configured CTF challenges. Phase 1 implements
the full solve pipeline; Phase 2 adds a suite of offline, registered *analysis*
tools (file/encoding/archive/image/pcap/document/crypto/artifact) with strict
safety bounds. Phase 3 adds bounded, scope-pinned **web** solving (authorized
single origin); Phase 4 adds bounded, scope-pinned **network** reconnaissance
(authorized single target). Remote flag submission and cross-challenge persistence
remain the only explicitly deferred parts.

## Scope of work

Preserve every existing feature and all previously passing tests. Add a dedicated
`gryphos/ctf/` package, a `solve` CLI command, structured session extensions, a
CTF report, and an offline test suite. The solver reuses the existing trust
boundaries: the model is untrusted, tool calls are validated by application
code, scope is enforced at execution time, and every decision is one of the
strictly validated kinds (plus a new `flag` kind).

## Known limitations

The analysis tools are **triage and helpers, not a universal solver**. Unless a
challenge's obfuscation matches one of the built-in heuristics, the tool reports
candidates for the model to reason about rather than an automatic answer:

- **Encodings** — covers base64/url-safe, base32, base16/hex, URL, quoted-printable,
  binary/decimal/octal codes, ascii85/base85, ROT13/ROT47, Morse, and bounded
  gzip/zlib. Arbitrary/proprietary encodings are not detected.
- **Archives** — zip/tar/gzip/bzip2/xz are fully handled by the standard library;
  7z/rar listing needs the optional `7z` binary. Encrypted or exotic archives are
  reported, not broken.
- **Images** — header/metadata/tail parsing only. LSB *extraction* (e.g. zsteg,
  steghide) needs those tools, which are not bundled; the tool reports an LSB-bit
  ratio and appended data as leads.
- **Crypto** — classical ciphers, single/repeating XOR, Vigenere, rail-fence, JWT,
  hash identification, and RSA only for small/close factors or `e=1`. There is no
  general factorization, no gzip oracle, no padding oracle.
- **Structured data** — YAML needs PyYAML; legacy OLE (doc/xls/ppt) streams need
  `olefile`. Both are optional; a clear "missing" note is emitted instead.

Detection is never treated as success: a candidate is only reported as **solved**
after the flag verifier accepts it.

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

## Phase 2 — offline analysis tools

Phase 2 extends the *existing* solver registry (it is not a parallel framework).
Every tool below is a `ToolSpec` on the same contract, is offline and read-only
against the challenge directory, is bounded in read size, recursion, and output,
and treats every file as untrusted (nothing is executed).

### New modules under `gryphos/ctf/`

- `sandbox.py` — one place for path confinement (`resolve_inside`), bounded reads
  (`read_bounded`), a discarded private temp dir (`safe_tempdir`), size limits
  (`MAX_READ_BYTES`, `MAX_SCAN_BYTES`, archive caps), and flag attachment.
- `deps.py` — optional binary/module discovery (`file`, `strings`, `binwalk`,
  `exiftool`, `7z`, `tshark`, `PIL`, `scapy`, `yaml`, `defusedxml`, `olefile`,
  `pefile`, `Crypto`). Gryphos **never installs** anything; missing capabilities
  are reported with an install hint.
- `filetools.py` — `file_identify` (magic bytes, md5/sha1/sha256/sha512/crc32,
  entropy, strings, embedded signatures) and `artifact_extract` (carve embedded
  objects or a byte range; reports type/hashes/preview; never executed).
- `encoding.py` — `encoding_decode`: ranks base64/url-safe, base32, hex, URL,
  quoted-printable, binary/decimal/octal codes, ascii85/base85, ROT13/reverse,
  Morse, and bounded gzip/zlib; depth-bounded recursion; flag matches promoted.
- `archives.py` — `archive_inspect`: zip/tar/gzip/bzip2/xz via stdlib (7z/rar with
  the optional binary). Flags absolute paths, `..` traversal, symlink/hardlink
  members, encryption, oversize members, and decompression-bomb ratios; recurses
  nested archives to a bounded depth.
- `images.py` — `image_triage`: PNG/JPEG/GIF/BMP header + metadata parsing,
  comments, EXIF (via `exiftool` when present), bytes appended after the format
  terminator, tail entropy/printability, embedded tail signatures, and an LSB-bit
  ratio. Non-destructive.
- `pcap.py` — `pcap_summary`: PCAP/PCAP-NG parsing with no scapy/tshark —
  link type, counts, time span, Ethernet/IP conversations, TCP/UDP ports, DNS
  queries, HTTP request lines, and payload strings.
- `documents.py` — `document_parse`: PDF (bounded Flate decode), JSON, XML
  (hardened; DOCTYPE/ENTITY flagged, external entities never resolved), HTML,
  CSV/TSV, TOML, RTF, plain text, and OOXML. Flags PDF JavaScript/Launch/
  EmbeddedFile and Office macros without running them.
- `crypto.py` — `crypto_analyze`: frequency/IoC, Caesar/ROT/Atbash, single-byte
  and repeating-key XOR, Vigenere (keyed or auto-cracked), rail-fence, JWT decode
  (`alg=none`/HS* flags), hash identification, and a bounded RSA attack. `mode`
  selects an analysis; `auto` runs the applicable ones and ranks candidates.
- `tools.py` — assembles the fixed registry in `build_solver_registry(root,
  timeout, out_limit, flag_pattern=None)`; the challenge's declared `flag_format`
  is compiled once and baked into every tool so flag-shaped strings surface in
  structured evidence. Also registers `list_capabilities`.

### Autonomous workflow (Phase 2)

1. **Identify** the category from the prompt/files and seed a category-specific
   task plan (`planner.build_initial_plan`).
2. **Triage cheaply first**: `file_identify` / `list_capabilities`, then the
   category-appropriate tool.
3. **Follow observations**, not scripts: the model names the missing fact and
   proposes the least expensive tool that fills it.
4. **Track attempts**: the evidence digest fed back to the model includes an
   attempts summary (each tool run with ok/error, rejections, detections, and
   flag verifications) so failed or duplicate actions are not repeated blindly.
5. **Bounded search only**: parameter searches and candidate generation are
   depth/size/time bounded (e.g. XOR key length, decode rounds, archive depth).
6. **Verify** against the challenge's flag format; only a verifier-accepted flag
   ends the run as solved. Solution steps are recorded in the plan/report.

### Safety bounds (Phase 2)

- Files are untrusted data; unknown binaries, macros, scripts, and extracted
  programs are **never executed**.
- Bounded read/scan sizes, bounded archive members/total/entry sizes, bounded
  compression ratio and nesting depth, bounded decode rounds and carve objects,
  bounded candidate/key lengths, and a discarded private temp directory.
- No file contents or secrets are sent to a remote model by default; the solver
  only sends what the existing agent already sends (evidence digests), and the
  opt-in remote verifier submits only the candidate flag to a configured endpoint.
- `list_capabilities` makes the "what is missing" explicit instead of silent.

### Phase 2 test coverage (`tests/test_ctf_analysis_tools.py`)

Synthetic, fully offline fixtures: encodings (base64/hex/bits/url, nested chain),
compressed and malformed archives, zip path-traversal + bomb-ratio flags, images
with text chunks and appended data, a hand-built PCAP, documents (JSON/HTML/XML/
CSV), and classical-crypto challenges (Caesar/XOR/Vigenere/JWT/RSA/hash). Resource
limits (bounded reads, decode round cap) and confinement (path traversal) are
tested directly.

## Phase 3 — authorized web solving

Phase 3 adds a bounded, scope-pinned HTTP capability to the **same** solver
registry. It is off unless a challenge explicitly authorizes a single origin, and
even then every request passes through the same execution-time guard. Nothing in
the model's output can widen the scope.

### New modules under `gryphos/ctf/`

- `webconfig.py` — `WebConfig`: the operator's authorization (one `origin`,
  optional `lab`, cross-origin-redirect opt-in, and clamped `max_requests` /
  `max_body_bytes` / `min_interval_ms` bounds). Loaded from the challenge's `web`
  block; a missing block means no web tools at all.
- `webscope.py` — `WebScope`: turns the config into an execution boundary.
  Validates scheme/host/port/path, refuses cross-origin unless opted in, and
  **re-resolves the host on every request, rejecting the request if any resolved
  address is blocked**. Cloud-metadata/link-local/multicast ranges are blocked
  unconditionally; private/loopback/reserved need `lab: true`.
- `webclient.py` — `WebClient`: a bounded HTTP client pinned to a validated IP
  (Host header + TLS SNI preserved, redirects never followed silently). Enforces
  the request budget and min-interval, caps body reads, retries idempotent GET/HEAD
  on transient failures, dedups identical requests (fingerprint includes cookie
  state) unless a comparison deliberately repeats one, keeps an in-memory cookie
  jar (Secure cookies withheld over http), and redacts cookies / `Authorization` /
  sensitive query & body values.
- `webtools.py` — the registered tools (below) plus an HTML/JS structural parser
  and a `collect_web_clues` synthesizer shared by `web_clues` and the report.

### Registered web tools

- `web_fetch` — fetch one same-origin resource (GET/HEAD), optional same-origin
  redirect chain, renders status/redacted headers/bounded body.
- `web_crawl` — bounded breadth-first same-origin link traversal (`max_pages`,
  `depth`); offsite links are listed but never fetched.
- `web_analyze` — page structure: title, meta, forms + fields, same-origin vs
  offsite links, external/inline scripts, referenced endpoint paths, HTML comments,
  optional `/robots.txt` and `/sitemap.xml`.
- `web_session` — submit a form / authenticate, track the session cookie jar, and
  report set-cookie names, held cookies, and present/missing security headers
  (cookie values always redacted).
- `web_probe` — send up to six controlled same-origin variants (query params,
  form fields, headers) and compare status/size/body; JSON responses are summarized.
- `web_clues` — **offline** (no network) prioritization of the web evidence
  gathered so far: endpoints, forms, cookies, parameters, JSON keys, comment hints,
  offsite refs, missing security headers, and flag candidates, ranked by
  security-relevant keywords.

All web tools bake in the challenge's `flag_format`, so flags surfacing in any
fetched body appear in structured evidence.

### Safety bounds (Phase 3)

- **Authorization is explicit and configuration-driven.** No `web` block → no web
  tools. `GRYPHOS_CTF_WEB_ENABLED=false` disables them even when declared.
- **Scope is enforced at execution time**, per request and per redirect hop; the
  resolved IP — not the model's chosen string — is what is contacted.
- Methods are restricted to GET/HEAD/POST/OPTIONS; body size, request count, and
  rate are bounded; response bodies are read with a hard byte cap.
- Cookies, `Authorization` headers, and sensitive query/body values are redacted
  before anything reaches the model, evidence, or the report. The write-up shows
  cookie **names** only.
- The solver treats every response as untrusted data, never as instructions.

### Phase 3 test coverage

Fully offline, using a local mock HTTP server (`tests/webserver.py`) bound to
`127.0.0.1`; no public target is ever contacted:

- `tests/test_ctf_web_config.py` — origin/bounds validation, `lab` requirement,
  ceiling clamps.
- `tests/test_ctf_webscope.py` — IP policy, blocked ranges, cross-origin refusal,
  path/DoS guards.
- `tests/test_ctf_webclient.py` — budget, size caps, retries, dedup vs deliberate
  repeats, method restrictions, redirect handling, redaction.
- `tests/test_ctf_webtools.py` — each tool end-to-end against the mock server,
  including flag surfacing, cookie tracking, Secure-cookie handling, probe
  comparison, and clue ranking.
- `tests/test_ctf_web_solve.py` — solver integration (fetch→verify), prompt/plan
  seeding, the kill switch, and that an origin is unreachable without authorization.

## Phase 4 — authorized network solving

Phase 4 adds a bounded, scope-pinned **TCP** capability to the same solver
registry, so the solver can work a network host (e.g. a TryHackMe machine) rather
than only web origins. It is off unless a challenge explicitly authorizes a single
`target`, and even then every connection passes through the same execution-time
guard. This phase is **reconnaissance only**: port scanning, banner/service
fingerprinting, and read-only HTTP(S) probes. There is no exploitation, no
state-changing action, and no write primitive.

Phase 3 and Phase 4 share one IP policy (`ipguard.py`): the web and network scopes
both resolve the destination and reject the connection if **any** resolved address
is blocked, so a hostname cannot rebind to a metadata/link-local address.

### New modules under `gryphos/ctf/`

- `ipguard.py` — the shared address policy: `check_host` resolves a host and
  enforces the always-blocked ranges (cloud metadata, link-local, multicast,
  reserved) and the lab-only ranges (loopback, private, CGNAT, test-net).
- `netconfig.py` — `TargetConfig`: the operator's authorization (one `host`,
  optional `lab`, a declared `ports` spec, and clamped `max_ports` /
  `max_connections` / `connect_timeout_ms` / `min_interval_ms` bounds). Loaded from
  the challenge's `target` block; a missing block means no network tools at all.
- `netscope.py` — `NetScope`: turns the config into an execution boundary. The
  configured host must itself satisfy the IP policy (fail fast), a requested host
  must equal the authorized one, and requested ports are parsed and bounded.
- `netclient.py` — `NetClient`: a bounded TCP client pinned to one validated IP.
  Enforces the connection budget, the optional min-interval rate limit, a
  wall-clock deadline, and a bounded worker pool; caps and sanitizes banner reads;
  records transport errors as data. `service_hint` maps a port/banner to a likely
  service name (never authoritative).
- `nettools.py` — the registered tools (below) plus a `collect_net_clues`
  synthesizer shared by `net_clues` and the report. The HTTP probe reuses the
  Phase 3 pinned connection class and response redaction.

### Registered network tools

- `net_portscan` — bounded TCP connect scan of a port range (or `top=true` for a
  built-in common-port set); reports open/closed/filtered ports and optionally
  reads a short banner from each open port.
- `net_service_probe` — banner grab / service fingerprint on specific ports, or on
  the ports already discovered.
- `net_http_probe` — bounded GET/HEAD to an HTTP(S) service on the target, with a
  redacted status/headers/body; several `paths` can be checked in one step.
- `net_clues` — **offline** (no network) prioritization of the network evidence
  gathered so far: open ports, services, banners, and probed HTTP endpoints, ranked
  by security-relevant keywords.

All network tools bake in the challenge's `flag_format`, so flags surfacing in any
banner or response body appear in structured evidence. A `target` can also be
authorized at run time with `solve <id> --target <host> [--lab]`, which builds or
overrides the challenge's `target` block.

### Safety bounds (Phase 4)

- **Authorization is explicit and configuration-driven.** No `target` block → no
  network tools. `GRYPHOS_CTF_NET_ENABLED=false` disables them even when declared.
- **Scope is enforced at execution time**, per connection: only the authorized host
  is ever contacted, and the resolved/validated IP is what is dialed.
- Only non-destructive reconnaissance exists; there is no exploitation or
  state-changing module in this phase.
- Ports, connection count, per-connect timeout, and rate are hard-bounded; the
  challenge cannot raise its own ceilings.
- Banners and HTTP responses are treated as untrusted data, never as instructions.

### Phase 4 test coverage

Fully offline, using a local mock TCP server (`tests/tcpserver.py`) and the Phase 3
mock HTTP server, both bound to `127.0.0.1`; no public target is ever contacted:

- `tests/test_ctf_net_config.py` — host/port/bounds validation, ceiling clamps,
  `target` block parsing and loader integration.
- `tests/test_ctf_netscope.py` — single-target policy, IP policy, blocked ranges,
  port bounds.
- `tests/test_ctf_nettools.py` — scan/probe/http/clues end-to-end against the mocks,
  including banner fingerprinting, flag surfacing, budget exhaustion, and registry
  gating.
- `tests/test_ctf_net_solve.py` — solver integration (scan→verify), prompt/plan
  seeding, the kill switch, absence without authorization, private-without-lab
  refusal, the network report section, and CLI argument parsing.
