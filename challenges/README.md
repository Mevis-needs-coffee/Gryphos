# CTF challenges

Each challenge is a self-contained directory:

```
challenges/<id>/challenge.json
challenges/<id>/<provided files...>
```

Run one in the CLI with:

```
solve <id>
```

`solve` with no id lists the challenges found here. The solver is confined to the
challenge directory: every tool only reads files inside it (path traversal and
absolute paths are rejected), never the wider filesystem, and it makes no network
activity by itself. The read-only tools are `challenge_file`, `file_identify`,
`encoding_decode`, `archive_inspect`, `image_triage`, `pcap_summary`,
`document_parse`, `crypto_analyze`, `artifact_extract`, and `list_capabilities`
(plus the passive `summarize_evidence` lens); nothing is executed. A challenge may
additionally declare a `web` block to authorize a single web origin and/or a
`target` block to authorize a single network host; only then do the matching
network `web_*` / `net_*` tools exist (see below).

## challenge.json fields

| Field | Required | Meaning |
|---|---|---|
| `id` | yes* | Challenge id (letters, digits, `.`, `_`, `-`). Must match the directory name. |
| `name` | no | Display name (defaults to the id). |
| `category` | yes | One of: `misc`, `encoding`, `crypto`, `forensics`, `stego`, `web`, `network`, `reverse_engineering`, `binary_exploitation`. |
| `description` | no | Background shown to the solver. |
| `task` | no | What must be done. |
| `flag_format` | no | A regex the flag must fully match. Omit to use the built-in default (`flag{...}`, `ctf{...}`, etc.). |
| `submit` | no | Optional CTFd-style `{"url", "token", "field"}` for remote verification. Only used when `GRYPHOS_CTF_REMOTE_VERIFY=true`. |
| `files` | no | Explicit provided-file list. If omitted, all files in the directory (except `challenge.json`) are listed. |
| `web` | no | Authorizes a single web origin (see below). Without it the solver has **no web tools**. |
| `target` | no | Authorizes a single network host for bounded reconnaissance (see below). Without it the solver has **no network-scan tools**. |

\* If `id` is omitted, the directory name is used.

## The `web` block (authorized web solving)

Adding a `web` block is the operator's explicit authorization for the solver to
make HTTP requests — **only** to that one origin. If a challenge has no `web`
block, no web tools exist and the solver cannot contact anything.

```json
"web": {
  "origin": "http://127.0.0.1:8080",
  "lab": true,
  "allow_cross_origin_redirects": false,
  "max_requests": 40,
  "max_body_bytes": 262144,
  "min_interval_ms": 0
}
```

| Field | Required | Meaning |
|---|---|---|
| `origin` | yes | Plain `scheme://host[:port]`, no path/query/credentials. The **only** origin reachable. |
| `lab` | no | Must be `true` to allow loopback/private/reserved/CGNAT/test-net destinations. Default `false`. |
| `allow_cross_origin_redirects` | no | Permit redirects to a different origin (still IP-validated). Default `false`. |
| `max_requests` | no | Request budget per run (default 40, ceiling 500). |
| `max_body_bytes` | no | Per-response body cap (default 262144, ceiling 4194304). |
| `min_interval_ms` | no | Minimum delay between requests (default 0, ceiling 5000). |

Safety properties (enforced in code, not by the model):

- The host is **re-resolved on every request and every resolved address is
  validated**, defeating DNS rebinding to a blocked address.
- Cloud metadata (`169.254.169.254`), link-local, multicast, and reserved ranges
  are blocked **unconditionally** — even for a `lab` origin.
- Cross-origin redirects are refused unless explicitly enabled, and are still
  IP-validated when they are.
- Methods are limited to GET/HEAD/POST/OPTIONS; responses are size-capped;
  cookies, authorization headers, and sensitive query/body values are redacted
  before they reach the model, evidence, or the report.
- `GRYPHOS_CTF_WEB_ENABLED=false` forces all web tools off globally.

Web tools registered when a `web` origin is authorized: `web_fetch` (one resource),
`web_crawl` (bounded same-origin link traversal), `web_analyze` (page structure:
forms, links, scripts, endpoints, comments, optional robots/sitemap), `web_session`
(form submit / login, cookie tracking, security headers), `web_probe` (compare up
to six controlled inputs), and `web_clues` (offline, no-network clue ranking).

## The `target` block (authorized network solving)

Adding a `target` block is the operator's explicit authorization for the solver to
open TCP connections — **only** to that one host. If a challenge has no `target`
block, no network-scan tools exist and the solver cannot contact anything. This is
the network-reconnaissance analogue of the `web` block and is what lets the solver
work a TryHackMe-style machine (typically a private VPN address, so `lab: true`).

```json
"target": {
  "host": "10.10.5.12",
  "lab": true,
  "ports": "1-1024",
  "max_ports": 1024,
  "max_connections": 200,
  "connect_timeout_ms": 1500,
  "min_interval_ms": 0
}
```

| Field | Required | Meaning |
|---|---|---|
| `host` | yes | The **only** IP/hostname reachable. A hostname is re-resolved and every address validated on each connection. |
| `lab` | no | Must be `true` to allow loopback/private/reserved/CGNAT/test-net destinations. Default `false`. |
| `ports` | no | Declared port spec for scans: `"80"`, `"1-1024"`, or `"22,80,443"` (default `"1-1024"`). |
| `max_ports` | no | Cap on ports selected by a spec (default 1024, ceiling 4096). |
| `max_connections` | no | Per-run TCP connection budget (default 200, ceiling 2000). |
| `connect_timeout_ms` | no | Per-connect timeout (default 1500, floor 100, ceiling 5000). |
| `min_interval_ms` | no | Minimum delay between connections (default 0, ceiling 5000). |

Safety properties (enforced in code, not by the model):

- The solver may contact **only** the authorized host; any other host is refused.
- The host is **re-resolved on every connection and every resolved address is
  validated**, defeating DNS rebinding to a blocked address.
- Cloud metadata (`169.254.169.254`), link-local, multicast, and reserved ranges
  are blocked **unconditionally** — even for a `lab` target.
- Ports, connection count, per-connect timeout, and rate are all bounded; a
  challenge cannot raise its own limits beyond the hard ceilings.
- Only **non-destructive reconnaissance** is available (no write actions, no
  exploitation); banners and responses are treated as untrusted data.
- `GRYPHOS_CTF_NET_ENABLED=false` forces all network tools off globally.

You can also authorize a target at run time without editing the challenge, for a
FT target you own:

```
solve <id> --target 10.10.5.12 --lab
```

Network tools registered when a `target` is authorized: `net_portscan` (bounded
TCP connect scan, optional banner grab, `top=true` for common ports),
`net_service_probe` (banner/service fingerprint on specific or discovered ports),
`net_http_probe` (bounded GET/HEAD to an HTTP(S) service, redacted responses), and
`net_clues` (offline, no-network clue ranking).

## Honesty model

A flag is only reported as **solved** when a verifier accepts a candidate. String
detection alone (a `flag{...}`-shaped match in a file) is recorded as an
**unverified** candidate, never as success. With the default offline verifier,
acceptance means "matches the declared flag format" and the report says so
explicitly; only a configured submit endpoint yields independent confirmation.

## Remote verification

Remote submission is **off by default**. To enable the CTFd-style verifier for a
challenge that declares a `submit` block, set:

```env
GRYPHOS_CTF_REMOTE_VERIFY=true
```

Only do this for event infrastructure you are authorized to submit to. The
solver still treats a non-accepted candidate as unsolved.
