"""Solver tool registry.

The solver is given a deliberately small, fixed tool surface built on the same
`ToolSpec` contract as the assessment tools. Every tool is offline, read-only
against the challenge directory, and bounded:

- `challenge_file` — read/list files *inside the challenge directory* (path is
  resolved and required to stay within the root; traversal, absolute paths, and
  symlink escapes are rejected). Records size and SHA-256.
- `file_identify` — magic bytes, hashes, entropy, strings, embedded signatures.
- `encoding_decode` — detect/decode common text and byte encodings, recursively.
- `archive_inspect` — list/profile archives and compressed streams with limits.
- `image_triage` — image metadata plus appended-data / LSB stego triage.
- `pcap_summary` — offline PCAP/PCAP-NG dissection and payload strings.
- `document_parse` — safe text/metadata extraction from documents/formats.
- `crypto_analyze` — classical ciphers, XOR, frequency, JWT, hash, bounded RSA.
- `artifact_extract` — carve embedded objects / byte ranges (never executed).
- `list_capabilities` — report which optional binaries/libraries are present.
- `summarize_evidence` — the existing offline evidence lens.

This registry is separate from the assessment registry on purpose: `solve` and
`assess` expose different, minimal capabilities. When a challenge declares a
`flag_format`, it is baked into every tool so flag-shaped strings surface in the
structured evidence the solver sees.

A challenge may additionally authorize one web origin (`web`) and/or one network
target (`target`). The matching `web_*` / `net_*` tools are added only when the
caller supplies the corresponding scope+client, so an unauthorized challenge has
no network capability at all.
"""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from pathlib import Path

from ..analysis import summarize_evidence_spec
from ..tools.base import ToolError, ToolResult, ToolSpec, duration_since
from .archives import archive_inspect_spec
from .crypto import crypto_analyze_spec
from .deps import capabilities_report, capability_status
from .documents import document_parse_spec
from .encoding import encoding_decode_spec
from .filetools import artifact_extract_spec, file_identify_spec
from .flag import FlagFormat
from .images import image_triage_spec
from .netclient import NetClient
from .netscope import NetScope
from .nettools import (
    net_clues_spec,
    net_http_probe_spec,
    net_portscan_spec,
    net_service_probe_spec,
)
from .pcap import pcap_summary_spec
from .webclient import WebClient
from .webscope import WebScope
from .webtools import (
    web_analyze_spec,
    web_clues_spec,
    web_crawl_spec,
    web_fetch_spec,
    web_probe_spec,
    web_session_spec,
)

MAX_READ_BYTES = 65536
_HEX_PREVIEW_BYTES = 256


def _is_inside(root: Path, candidate: Path) -> bool:
    try:
        candidate.resolve().relative_to(root.resolve())
        return True
    except ValueError:
        return False


def _read_challenge_file(
    root: Path,
    path: str,
    max_bytes: int,
    out_limit: int,
) -> ToolResult:
    raw = (path or "").strip()
    if not raw:
        raise ToolError("A file path within the challenge directory is required.")
    if Path(raw).is_absolute() or raw.startswith("~"):
        raise ToolError("Path must be relative to the challenge directory (no absolute paths).")
    root = Path(root).resolve()
    target = (root / raw).resolve()
    if not _is_inside(root, target):
        raise ToolError(
            "Refused: the path escapes the challenge directory. Only files inside "
            "the configured challenge may be read."
        )
    if not target.exists():
        raise ToolError(f"No such file in the challenge: {raw}")
    started = datetime.now(UTC)
    if target.is_dir():
        entries = sorted(p.relative_to(root).as_posix() for p in target.iterdir())
        entries = entries[:200]
        output = "Directory: " + raw + "\n" + "\n".join(entries)
        return ToolResult(
            tool="challenge_file", target=raw, display=f"challenge_file({raw}) [list]",
            returncode=0, output=output[:out_limit], network_active=False, activity="passive",
            started_at=started.isoformat(), duration_seconds=duration_since(started),
            data={"path": raw, "kind": "directory", "entry_count": len(entries)},
        )
    try:
        data_bytes = target.read_bytes()
    except OSError as exc:
        raise ToolError(f"Could not read {raw}: {type(exc).__name__}") from exc
    size = len(data_bytes)
    digest = hashlib.sha256(data_bytes).hexdigest()
    bounded = data_bytes[: min(max_bytes, MAX_READ_BYTES)]
    text = bounded.decode("utf-8", errors="replace")
    lines = [
        f"File: {raw} ({size} bytes, sha256 {digest})",
        "----",
        text[:out_limit],
    ]
    if size > len(bounded):
        lines.append(f"\n…[truncated at {len(bounded)} bytes]")
    non_printable = sum(1 for b in bounded if b < 9 or (13 < b < 32) or b > 126)
    data = {"path": raw, "size": size, "sha256": digest, "read_bytes": len(bounded)}
    if bounded and non_printable > len(bounded) // 4:
        preview_bytes = bounded[:_HEX_PREVIEW_BYTES]
        lines.append(
            f"\nHex preview (likely binary; first {len(preview_bytes)} bytes):\n{preview_bytes.hex()}"
        )
        data["binary"] = True
    return ToolResult(
        tool="challenge_file", target=raw, display=f"challenge_file({raw})",
        returncode=0, output="\n".join(lines)[: max(out_limit, 0) + 512],
        network_active=False, activity="passive",
        started_at=started.isoformat(), duration_seconds=duration_since(started),
        data=data,
    )


def challenge_file_spec(root: Path, timeout: int, out_limit: int) -> ToolSpec:
    return ToolSpec(
        name="challenge_file",
        description=(
            "Read or list a file inside the challenge directory (read-only). "
            "Path is relative to the challenge root; traversal and absolute paths "
            "are rejected. Records size and SHA-256. Binary files include a hex preview."
        ),
        purpose="Inspect the challenge's provided artifacts without leaving its directory.",
        input_schema={
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Path relative to the challenge directory.",
                },
                "max_bytes": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": MAX_READ_BYTES,
                    "description": "Maximum bytes to read from the file.",
                },
            },
            "required": ["path"],
            "additionalProperties": False,
        },
        risk="informational",
        side_effects="None: read-only access to files within the challenge directory.",
        network_active=False,
        approval_policy="none",
        timeout=min(timeout, 15),
        max_output_chars=out_limit,
        activity="passive",
        approval_level=1,
        scope_requirements="Confined to the challenge directory; no network access.",
        result_schema={"type": "object", "properties": {
            "path": {"type": "string"},
            "size": {"type": "integer"},
            "sha256": {"type": "string"},
        }},
        show=lambda args: f"challenge_file(path={args.get('path')!r})",
        execute=lambda args, scope_items, evidence=None: _read_challenge_file(
            root,
            str(args.get("path", "")),
            int(args.get("max_bytes", MAX_READ_BYTES)),
            out_limit,
        ),
    )


def list_capabilities_spec(timeout: int, out_limit: int) -> ToolSpec:
    def _run(args, scope_items, evidence=None) -> ToolResult:
        started = datetime.now(UTC)
        return ToolResult(
            tool="list_capabilities",
            target="(local)",
            display="list_capabilities()",
            returncode=0,
            output=capabilities_report()[:out_limit],
            network_active=False,
            activity="passive",
            started_at=started.isoformat(),
            duration_seconds=duration_since(started),
            data={"capabilities": capability_status()},
        )

    return ToolSpec(
        name="list_capabilities",
        description=(
            "Report which optional binaries and Python libraries are available locally "
            "(file, strings, binwalk, exiftool, 7z, tshark, PIL, scapy, ...) and what is "
            "missing. Gryphos never installs anything; this only tells the solver which "
            "tools can be used and where a bounded fallback applies."
        ),
        purpose="Choose tooling appropriate to the environment and report gaps to the operator.",
        input_schema={"type": "object", "properties": {}, "additionalProperties": False},
        risk="informational",
        side_effects="None: probes availability only.",
        network_active=False,
        approval_policy="none",
        timeout=min(timeout, 10),
        max_output_chars=out_limit,
        activity="passive",
        approval_level=1,
        scope_requirements="None: local capability probe; no files or network.",
        result_schema={"type": "object", "properties": {"capabilities": {"type": "array"}}},
        show=lambda args: "list_capabilities()",
        execute=_run,
    )


def build_solver_registry(
    root: Path,
    timeout: int,
    out_limit: int,
    flag_pattern: str | None = None,
    web_scope: WebScope | None = None,
    web_client: WebClient | None = None,
    net_scope: NetScope | None = None,
    net_client: NetClient | None = None,
) -> dict[str, ToolSpec]:
    """Return the fixed solver tool set.

    `flag_pattern`, when supplied (the challenge's declared `flag_format`), is
    compiled once and baked into every tool so flag-shaped strings are detected
    inside each tool's own rendering and surfaced in structured evidence.

    When a challenge declares an authorized web mission, the caller passes a
    matching `web_scope`/`web_client`; the read-oriented web tools are then added
    to the registry. When a challenge declares an authorized network `target`, the
    caller passes a matching `net_scope`/`net_client` and the network tools are
    added. Without these the solver has no network capability at all.
    """
    fmt = FlagFormat(flag_pattern) if flag_pattern else FlagFormat()
    specs = [
        challenge_file_spec(root, timeout, out_limit),
        file_identify_spec(root, timeout, out_limit, fmt),
        encoding_decode_spec(root, timeout, out_limit, fmt),
        archive_inspect_spec(root, timeout, out_limit, fmt),
        image_triage_spec(root, timeout, out_limit, fmt),
        pcap_summary_spec(root, timeout, out_limit, fmt),
        document_parse_spec(root, timeout, out_limit, fmt),
        crypto_analyze_spec(root, timeout, out_limit, fmt),
        artifact_extract_spec(root, timeout, out_limit, fmt),
        list_capabilities_spec(timeout, out_limit),
        summarize_evidence_spec(timeout, out_limit),
    ]
    if web_scope is not None and web_client is not None:
        specs.append(web_fetch_spec(web_scope, web_client, fmt, timeout, out_limit))
        specs.append(web_crawl_spec(web_scope, web_client, fmt, timeout, out_limit))
        specs.append(web_analyze_spec(web_scope, web_client, fmt, timeout, out_limit))
        specs.append(web_session_spec(web_scope, web_client, fmt, timeout, out_limit))
        specs.append(web_probe_spec(web_scope, web_client, fmt, timeout, out_limit))
        specs.append(web_clues_spec(fmt, out_limit))
    if net_scope is not None and net_client is not None:
        specs.append(net_portscan_spec(net_scope, net_client, fmt, timeout, out_limit))
        specs.append(net_service_probe_spec(net_scope, net_client, fmt, timeout, out_limit))
        specs.append(net_http_probe_spec(net_scope, net_client, fmt, timeout, out_limit))
        specs.append(net_clues_spec(fmt, out_limit))
    registry = {spec.name: spec for spec in specs}
    if len(registry) != len(specs):
        raise ValueError("Duplicate solver tool name.")
    return registry
