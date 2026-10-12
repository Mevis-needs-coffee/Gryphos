"""Solver tool registry.

The solver is given a deliberately small, fixed tool surface built on the same
`ToolSpec` contract as the assessment tools:

- `challenge_file` — read-only access to files *inside the challenge directory*.
  The path is resolved and required to stay within the root; traversal, absolute
  paths, and symlink escapes are rejected. Output is bounded and the file's size
  and SHA-256 are recorded as evidence. No shell, no network, no writes.
- `summarize_evidence` — the existing offline evidence lens.

This registry is separate from the assessment registry on purpose: `solve` and
`assess` expose different, minimal capabilities.
"""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from pathlib import Path

from ..analysis import summarize_evidence_spec
from ..tools.base import ToolError, ToolResult, ToolSpec, duration_since

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


def build_solver_registry(root: Path, timeout: int, out_limit: int) -> dict[str, ToolSpec]:
    """Return the fixed solver tool set (confined file reader + evidence lens)."""
    specs = [
        challenge_file_spec(root, timeout, out_limit),
        summarize_evidence_spec(timeout, out_limit),
    ]
    registry = {spec.name: spec for spec in specs}
    if len(registry) != len(specs):
        raise ValueError("Duplicate solver tool name.")
    return registry
