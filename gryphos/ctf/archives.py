"""Archive and compressed-stream inspection with safety limits.

Lists members of zip/tar (and 7z/rar when the `7z` binary is present) and
profiles gzip/bzip2/xz streams -- without extracting into the challenge tree and
without ever executing member content. Every archive is checked for absolute
paths, `..` traversal, symlink/hardlink members, encrypted entries, oversize
members, and decompression-bomb ratios. Nested archives are recursed to a
bounded depth using a private temporary directory.
"""

from __future__ import annotations

import bz2
import gzip
import lzma
import posixpath
import tarfile
import zipfile
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath

from ..tools.base import ToolResult, ToolSpec, duration_since
from .deps import optional_binary
from .sandbox import (
    MAX_ARCHIVE_DEPTH,
    MAX_ARCHIVE_ENTRY_BYTES,
    MAX_ARCHIVE_MEMBERS,
    MAX_ARCHIVE_RATIO,
    MAX_SCAN_BYTES,
    attach_flags,
    relative_label,
    resolve_inside,
    safe_tempdir,
)

_ARCHIVE_EXTS = (".zip", ".tar", ".gz", ".tgz", ".bz2", ".xz", ".7z", ".rar", ".zst")


def _member_flags(name: str, size: int, compress_size: int, tm: tarfile.TarInfo | None) -> list[str]:
    flags: list[str] = []
    if PurePosixPath(name.replace("\\", "/")).is_absolute() or (len(name) > 1 and name[1] == ":"):
        flags.append("absolute-path")
    normalized = posixpath.normpath(name.replace("\\", "/"))
    if normalized == ".." or normalized.startswith("../") or "/../" in normalized:
        flags.append("path-traversal")
    if tm is not None:
        if tm.issym():
            flags.append("symlink")
        if tm.islnk():
            flags.append("hardlink")
        if not (tm.isfile() or tm.isdir()):
            flags.append("special-file")
    if size > MAX_ARCHIVE_ENTRY_BYTES:
        flags.append("oversize")
    if compress_size > 0 and size / compress_size > MAX_ARCHIVE_RATIO:
        flags.append("high-compression-ratio")
    return flags


def _is_archive_name(name: str) -> bool:
    return name.lower().endswith(_ARCHIVE_EXTS)


def _stream_kind(data: bytes) -> str | None:
    if data[:6] == b"\xfd7zXZ\x00":
        return "xz"
    if data[:2] == b"\x1f\x8b":
        return "gzip"
    if data[:3] == b"BZh":
        return "bzip2"
    if data[:4] in (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08"):
        return "zip"
    if data[:6] == b"7z\xbc\xaf\x27\x1c":
        return "7z"
    if data[:7] in (b"Rar!\x1a\x07\x00", b"Rar!\x1a\x07\x01"):
        return "rar"
    return None


def _inspect_bytes(data: bytes, depth: int, max_depth: int) -> dict | None:
    """Inspect an in-memory archive blob, returning a nested summary or None."""
    if depth >= max_depth or len(data) > MAX_ARCHIVE_ENTRY_BYTES:
        return None
    kind = _stream_kind(data)
    if kind is None:
        return None
    with safe_tempdir() as tmp:
        blob = tmp / "member"
        blob.write_bytes(data)
        try:
            return _inspect_path(blob, depth + 1, max_depth)
        except Exception:  # noqa: BLE001 - a malformed nested blob is reported as unreadable
            return {"kind": kind, "error": "nested archive could not be read", "members": []}


def _inspect_path(path: Path, depth: int, max_depth: int) -> dict:
    with path.open("rb") as handle:
        head = handle.read(512)
    if zipfile.is_zipfile(path) or head[:4] in (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08"):
        return _inspect_zip(path, depth, max_depth)
    if tarfile.is_tarfile(path):
        return _inspect_tar(path, depth, max_depth)
    if head[:2] == b"\x1f\x8b":
        return _inspect_stream(path, "gzip", gzip.decompress)
    if head[:3] == b"BZh":
        return _inspect_stream(path, "bzip2", bz2.decompress)
    if head[:6] == b"\xfd7zXZ\x00":
        return _inspect_stream(path, "xz", lzma.decompress)
    if head[:6] == b"7z\xbc\xaf\x27\x1c" or head[:7] in (b"Rar!\x1a\x07\x00", b"Rar!\x1a\x07\x01"):
        return _inspect_external(path)
    return {"kind": "unknown", "members": [], "note": "not a recognized archive or stream"}


def _inspect_zip(path: Path, depth: int, max_depth: int) -> dict:
    members: list[dict] = []
    total = 0
    nested: list[dict] = []
    try:
        with zipfile.ZipFile(path) as archive:
            for info in archive.infolist()[:MAX_ARCHIVE_MEMBERS]:
                total += info.file_size
                entry = {
                    "name": info.filename,
                    "size": info.file_size,
                    "compressed": info.compress_size,
                    "ratio": round(info.file_size / info.compress_size, 1) if info.compress_size else None,
                    "encrypted": bool(info.flag_bits & 0x1),
                }
                entry["flags"] = _member_flags(info.filename, info.file_size, info.compress_size, None)
                if entry["encrypted"]:
                    entry["flags"].append("encrypted")
                members.append(entry)
                if (
                    _is_archive_name(info.filename)
                    and depth + 1 < max_depth
                    and info.file_size <= MAX_ARCHIVE_ENTRY_BYTES
                    and not entry["encrypted"]
                ):
                    try:
                        nested_summary = _inspect_bytes(archive.read(info), depth, max_depth)
                    except Exception:  # noqa: BLE001 - a bad member is not fatal
                        nested_summary = None
                    if nested_summary:
                        nested.append({"name": info.filename, "summary": nested_summary})
    except (zipfile.BadZipFile, OSError):
        return {"kind": "zip", "error": "malformed zip: bad central directory", "members": []}
    return {
        "kind": "zip",
        "member_count": len(members),
        "total_uncompressed": total,
        "members": members,
        "nested": nested,
    }


def _inspect_tar(path: Path, depth: int, max_depth: int) -> dict:
    members: list[dict] = []
    total = 0
    nested: list[dict] = []
    try:
        with tarfile.open(path, "r:*") as archive:
            for info in archive:
                total += info.size
                entry = {
                    "name": info.name,
                    "size": info.size,
                    "type": "file" if info.isfile() else ("dir" if info.isdir() else "other"),
                }
                entry["flags"] = _member_flags(info.name, info.size, 0, info)
                members.append(entry)
                if len(members) >= MAX_ARCHIVE_MEMBERS:
                    break
                if (
                    info.isfile()
                    and _is_archive_name(info.name)
                    and depth + 1 < max_depth
                    and info.size <= MAX_ARCHIVE_ENTRY_BYTES
                ):
                    extracted = archive.extractfile(info)
                    if extracted is not None:
                        nested_summary = _inspect_bytes(extracted.read(), depth, max_depth)
                        if nested_summary:
                            nested.append({"name": info.name, "summary": nested_summary})
    except (tarfile.TarError, OSError):
        return {"kind": "tar", "error": "malformed tar: could not read members", "members": []}
    return {
        "kind": "tar",
        "member_count": len(members),
        "total_uncompressed": total,
        "members": members,
        "nested": nested,
    }


def _inspect_stream(path: Path, label: str, decompress) -> dict:
    size = path.stat().st_size
    try:
        with path.open("rb") as handle:
            data = handle.read(MAX_SCAN_BYTES)
        out = decompress(data)
    except (OSError, EOFError, lzma.LZMAError) as exc:
        return {"kind": label, "error": f"could not decompress: {type(exc).__name__}", "members": []}
    truncated = len(out) > MAX_ARCHIVE_ENTRY_BYTES
    body = out[:MAX_ARCHIVE_ENTRY_BYTES]
    ratio = round(len(out) / size, 1) if size else None
    return {
        "kind": label,
        "compressed_size": size,
        "uncompressed_size": len(out),
        "truncated": truncated,
        "ratio": ratio,
        "flags": ["high-compression-ratio"] if ratio and ratio > MAX_ARCHIVE_RATIO else [],
        "preview": body[:200].decode("utf-8", errors="replace"),
        "members": [],
        "nested": [],
    }


def _inspect_external(path: Path) -> dict:
    binary = optional_binary("7z")
    if not binary:
        return {
            "kind": path.suffix.lstrip("."),
            "members": [],
            "note": "listing this archive requires the optional '7z' binary, which is not installed",
        }
    import subprocess

    try:
        completed = subprocess.run(
            [binary, "l", "-slt", "--", str(path)], capture_output=True, text=True, timeout=20, check=False
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return {"kind": path.suffix.lstrip("."), "members": [], "note": f"7z failed: {type(exc).__name__}"}
    members: list[dict] = []
    current: dict | None = None
    for line in (completed.stdout or "").splitlines():
        if line.startswith("Path = "):
            if current:
                members.append(current)
            current = {"name": line[7:], "size": 0}
        elif line.startswith("Size = ") and current is not None:
            try:
                current["size"] = int(line[7:])
            except ValueError:
                current["size"] = 0
    if current:
        members.append(current)
    members = members[:MAX_ARCHIVE_MEMBERS]
    for entry in members:
        entry["flags"] = _member_flags(entry.get("name", ""), entry.get("size", 0), 0, None)
    return {"kind": path.suffix.lstrip("."), "member_count": len(members), "members": members, "nested": []}


def inspect_archive(root: Path, path: str, max_depth: int, fmt=None) -> ToolResult:
    started = datetime.now(UTC)
    target = resolve_inside(root, path)
    depth = max(0, min(int(max_depth), MAX_ARCHIVE_DEPTH))
    summary = _inspect_path(target, 0, depth)
    label = relative_label(root, target)
    members = summary.get("members", [])
    flagged = [m for m in members if m.get("flags")]

    lines = [f"Archive: {label}", f"Kind: {summary.get('kind')}"]
    if summary.get("error"):
        lines.append(f"Error: {summary['error']}")
    if summary.get("note"):
        lines.append(f"Note: {summary['note']}")
    if "member_count" in summary:
        lines.append(
            f"Members: {summary['member_count']} "
            f"(uncompressed total {summary.get('total_uncompressed', 0)} bytes)"
        )
    if "uncompressed_size" in summary:
        lines.append(
            f"Stream: compressed {summary['compressed_size']} -> uncompressed {summary['uncompressed_size']} "
            f"bytes (ratio {summary.get('ratio')}, truncated={summary.get('truncated')})"
        )
        lines.append("Preview: " + (summary.get("preview", "")[:400].replace("\n", " ")))
    if flagged:
        lines.append(f"Safety flags on {len(flagged)} member(s):")
        for entry in flagged[:40]:
            lines.append(f"  ! {entry['name']} -> {', '.join(entry['flags'])}")
    lines.append("Members:")
    for entry in members[:100]:
        ratio = entry.get("ratio")
        extra = f", ratio={ratio}" if ratio is not None else ""
        lines.append(f"  {entry['name']} ({entry.get('size', 0)} bytes{extra})")
    for nested in summary.get("nested", []):
        sub = nested.get("summary", {})
        lines.append(f"Nested [{nested['name']}] kind={sub.get('kind')} members={sub.get('member_count', '?')}")
    if len(members) > 100:
        lines.append(f"  ... {len(members) - 100} more")

    return attach_flags(
        ToolResult(
            tool="archive_inspect",
            target=label,
            display=f"archive_inspect(path={path!r})",
            returncode=0,
            output="\n".join(lines)[:20000],
            network_active=False,
            activity="passive",
            started_at=started.isoformat(),
            duration_seconds=duration_since(started),
            data={"path": label, **summary},
        ),
        fmt,
    )


def archive_inspect_spec(root: Path, timeout: int, out_limit: int, fmt=None) -> ToolSpec:
    return ToolSpec(
        name="archive_inspect",
        description=(
            "List and profile an archive or compressed stream (zip, tar, gzip, bzip2, "
            "xz; 7z/rar with the optional '7z' binary) without executing or extracting "
            "into the challenge. Flags path traversal, symlinks, encryption, oversize "
            "members, and decompression bombs; recurses nested archives to a bounded depth."
        ),
        purpose="Safely understand archive structure and contents before extracting anything.",
        input_schema={
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Path relative to the challenge directory."},
                "max_depth": {"type": "integer", "minimum": 0, "maximum": MAX_ARCHIVE_DEPTH},
            },
            "required": ["path"],
            "additionalProperties": False,
        },
        risk="informational",
        side_effects="None: reads bounded member metadata; never writes into the challenge.",
        network_active=False,
        approval_policy="none",
        timeout=min(timeout, 30),
        max_output_chars=out_limit,
        activity="passive",
        approval_level=1,
        scope_requirements="Confined to the challenge directory; no network access.",
        result_schema={"type": "object", "properties": {
            "kind": {"type": "string"}, "members": {"type": "array"}, "nested": {"type": "array"},
        }},
        show=lambda args: f"archive_inspect(path={args.get('path')!r})",
        execute=lambda args, scope_items, evidence=None: inspect_archive(
            root, str(args.get("path", "")), int(args.get("max_depth", 3)), fmt
        ),
    )
