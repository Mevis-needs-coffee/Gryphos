"""File identification, metadata, hashing, strings, signatures, and carving.

Pure standard-library analysis bounded by read/scan limits. `file`, `strings`,
and `binwalk` are used only when present (they are never installed here); the
built-in signature table and strings scanner are the fallbacks. Nothing is
executed and no file is written.
"""

from __future__ import annotations

import binascii
import hashlib
import math
import re
from datetime import UTC, datetime
from pathlib import Path

from ..tools.base import ToolResult, ToolSpec, duration_since
from .sandbox import (
    MAX_ARCHIVE_ENTRY_BYTES,
    MAX_CARVE_OBJECTS,
    MAX_SCAN_BYTES,
    attach_flags,
    read_bounded,
    relative_label,
    resolve_inside,
    safe_tempdir,
)

# (name, mime, extension, offset, magic bytes) — offset-aware magic table.
_SIGNATURES: tuple[tuple[str, str, str, int, bytes], ...] = (
    ("PNG image", "image/png", "png", 0, b"\x89PNG\r\n\x1a\n"),
    ("JPEG image", "image/jpeg", "jpg", 0, b"\xff\xd8\xff"),
    ("GIF image", "image/gif", "gif", 0, b"GIF87a"),
    ("GIF image", "image/gif", "gif", 0, b"GIF89a"),
    ("BMP image", "image/bmp", "bmp", 0, b"BM"),
    ("TIFF image (LE)", "image/tiff", "tiff", 0, b"II*\x00"),
    ("TIFF image (BE)", "image/tiff", "tiff", 0, b"MM\x00*"),
    ("ICO icon", "image/x-icon", "ico", 0, b"\x00\x00\x01\x00"),
    ("PDF document", "application/pdf", "pdf", 0, b"%PDF-"),
    ("ZIP archive", "application/zip", "zip", 0, b"PK\x03\x04"),
    ("ZIP archive (empty)", "application/zip", "zip", 0, b"PK\x05\x06"),
    ("ZIP archive (spanned)", "application/zip", "zip", 0, b"PK\x07\x08"),
    ("gzip stream", "application/gzip", "gz", 0, b"\x1f\x8b"),
    ("bzip2 stream", "application/x-bzip2", "bz2", 0, b"BZh"),
    ("xz stream", "application/x-xz", "xz", 0, b"\xfd7zXZ\x00"),
    ("7-Zip archive", "application/x-7z-compressed", "7z", 0, b"7z\xbc\xaf\x27\x1c"),
    ("RAR archive v4", "application/vnd.rar", "rar", 0, b"Rar!\x1a\x07\x00"),
    ("RAR archive v5", "application/vnd.rar", "rar", 0, b"Rar!\x1a\x07\x01\x00"),
    ("Zstandard stream", "application/zstd", "zst", 0, b"\x28\xb5\x2f\xfd"),
    ("ELF binary", "application/x-elf", "elf", 0, b"\x7fELF"),
    ("PE/COFF executable", "application/vnd.microsoft.portable-executable", "exe", 0, b"MZ"),
    ("WASM module", "application/wasm", "wasm", 0, b"\x00asm"),
    ("SQLite database", "application/vnd.sqlite3", "sqlite", 0, b"SQLite format 3\x00"),
    ("OLE/CFB document", "application/x-ole-storage", "ole", 0, b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"),
    ("PCAP capture (LE)", "application/vnd.tcpdump.pcap", "pcap", 0, b"\xd4\xc3\xb2\xa1"),
    ("PCAP capture (BE)", "application/vnd.tcpdump.pcap", "pcap", 0, b"\xa1\xb2\xc3\xd4"),
    ("PCAPNG capture", "application/x-pcapng", "pcapng", 0, b"\x0a\x0d\x0d\x0a"),
    ("MP3 audio", "audio/mpeg", "mp3", 0, b"ID3"),
    ("Ogg stream", "application/ogg", "ogg", 0, b"OggS"),
    ("FLAC audio", "audio/flac", "flac", 0, b"fLaC"),
    ("RIFF/WAV", "audio/wav", "wav", 0, b"RIFF"),
    ("Matroska/WebM", "video/x-matroska", "mkv", 0, b"\x1a\x45\xdf\xa3"),
    ("PKCS#12 keystore", "application/x-pkcs12", "p12", 0, b"\x30\x82"),
    ("Java class / Mach-O FAT", "application/java-vm", "class", 0, b"\xca\xfe\xba\xbe"),
    ("Mach-O 32-bit LE", "application/x-mach-binary", "macho", 0, b"\xce\xfa\xed\xfe"),
    ("Mach-O 64-bit LE", "application/x-mach-binary", "macho", 0, b"\xcf\xfa\xed\xfe"),
    ("PostScript document", "application/postscript", "ps", 0, b"%!PS"),
    ("Rich Text Format", "application/rtf", "rtf", 0, b"{\\rtf"),
    ("Torrent metainfo", "application/x-bittorrent", "torrent", 0, b"d8:announce"),
    ("Windows registry hive", "application/x-windows-registry", "regf", 0, b"regf"),
    ("PEM certificate/key", "application/x-pem-file", "pem", 0, b"-----BEGIN "),
    ("Embedded file (ftyp)", "video/mp4", "mp4", 4, b"ftyp"),
    ("RIFF/WEBP", "image/webp", "webp", 8, b"WEBP"),
    ("tar archive", "application/x-tar", "tar", 257, b"ustar"),
)

_TRAILING_MARKERS = {
    b"\x89PNG\r\n\x1a\n": b"IEND\xaeB`\x82",
    b"\xff\xd8\xff": b"\xff\xd9",
    b"GIF87a": b"\x3b",
    b"GIF89a": b"\x3b",
}


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for byte in data:
        counts[byte] += 1
    total = len(data)
    value = 0.0
    for count in counts:
        if count:
            p = count / total
            value -= p * math.log2(p)
    return round(value, 4)


def _hashes(data: bytes) -> dict:
    return {
        "md5": hashlib.md5(data).hexdigest(),  # noqa: S324 - non-security fingerprint for identification
        "sha1": hashlib.sha1(data).hexdigest(),  # noqa: S324 - non-security fingerprint for identification
        "sha256": hashlib.sha256(data).hexdigest(),
        "sha512": hashlib.sha512(data).hexdigest(),
        "crc32": format(binascii.crc32(data) & 0xFFFFFFFF, "08x"),
    }


def identify_signatures(data: bytes) -> list[dict]:
    """Return known signatures at offset 0/4/8 (declared) plus any embedded hits."""
    hits: list[dict] = []
    for name, mime, ext, offset, magic in _SIGNATURES:
        if data[offset : offset + len(magic)] == magic:
            hits.append({"name": name, "mime": mime, "ext": ext, "offset": offset, "declared": True})
    seen = {(h["name"], h["offset"]) for h in hits}
    for name, mime, ext, _offset, magic in _SIGNATURES:
        if len(magic) < 4:
            continue
        start = 0
        while True:
            index = data.find(magic, start)
            if index < 0:
                break
            if (name, index) not in seen and index != 0:
                seen.add((name, index))
                hits.append({"name": name, "mime": mime, "ext": ext, "offset": index, "declared": False})
            start = index + 1
            if len(hits) >= MAX_CARVE_OBJECTS:
                break
        if len(hits) >= MAX_CARVE_OBJECTS:
            break
    return hits[:MAX_CARVE_OBJECTS]


def extract_strings(data: bytes, min_len: int, limit: int) -> list[dict]:
    if limit <= 0:
        return []
    floor = max(1, min_len)
    ascii_re = re.compile(rb"[\x20-\x7e]{%d,}" % floor)
    utf16_re = re.compile(rb"(?:[\x20-\x7e]\x00){%d,}" % floor)
    out: list[dict] = []
    for match in ascii_re.finditer(data):
        value = match.group(0)
        out.append({"offset": match.start(), "encoding": "ascii", "value": value.decode("latin-1")})
        if len(out) >= limit:
            return out
    for match in utf16_re.finditer(data):
        value = match.group(0).decode("utf-16-le", errors="replace")
        out.append({"offset": match.start(), "encoding": "utf-16le", "value": value})
        if len(out) >= limit:
            return out
    return out[:limit]


def _external_file_types(path: Path) -> list[str]:
    from .deps import optional_binary

    binary = optional_binary("file")
    if not binary:
        return []
    import subprocess

    try:
        completed = subprocess.run(
            [binary, "-b", "--", str(path)], capture_output=True, text=True, timeout=10, check=False
        )
    except (OSError, subprocess.SubprocessError):
        return []
    return [line.strip() for line in (completed.stdout or "").splitlines() if line.strip()]


def identify_file(
    root: Path,
    path: str,
    max_strings: int = 50,
    min_string_len: int = 4,
    scan_embedded: bool = True,
    max_scan_bytes: int = 1_000_000,
    fmt=None,
) -> ToolResult:
    started = datetime.now(UTC)
    target = resolve_inside(root, path)
    if target.is_dir():
        from .sandbox import ToolError

        raise ToolError("file_identify expects a file, not a directory.")
    scan_cap = max(1024, min(int(max_scan_bytes), MAX_SCAN_BYTES))
    data, size = read_bounded(target, scan_cap)
    signatures = identify_signatures(data)
    declared = signatures[0] if signatures else None
    strings = extract_strings(data, max(3, min(int(min_string_len), 32)), max(0, min(int(max_strings), 500)))
    embedded = [h for h in signatures if not h["declared"]] if scan_embedded else []
    tail = _appended_tail(data, declared)
    external = _external_file_types(target)

    data_out = {
        "path": relative_label(root, target),
        "size": size,
        "scanned_bytes": len(data),
        "truncated": size > len(data),
        "hashes": _hashes(data),
        "entropy": _entropy(data),
        "signatures": signatures,
        "embedded_signatures": embedded,
        "strings_count": len(strings),
        "strings_sample": strings[:100],
    }
    if declared:
        data_out["type"] = declared["name"]
        data_out["mime"] = declared["mime"]
    if external:
        data_out["file_command"] = external
    if tail is not None:
        data_out["appended_bytes_after_end"] = tail

    lines = [
        f"File: {data_out['path']} ({size} bytes, scanned {len(data)})",
        f"Type: {declared['name'] if declared else 'unknown'} ({declared['mime'] if declared else 'n/a'})",
        f"Entropy: {data_out['entropy']} bits/byte",
        "Hashes: " + ", ".join(f"{k}={v}" for k, v in data_out["hashes"].items()),
    ]
    if external:
        lines.append("file(1): " + "; ".join(external))
    if embedded:
        lines.append(
            "Embedded signatures: "
            + ", ".join(f"{h['name']}@{h['offset']}" for h in embedded[:20])
        )
    if tail is not None:
        lines.append(f"Appended data after format end: {tail} byte(s) (possible stego/extra payload)")
    lines.append(f"Strings ({len(strings)}):")
    lines.extend(f"  @{s['offset']} [{s['encoding']}] {s['value']}" for s in strings[:100])
    return attach_flags(
        ToolResult(
            tool="file_identify",
            target=relative_label(root, target),
            display=f"file_identify(path={path!r})",
            returncode=0,
            output="\n".join(lines)[:20000],
            network_active=False,
            activity="passive",
            started_at=started.isoformat(),
            duration_seconds=duration_since(started),
            data=data_out,
        ),
        fmt,
    )


def _appended_tail(data: bytes, declared: dict | None) -> int | None:
    if not declared:
        return None
    magic = None
    for _name, _mime, _ext, offset, sig in _SIGNATURES:
        if declared["offset"] == offset and data[offset : offset + len(sig)] == sig:
            magic = sig
            break
    marker = _TRAILING_MARKERS.get(magic) if magic else None
    if not marker:
        return None
    index = data.rfind(marker)
    if index < 0:
        return None
    tail = len(data) - (index + len(marker))
    return tail if tail > 0 else 0


def carve_artifact(
    root: Path,
    path: str,
    offset: int | None = None,
    length: int | None = None,
    fmt=None,
) -> ToolResult:
    started = datetime.now(UTC)
    target = resolve_inside(root, path)
    data, size = read_bounded(target, MAX_SCAN_BYTES)
    label = relative_label(root, target)
    if offset is None:
        objects = identify_signatures(data)
        embedded = [h for h in objects if not h["declared"]]
        lines = [f"Carve scan of {label} ({size} bytes): {len(embedded)} embedded object(s)"]
        lines.extend(f"  {h['name']} ({h['mime']}) at offset {h['offset']}" for h in embedded[:MAX_CARVE_OBJECTS])
        if not embedded:
            lines.append("  (none found among known signatures)")
        return attach_flags(
            ToolResult(
                tool="artifact_extract", target=label, display=f"artifact_extract(path={path!r})",
                returncode=0, output="\n".join(lines), network_active=False, activity="passive",
                started_at=started.isoformat(), duration_seconds=duration_since(started),
                data={"path": label, "objects": embedded, "size": size},
            ),
            fmt,
        )
    start = max(0, int(offset))
    if start >= len(data):
        from .sandbox import ToolError

        raise ToolError(f"Offset {start} is beyond the scanned {len(data)} bytes.")
    cap = MAX_ARCHIVE_ENTRY_BYTES
    end = len(data) if length is None else start + max(1, min(int(length), cap))
    chunk = data[start:end]
    sigs = identify_signatures(chunk)
    declared = sigs[0] if sigs and sigs[0]["offset"] == 0 else None
    hashes = _hashes(chunk)
    with safe_tempdir() as _tmp:
        # Bytes are isolated (for hashing/preview) but never executed and the
        # temp directory is discarded on exit; nothing is written to the challenge.
        preview = chunk[:256].decode("utf-8", errors="replace")
        lines = [
            f"Carved {len(chunk)} byte(s) from {label} at offset {start}",
            f"Type: {declared['name'] if declared else 'unknown'}",
            "Hashes: " + ", ".join(f"{k}={v}" for k, v in hashes.items()),
            "Preview (first 256 bytes):",
            preview,
        ]
        return attach_flags(
            ToolResult(
                tool="artifact_extract", target=label,
                display=f"artifact_extract(path={path!r}, offset={start})",
                returncode=0, output="\n".join(lines), network_active=False, activity="passive",
                started_at=started.isoformat(), duration_seconds=duration_since(started),
                data={"path": label, "offset": start, "length": len(chunk), "hashes": hashes,
                      "type": declared["name"] if declared else None},
            ),
            fmt,
        )


def file_identify_spec(root: Path, timeout: int, out_limit: int, fmt=None) -> ToolSpec:
    return ToolSpec(
        name="file_identify",
        description=(
            "Identify a challenge file: magic-byte type, size, md5/sha1/sha256/sha512/crc32, "
            "Shannon entropy, printable strings, and any embedded file signatures (offsets). "
            "Read-only; no execution, no network."
        ),
        purpose="Low-cost first triage of an unknown artifact before deeper analysis.",
        input_schema={
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Path relative to the challenge directory."},
                "max_strings": {"type": "integer", "minimum": 0, "maximum": 500},
                "min_string_len": {"type": "integer", "minimum": 3, "maximum": 32},
                "scan_embedded": {"type": "boolean"},
                "max_scan_bytes": {"type": "integer", "minimum": 1024, "maximum": MAX_SCAN_BYTES},
            },
            "required": ["path"],
            "additionalProperties": False,
        },
        risk="informational",
        side_effects="None: reads a file inside the challenge directory, bounded.",
        network_active=False,
        approval_policy="none",
        timeout=min(timeout, 30),
        max_output_chars=out_limit,
        activity="passive",
        approval_level=1,
        scope_requirements="Confined to the challenge directory; no network access.",
        result_schema={"type": "object", "properties": {
            "type": {"type": "string"}, "hashes": {"type": "object"}, "entropy": {"type": "number"},
            "signatures": {"type": "array"}, "strings_sample": {"type": "array"},
        }},
        show=lambda args: f"file_identify(path={args.get('path')!r})",
        execute=lambda args, scope_items, evidence=None: identify_file(
            root,
            str(args.get("path", "")),
            int(args.get("max_strings", 50)),
            int(args.get("min_string_len", 4)),
            bool(args.get("scan_embedded", True)),
            int(args.get("max_scan_bytes", 1_000_000)),
            fmt,
        ),
    )


def artifact_extract_spec(root: Path, timeout: int, out_limit: int, fmt=None) -> ToolSpec:
    return ToolSpec(
        name="artifact_extract",
        description=(
            "Carve embedded objects (by known signatures) from a file, or carve a byte range "
            "at a given offset. Reports type, size, hashes, and a bounded preview. Extraction "
            "targets a temporary directory that is discarded; nothing is executed or written "
            "into the challenge."
        ),
        purpose="Bound the extraction and identification of embedded/appended artifacts.",
        input_schema={
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Path relative to the challenge directory."},
                "offset": {"type": "integer", "minimum": 0},
                "length": {"type": "integer", "minimum": 1, "maximum": MAX_ARCHIVE_ENTRY_BYTES},
            },
            "required": ["path"],
            "additionalProperties": False,
        },
        risk="informational",
        side_effects="None: read-only; bounded in-memory carving to a discarded temp directory.",
        network_active=False,
        approval_policy="none",
        timeout=min(timeout, 30),
        max_output_chars=out_limit,
        activity="passive",
        approval_level=1,
        scope_requirements="Confined to the challenge directory; no network access.",
        result_schema={"type": "object", "properties": {
            "objects": {"type": "array"}, "hashes": {"type": "object"},
        }},
        show=lambda args: (
            f"artifact_extract(path={args.get('path')!r}, offset={args.get('offset')})"
        ),
        execute=lambda args, scope_items, evidence=None: carve_artifact(
            root,
            str(args.get("path", "")),
            args.get("offset"),
            args.get("length"),
            fmt,
        ),
    )
