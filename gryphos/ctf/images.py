"""Image metadata and steganography triage (stdlib only).

Parses PNG/JPEG/GIF/BMP headers without decoding pixels, lists metadata chunks
or segments (PNG tEXt/zTXt/iTXt, JPEG EXIF/COM, GIF comments), and performs
*non-destructive* stego triage: bytes appended after the format terminator,
their size/entropy/printability, embedded signatures in the tail, and a rough
LSB-bit-set ratio. `exiftool` is used only when present. Nothing is executed and
no pixels are rewritten.
"""

from __future__ import annotations

import math
import struct
from datetime import UTC, datetime
from pathlib import Path

from ..tools.base import ToolResult, ToolSpec, duration_since
from .deps import optional_binary
from .filetools import identify_signatures
from .sandbox import MAX_SCAN_BYTES, attach_flags, read_bounded, relative_label, resolve_inside

_PNG_END = b"IEND\xaeB`\x82"
_JPEG_END = b"\xff\xd9"


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


def _printable_ratio(data: bytes) -> float:
    if not data:
        return 0.0
    good = sum(1 for b in data if 9 <= b <= 13 or 32 <= b <= 126)
    return round(good / len(data), 3)


def _lsb_ratio(data: bytes) -> float:
    if not data:
        return 0.0
    ones = sum(bin(byte & 1).count("1") for byte in data)
    return round(ones / len(data), 4)


def _parse_png(data: bytes) -> dict:
    info: dict = {"format": "PNG", "chunks": [], "comments": []}
    pos = 8
    while pos + 12 <= len(data):
        (length,) = struct.unpack(">I", data[pos : pos + 4])
        ctype = data[pos + 4 : pos + 8]
        name = ctype.decode("latin-1", errors="replace")
        available = len(data) - (pos + 12)
        if length > available:
            info["chunks"].append({"type": name, "declared_size": length, "truncated": True})
            pos = len(data)
            break
        content = data[pos + 8 : pos + 8 + length]
        info["chunks"].append({"type": name, "size": length, "offset": pos})
        if ctype == b"IHDR" and len(content) >= 10:
            info["width"], info["height"] = struct.unpack(">II", content[:8])
            info["bit_depth"] = content[8]
            info["color_type"] = content[9]
        elif ctype in (b"tEXt", b"iTXt", b"zTXt"):
            info["comments"].append({"type": name, "text": content[:400].decode("latin-1", errors="replace")})
        pos += 12 + length
        if ctype == b"IEND":
            break
    index = data.rfind(_PNG_END)
    info["end_offset"] = (index + len(_PNG_END)) if index >= 0 else len(data)
    return info


def _parse_jpeg(data: bytes) -> dict:
    info: dict = {"format": "JPEG", "segments": [], "comments": []}
    pos = 2
    while pos + 4 <= len(data):
        if data[pos] != 0xFF:
            pos += 1
            continue
        marker = data[pos + 1]
        if marker in (0xD8, 0xD9) or 0xD0 <= marker <= 0xD7:
            pos += 2
            if marker == 0xD9:
                break
            continue
        if pos + 4 > len(data):
            break
        (length,) = struct.unpack(">H", data[pos + 2 : pos + 4])
        payload = data[pos + 4 : pos + 2 + length]
        name = f"0xFF{marker:02X}"
        info["segments"].append({"marker": name, "size": length})
        if marker in (0xC0, 0xC1, 0xC2, 0xC3) and len(payload) >= 5:
            info["height"], info["width"] = struct.unpack(">HH", payload[1:5])
            info["precision"] = payload[0]
        if marker == 0xE1 and payload[:6] == b"Exif\x00\x00":
            info["has_exif"] = True
        if marker == 0xFE:
            info["comments"].append({"type": "COM", "text": payload[:400].decode("latin-1", errors="replace")})
        pos += 2 + length
    index = data.rfind(_JPEG_END)
    info["end_offset"] = (index + 2) if index >= 0 else len(data)
    return info


def _parse_gif(data: bytes) -> dict:
    info: dict = {"format": "GIF", "comments": [], "frames": 0, "extensions": []}
    if len(data) >= 10:
        info["version"] = data[:6].decode("latin-1", errors="replace")
        info["width"], info["height"] = struct.unpack("<HH", data[6:10])
    pos = 13
    if pos <= len(data) and len(data) > 10 and data[10] & 0x80:
        pos += 3 * (2 ** ((data[10] & 0x07) + 1))
    while pos < len(data):
        block = data[pos]
        if block == 0x3B:
            info["end_offset"] = pos + 1
            break
        if block == 0x2C:
            info["frames"] += 1
            if pos + 10 > len(data):
                break
            local_flags = data[pos + 9]
            pos += 10
            if local_flags & 0x80:
                pos += 3 * (2 ** ((local_flags & 0x07) + 1))
            pos = _skip_subblocks(data, pos + 1)
        elif block == 0x21:
            if pos + 2 > len(data):
                break
            label = data[pos + 1]
            if label == 0xFE:
                text, pos = _read_subblocks(data, pos + 2)
                info["comments"].append({"type": "comment", "text": text[:400].decode("latin-1", errors="replace")})
            else:
                info["extensions"].append(f"0x{label:02X}")
                pos = _skip_subblocks(data, pos + 2)
        else:
            pos += 1
    info.setdefault("end_offset", len(data))
    return info


def _skip_subblocks(data: bytes, pos: int) -> int:
    while pos < len(data):
        size = data[pos]
        pos += 1
        if size == 0:
            break
        pos += size
    return pos


def _read_subblocks(data: bytes, pos: int) -> tuple[bytes, int]:
    parts: list[bytes] = []
    while pos < len(data):
        size = data[pos]
        pos += 1
        if size == 0:
            break
        parts.append(data[pos : pos + size])
        pos += size
    return b"".join(parts), pos


def _parse_bmp(data: bytes) -> dict:
    info: dict = {"format": "BMP"}
    if len(data) >= 26:
        info["width"], info["height"] = struct.unpack("<ii", data[18:26])
        info["bit_depth"] = struct.unpack("<H", data[28:30])[0] if len(data) >= 30 else None
    info["end_offset"] = len(data)
    return info


def _tail_summary(data: bytes, info: dict) -> dict | None:
    end = info.get("end_offset")
    if end is None or end >= len(data):
        return None
    tail = data[end:]
    sigs = identify_signatures(tail)
    return {
        "size": len(tail),
        "entropy": _entropy(tail[:4096]),
        "printable_ratio": _printable_ratio(tail[:4096]),
        "lsb_ratio": _lsb_ratio(tail[:65536]),
        "printing_preview": tail[:200].decode("latin-1", errors="replace"),
        "signatures": [{"name": s["name"], "offset": s["offset"]} for s in sigs],
    }


def _exiftool(path: Path) -> list[str]:
    binary = optional_binary("exiftool")
    if not binary:
        return []
    import subprocess

    try:
        completed = subprocess.run(
            [binary, "-s", "--", str(path)], capture_output=True, text=True, timeout=15, check=False
        )
    except (OSError, subprocess.SubprocessError):
        return []
    return [line for line in (completed.stdout or "").splitlines() if line.strip()][:40]


def triage_image(root: Path, path: str, fmt=None) -> ToolResult:
    started = datetime.now(UTC)
    target = resolve_inside(root, path)
    data, size = read_bounded(target, MAX_SCAN_BYTES)
    label = relative_label(root, target)
    head = data[:16]

    if head[:8] == b"\x89PNG\r\n\x1a\n":
        info = _parse_png(data)
    elif head[:3] == b"\xff\xd8\xff":
        info = _parse_jpeg(data)
    elif head[:6] in (b"GIF87a", b"GIF89a"):
        info = _parse_gif(data)
    elif head[:2] == b"BM":
        info = _parse_bmp(data)
    else:
        info = {"format": "unknown", "note": "not a PNG/JPEG/GIF/BMP image"}

    info["path"] = label
    info["size"] = size
    info["scanned_bytes"] = len(data)
    info["entropy"] = _entropy(data[:65536])
    tail = _tail_summary(data, info) if info.get("format") != "unknown" else None
    external = _exiftool(target)

    lines = [f"Image: {label} ({size} bytes)", f"Format: {info.get('format')}"]
    if info.get("note"):
        lines.append(info["note"])
    if "width" in info:
        lines.append(
            f"Dimensions: {info.get('width')}x{info.get('height')} "
            f"(bit_depth={info.get('bit_depth')}, color_type={info.get('color_type')})"
        )
    if info.get("frames"):
        lines.append(f"GIF frames: {info['frames']}")
    if info.get("chunks"):
        summary = ", ".join(f"{c['type']}:{c.get('size', '?')}" for c in info["chunks"][:30])
        lines.append(f"PNG chunks: {summary}")
    if info.get("segments"):
        summary = ", ".join(f"{s['marker']}:{s['size']}" for s in info["segments"][:30])
        lines.append(f"JPEG segments: {summary}")
    for comment in info.get("comments", []):
        lines.append(f"Comment [{comment['type']}]: {comment['text']!r}")
    if external:
        lines.append("exiftool:")
        lines.extend(f"  {line}" for line in external)
    if tail:
        lines.append(
            f"Appended after image end: {tail['size']} byte(s) "
            f"(entropy={tail['entropy']}, printable={tail['printable_ratio']}, lsb_ratio={tail['lsb_ratio']})"
        )
        if tail["signatures"]:
            lines.append(
                "Embedded in tail: " + ", ".join(f"{s['name']}@{s['offset']}" for s in tail["signatures"])
            )
        if tail["printing_preview"].strip():
            lines.append("Tail preview: " + tail["printing_preview"][:200])

    return attach_flags(
        ToolResult(
            tool="image_triage",
            target=label,
            display=f"image_triage(path={path!r})",
            returncode=0,
            output="\n".join(lines)[:20000],
            network_active=False,
            activity="passive",
            started_at=started.isoformat(),
            duration_seconds=duration_since(started),
            data={**info, "tail": tail, "exiftool": external},
        ),
        fmt,
    )


def image_triage_spec(root: Path, timeout: int, out_limit: int, fmt=None) -> ToolSpec:
    return ToolSpec(
        name="image_triage",
        description=(
            "Parse PNG/JPEG/GIF/BMP metadata (dimensions, chunks/segments, text comments, "
            "EXIF) and triage for steganography: bytes appended after the end marker, their "
            "entropy/printability, embedded signatures in the tail, and a rough LSB-bit ratio. "
            "Non-destructive; no pixels are modified and nothing is executed."
        ),
        purpose="Cheap first pass over an image challenge before any pixel-level stego work.",
        input_schema={
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Path relative to the challenge directory."},
            },
            "required": ["path"],
            "additionalProperties": False,
        },
        risk="informational",
        side_effects="None: read-only header/tail parsing.",
        network_active=False,
        approval_policy="none",
        timeout=min(timeout, 30),
        max_output_chars=out_limit,
        activity="passive",
        approval_level=1,
        scope_requirements="Confined to the challenge directory; no network access.",
        result_schema={"type": "object", "properties": {
            "format": {"type": "string"}, "tail": {"type": "object"}, "comments": {"type": "array"},
        }},
        show=lambda args: f"image_triage(path={args.get('path')!r})",
        execute=lambda args, scope_items, evidence=None: triage_image(root, str(args.get("path", "")), fmt),
    )
