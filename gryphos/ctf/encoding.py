"""Encoding detection and decoding (bounded, offline).

Peels common text/byte encodings -- Base64 (standard and URL-safe), Base32,
Base16/hex, URL percent-encoding, quoted-printable, binary/bit strings, decimal
and octal char codes, ASCII85/Base85, ROT13, reversal, Morse, and bounded
gzip/zlib -- and reports ranked candidates with a printable-ratio/entropy score.
Recursion is depth-bounded and every decoded blob is size-bounded.
"""

from __future__ import annotations

import base64
import binascii
import gzip
import math
import quopri
import re
import zlib
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import unquote

from ..tools.base import ToolError, ToolResult, ToolSpec, duration_since
from .sandbox import MAX_DECODE_ROUNDS, attach_flags, read_bounded, relative_label, resolve_inside

MAX_INPUT_CHARS = 200_000
MAX_DECODED_BYTES = 262_144
_MAX_CANDIDATES = 60

_B64_RE = re.compile(r"^[A-Za-z0-9+/\-_]+={0,2}$")
_HEX_RE = re.compile(r"^[0-9A-Fa-f]+$")
_BIN_RE = re.compile(r"^[01\s]+$")
_MORSE_RE = re.compile(r"^[.\-/\s]+$")

_MORSE = {
    ".-": "A", "-...": "B", "-.-.": "C", "-..": "D", ".": "E", "..-.": "F",
    "--.": "G", "....": "H", "..": "I", ".---": "J", "-.-": "K", ".-..": "L",
    "--": "M", "-.": "N", "---": "O", ".--.": "P", "--.-": "Q", ".-.": "R",
    "...": "S", "-": "T", "..-": "U", "...-": "V", ".--": "W", "-..-": "X",
    "-.--": "Y", "--..": "Z", "-----": "0", ".----": "1", "..---": "2",
    "...--": "3", "....-": "4", ".....": "5", "-....": "6", "--...": "7",
    "---..": "8", "----.": "9",
}


def _printable_ratio(data: bytes) -> float:
    if not data:
        return 0.0
    good = sum(1 for b in data if 9 <= b <= 13 or 32 <= b <= 126)
    return round(good / len(data), 3)


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


def _to_text(data: bytes) -> str:
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return data.decode("latin-1")


def _tight(text: str) -> str:
    return re.sub(r"\s+", "", text or "")


def _try_base64(s: str) -> bytes | None:
    core = _tight(s)
    urlsafe = "-" in core or "_" in core
    if not _B64_RE.match(core) or len(core) < 4:
        return None
    padded = core + "=" * (-len(core) % 4)
    decoder = base64.urlsafe_b64decode if urlsafe else base64.b64decode
    try:
        return decoder(padded)
    except (binascii.Error, ValueError):
        return None


def _try_base32(s: str) -> bytes | None:
    core = _tight(s).upper()
    if not re.match(r"^[A-Z2-7]+=*$", core) or len(core) < 8:
        return None
    try:
        return base64.b32decode(core + "=" * (-len(core) % 8))
    except (binascii.Error, ValueError):
        return None


def _try_hex(s: str) -> bytes | None:
    core = _tight(s)
    if core.lower().startswith("0x"):
        core = core[2:]
    if len(core) < 2 or len(core) % 2 or not _HEX_RE.match(core):
        return None
    try:
        return bytes.fromhex(core)
    except ValueError:
        return None


def _try_url(s: str) -> bytes | None:
    if "%" not in s:
        return None
    decoded = unquote(s)
    if decoded == s:
        return None
    return decoded.encode("utf-8", errors="replace")


def _try_quopri(s: str) -> bytes | None:
    if not re.search(r"=[0-9A-Fa-f]{2}", s):
        return None
    decoded = quopri.decodestring(s.encode("latin-1"))
    if decoded == s.encode("latin-1"):
        return None
    return decoded


def _try_binary(s: str) -> bytes | None:
    if not _BIN_RE.match(s):
        return None
    bits = _tight(s)
    if not bits or len(bits) % 8:
        return None
    return bytes(int(bits[i : i + 8], 2) for i in range(0, len(bits), 8))


def _try_decimals(s: str) -> bytes | None:
    tokens = s.split()
    if len(tokens) < 2 or not all(t.isdigit() for t in tokens):
        return None
    values = [int(t) for t in tokens]
    if all(0 <= v <= 255 for v in values):
        return bytes(values)
    return None


def _try_octal(s: str) -> bytes | None:
    tokens = s.split()
    if len(tokens) < 2 or not all(re.match(r"^[0-3]?[0-7]{1,3}$", t) for t in tokens):
        return None
    values = [int(t, 8) for t in tokens]
    if all(0 <= v <= 255 for v in values):
        return bytes(values)
    return None


def _try_a85(s: str) -> bytes | None:
    core = _tight(s)
    if len(core) < 5 or not re.match(r"^[!-u]+$", core):
        return None
    try:
        return base64.a85decode(core, adobe=False)
    except (binascii.Error, ValueError):
        return None


def _try_b85(s: str) -> bytes | None:
    core = _tight(s)
    if len(core) < 5 or not re.match(r"^[0-9A-Za-z!#$%&()*+\-;<=>?@^_`{|}~]+$", core):
        return None
    try:
        return base64.b85decode(core)
    except (binascii.Error, ValueError):
        return None


def _try_gzip_zlib(s: str) -> bytes | None:
    raw = _try_base64(s) or (s.encode("latin-1") if s.isprintable() else None)
    if not raw or len(raw) < 2:
        return None
    for magic, decompress in ((b"\x1f\x8b", gzip.decompress), (b"\x78", zlib.decompress)):
        if raw[: len(magic)] == magic:
            try:
                out = decompress(raw)
            except (OSError, zlib.error, EOFError):
                continue
            if len(out) <= MAX_DECODED_BYTES:
                return out
    return None


def _try_morse(s: str) -> bytes | None:
    if not _MORSE_RE.match(s) or ("." not in s and "-" not in s):
        return None
    words = re.split(r"\s{2,}|/", s.strip())
    out: list[str] = []
    for word in words:
        letters = [_MORSE.get(code, "?") for code in word.split() if code]
        out.append("".join(letters))
    decoded = " ".join(part for part in out if part)
    return decoded.encode("latin-1") if decoded else None


def _single_pass(text: str) -> list[tuple[str, bytes]]:
    candidates: list[tuple[str, bytes]] = []
    for method, fn in (
        ("base64", _try_base64),
        ("base32", _try_base32),
        ("base16/hex", _try_hex),
        ("url-decode", _try_url),
        ("quoted-printable", _try_quopri),
        ("binary-bits", _try_binary),
        ("decimal-codes", _try_decimals),
        ("octal-codes", _try_octal),
        ("ascii85", _try_a85),
        ("base85", _try_b85),
        ("gzip/zlib", _try_gzip_zlib),
        ("morse", _try_morse),
    ):
        try:
            result = fn(text)
        except Exception:  # noqa: BLE001 - a failed heuristic simply yields no candidate
            result = None
        if result is not None and 0 < len(result) <= MAX_DECODED_BYTES:
            candidates.append((method, result))
    lowered = text.swapcase()
    if lowered != text:
        candidates.append(("reverse-case (ROT13-style)", lowered.encode("utf-8", errors="replace")))
    if text[::-1] != text:
        candidates.append(("reverse", text[::-1].encode("utf-8", errors="replace")))
    return candidates


_WEAK_METHODS = frozenset({"reverse", "reverse-case (ROT13-style)", "morse"})


def _extract_tokens(text: str) -> list[str]:
    """Pull base64/hex/binary-looking substrings out of surrounding prose.

    A challenge often hides an encoded blob inside a larger text file; trying the
    whole file as one blob would miss it, so each token is also peeled on its own.
    """
    tokens: list[str] = []
    for pattern in (
        r"[A-Za-z0-9+/\-_]{16,}={0,2}",
        r"\b[0-9A-Fa-f]{16,}\b",
        r"(?:[01]{8}\s+){3,}[01]{8}",
    ):
        tokens.extend(match.group(0) for match in re.finditer(pattern, text))
    seen: set[str] = set()
    out: list[str] = []
    for token in tokens:
        if token not in seen:
            seen.add(token)
            out.append(token)
    return out[:40]


def decode_input(text: str, max_rounds: int, fmt=None) -> list[dict]:
    """Breadth-first bounded peel; returns ranked candidate records."""
    rounds = max(1, min(int(max_rounds), MAX_DECODE_ROUNDS))
    results: list[dict] = []
    seen: set[bytes] = set()
    frontier = [(text, [])]
    for token in _extract_tokens(text):
        if token != text:
            frontier.append((token, []))
    for _ in range(rounds):
        next_frontier: list[tuple[str, list[str]]] = []
        for current, chain in frontier:
            if len(chain) >= rounds:
                continue
            for method, data in _single_pass(current):
                if data in seen:
                    continue
                seen.add(data)
                chain_now = [*chain, method]
                text_now = _to_text(data)
                ratio = _printable_ratio(data)
                flags = fmt.find(text_now) if fmt else []
                results.append({
                    "chain": chain_now,
                    "method": method,
                    "length": len(data),
                    "printable_ratio": ratio,
                    "entropy": _entropy(data),
                    "text": text_now[:4000],
                    "flags": flags,
                })
                if ratio >= 0.85 and len(next_frontier) < _MAX_CANDIDATES:
                    next_frontier.append((text_now, chain_now))
                if len(results) >= _MAX_CANDIDATES:
                    break
            if len(results) >= _MAX_CANDIDATES:
                break
        frontier = next_frontier
        if not frontier:
            break
    results.sort(
        key=lambda item: (
            bool(item["flags"]),
            item["method"] not in _WEAK_METHODS,
            item["printable_ratio"],
            -len(item["chain"]),
        ),
        reverse=True,
    )
    return results[:40]


def decode_encoded(
    root: Path,
    path: str | None,
    input_text: str | None,
    max_rounds: int,
    fmt=None,
) -> ToolResult:
    started = datetime.now(UTC)
    if path and input_text:
        raise ToolError("Provide either 'path' or 'input', not both.")
    if not path and not input_text:
        raise ToolError("Provide 'path' (a challenge file) or 'input' (a string).")
    if path:
        target = resolve_inside(root, path)
        data, size = read_bounded(target, MAX_INPUT_CHARS)
        text = data.decode("utf-8", errors="replace")
        label = relative_label(root, target)
    else:
        text = input_text or ""
        size = len(text)
        label = "(inline input)"
    text = text[:MAX_INPUT_CHARS]

    candidates = decode_input(text, max_rounds, fmt)
    lines = [f"Encoding analysis of {label} ({size} bytes, {len(candidates)} candidate(s)):"]
    for index, cand in enumerate(candidates[:20], start=1):
        chain = " -> ".join(cand["chain"])
        marker = " [FLAG]" if cand["flags"] else ""
        lines.append(
            f"\n[{index}] {chain}{marker}  (len={cand['length']}, "
            f"printable={cand['printable_ratio']}, entropy={cand['entropy']})"
        )
        preview = cand["text"].strip().replace("\r", "")
        lines.append("    " + preview[:400].replace("\n", "\n    "))
    if not candidates:
        lines.append("  No known encoding produced a plausible decoding.")
    return attach_flags(
        ToolResult(
            tool="encoding_decode",
            target=label,
            display=f"encoding_decode(path={path!r})" if path else "encoding_decode(input=...)",
            returncode=0,
            output="\n".join(lines)[:20000],
            network_active=False,
            activity="passive",
            started_at=started.isoformat(),
            duration_seconds=duration_since(started),
            data={"path": label, "candidates": candidates},
        ),
        fmt,
    )


def encoding_decode_spec(root: Path, timeout: int, out_limit: int, fmt=None) -> ToolSpec:
    return ToolSpec(
        name="encoding_decode",
        description=(
            "Detect and decode common encodings (base64/url-safe, base32, hex, URL, "
            "quoted-printable, binary bits, decimal/octal codes, ascii85/base85, ROT13, "
            "reverse, Morse, bounded gzip/zlib) with depth-bounded recursion. Ranks "
            "candidates by printability and flag match. Read-only."
        ),
        purpose="Reverse encoding layers on challenge text or a supplied file.",
        input_schema={
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Path relative to the challenge directory."},
                "input": {"type": "string", "description": "Inline string to decode."},
                "max_rounds": {"type": "integer", "minimum": 1, "maximum": MAX_DECODE_ROUNDS},
            },
            "additionalProperties": False,
        },
        risk="informational",
        side_effects="None: pure in-memory transformation of provided data.",
        network_active=False,
        approval_policy="none",
        timeout=min(timeout, 20),
        max_output_chars=out_limit,
        activity="passive",
        approval_level=1,
        scope_requirements="Confined to the challenge directory; no network access.",
        result_schema={"type": "object", "properties": {"candidates": {"type": "array"}}},
        show=lambda args: (
            f"encoding_decode(path={args.get('path')!r})"
            if args.get("path") else "encoding_decode(input=...)"
        ),
        execute=lambda args, scope_items, evidence=None: decode_encoded(
            root,
            args.get("path"),
            args.get("input"),
            int(args.get("max_rounds", 3)),
            fmt,
        ),
    )
