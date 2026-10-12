"""Classical-crypto, XOR, frequency, and weak-parameter analysis (stdlib only).

Offline helpers for CTF crypto challenges: English frequency/chi-square scoring,
Caesar/ROT/Atbash, single-byte and repeating-key XOR, Vigenere (keyed and
auto-cracked), Rail-fence transposition, JWT decoding, hash-type identification
(with weak-algorithm flags), and a bounded RSA attack for smallprimeable
moduli, small `e`, or `e=1`. Every candidate is scored and flag matches are
promoted. `mode="auto"` runs the applicable analyses and ranks results.
"""

from __future__ import annotations

import base64
import binascii
import json
import math
import re
import string
from datetime import UTC, datetime
from pathlib import Path

from ..tools.base import ToolResult, ToolSpec, duration_since
from .sandbox import MAX_SCAN_BYTES, attach_flags, read_bounded, relative_label, resolve_inside

MODES = ("auto", "frequency", "caesar", "xor", "vigenere", "railfence", "atbash", "hash", "jwt", "rsa")

_ENGLISH_FREQ = {
    "a": 8.167, "b": 1.492, "c": 2.782, "d": 4.253, "e": 12.702, "f": 2.228,
    "g": 2.015, "h": 6.094, "i": 6.966, "j": 0.153, "k": 0.772, "l": 4.025,
    "m": 2.406, "n": 6.749, "o": 7.507, "p": 1.929, "q": 0.095, "r": 5.987,
    "s": 6.327, "t": 9.056, "u": 2.758, "v": 0.978, "w": 2.360, "x": 0.150,
    "y": 1.974, "z": 0.074,
}
_COMMON_WORDS = (" the ", " and ", "ing ", "ion", "flag", "ctf", "http", "secret", "password", "key{")
_HASH_PATTERNS = (
    (r"^[a-f0-9]{32}$", "MD5 (weak)"), (r"^[a-f0-9]{40}$", "SHA-1 (weak)"),
    (r"^[a-f0-9]{64}$", "SHA-256"), (r"^[a-f0-9]{128}$", "SHA-512"),
    (r"^\$2[aby]\$\d{2}\$.{53}$", "bcrypt"), (r"^\$1\$.{0,8}\$.{22}$", "MD5-crypt (weak)"),
    (r"^\$5\$.{0,16}\$.{43}$", "SHA-256-crypt"), (r"^\$6\$.{0,16}\$.{86}$", "SHA-512-crypt"),
    (r"^[a-f0-9]{8}$", "CRC-32 / 32-bit hash"), (r"^[a-f0-9]{16}$", "half-MD5 / 64-bit hash"),
)


def _chi_square(text: str) -> float:
    letters = [c for c in text.lower() if c in string.ascii_lowercase]
    if len(letters) < 4:
        return 1e9
    counts = {c: 0 for c in string.ascii_lowercase}
    for c in letters:
        counts[c] += 1
    total = len(letters)
    score = 0.0
    for letter, expected_pct in _ENGLISH_FREQ.items():
        expected = expected_pct / 100 * total
        observed = counts[letter]
        if expected > 0:
            score += (observed - expected) ** 2 / expected
    return score


def _printable_ratio(data: bytes) -> float:
    if not data:
        return 0.0
    good = sum(1 for b in data if 9 <= b <= 13 or 32 <= b <= 126)
    return good / len(data)


def _score(text: str) -> float:
    if not text:
        return 1e9
    ratio = _printable_ratio(text.encode("latin-1", errors="replace"))
    if ratio < 0.8:
        return 1e9 * (1.2 - ratio)
    letters = sum(1 for c in text if c in string.ascii_letters)
    letter_ratio = letters / len(text)
    score = _chi_square(text) + (1 - letter_ratio) * 300
    lowered = text.lower()
    for word in _COMMON_WORDS:
        if word in lowered:
            score -= 40
    return score


def _decode_bytes(text: str) -> bytes:
    raw = text.strip()
    if re.fullmatch(r"[0-9a-fA-F\s]+", raw) and len(re.sub(r"\s", "", raw)) % 2 == 0:
        try:
            return bytes.fromhex(re.sub(r"\s", "", raw))
        except ValueError:
            pass
    return raw.encode("latin-1", errors="replace")


def _caesar(text: str) -> list[tuple[int, str]]:
    out: list[tuple[int, str]] = []
    for shift in range(26):
        out.append((shift, _rotate(text, shift)))
    out.append((47, _rot47(text)))
    return out


def _rotate(text: str, shift: int) -> str:
    result = []
    for ch in text:
        if ch.islower():
            result.append(chr((ord(ch) - 97 - shift) % 26 + 97))
        elif ch.isupper():
            result.append(chr((ord(ch) - 65 - shift) % 26 + 65))
        else:
            result.append(ch)
    return "".join(result)


def _rot47(text: str) -> str:
    return "".join(chr(33 + (ord(ch) - 33 + 47) % 94) if 33 <= ord(ch) <= 126 else ch for ch in text)


def _atbash(text: str) -> str:
    result = []
    for ch in text:
        if ch.islower():
            result.append(chr(122 - (ord(ch) - 97)))
        elif ch.isupper():
            result.append(chr(90 - (ord(ch) - 65)))
        else:
            result.append(ch)
    return "".join(result)


def _xor_single(data: bytes) -> list[tuple[int, bytes]]:
    results = []
    for key in range(256):
        decoded = bytes(b ^ key for b in data)
        score = _score(decoded.decode("latin-1", errors="replace"))
        results.append((score, key, decoded))
    results.sort(key=lambda item: item[0])
    return [(key, decoded) for _score_val, key, decoded in results[:10]]


def _xor_repeating(data: bytes, max_key: int) -> list[tuple[bytes, bytes]]:
    out: list[tuple[float, bytes, bytes]] = []
    key_limit = min(max_key, max(1, len(data) // 4), 16)
    for key_len in range(2, key_limit + 1):
        key = bytearray()
        for column in range(key_len):
            chunk = data[column::key_len]
            best = min(range(256), key=lambda k: _chi_square(bytes(b ^ k for b in chunk).decode("latin-1", "replace")))
            key.append(best)
        decoded = bytes(b ^ key[i % len(key)] for i, b in enumerate(data))
        out.append((_score(decoded.decode("latin-1", errors="replace")), bytes(key), decoded))
    out.sort(key=lambda item: item[0])
    return [(key, decoded) for _score_val, key, decoded in out[:5]]


def _vigenere(text: str, key: str) -> str:
    if not key:
        return ""
    letters = [c for c in key.lower() if c.isalpha()]
    if not letters:
        return ""
    result = []
    index = 0
    for ch in text:
        if ch.isalpha():
            shift = ord(letters[index % len(letters)]) - 97
            base = 97 if ch.islower() else 65
            result.append(chr((ord(ch) - base - shift) % 26 + base))
            index += 1
        else:
            result.append(ch)
    return "".join(result)


def _vigenere_auto(text: str, max_key: int) -> list[tuple[str, str]]:
    letters = [c.lower() for c in text if c.isalpha()]
    if len(letters) < 16:
        return []
    candidates: list[tuple[float, str, str]] = []
    for key_len in range(1, min(max_key, 12) + 1):
        key = []
        for column in range(key_len):
            chunk = "".join(letters[column::key_len])
            shifts = [(idx, _chi_square(_rotate(chunk, idx))) for idx in range(26)]
            best_shift = min(shifts, key=lambda item: item[1])[0]
            key.append(chr(best_shift + 97))
        key_str = "".join(key)
        decoded = _vigenere(text, key_str)
        candidates.append((_score(decoded), key_str, decoded))
    candidates.sort(key=lambda item: item[0])
    return [(key, decoded) for _score_val, key, decoded in candidates[:5]]


def _railfence_decode(text: str, rails: int) -> str:
    if rails < 2 or rails >= len(text):
        return text
    pattern = list(range(rails)) + list(range(rails - 2, 0, -1))
    cycle = len(pattern)
    counts = [0] * rails
    for i in range(len(text)):
        counts[pattern[i % cycle]] += 1
    chunks, pos = [], 0
    for count in counts:
        chunks.append(list(text[pos : pos + count]))
        pos += count
    result = []
    for i in range(len(text)):
        rail = pattern[i % cycle]
        result.append(chunks[rail].pop(0))
    return "".join(result)


def _railfence_brute(text: str) -> list[tuple[int, str]]:
    out = []
    for rails in range(2, min(9, max(3, len(text)))):
        decoded = _railfence_decode(text, rails)
        out.append((_score(decoded), rails, decoded))
    out.sort(key=lambda item: item[0])
    return [(rails, decoded) for _score_val, rails, decoded in out]


def _frequency_report(text: str) -> dict:
    letters = [c.lower() for c in text if c.isalpha()]
    counts: dict[str, int] = {}
    for c in letters:
        counts[c] = counts.get(c, 0) + 1
    total = len(letters) or 1
    freq = {k: round(v / total * 100, 2) for k, v in sorted(counts.items(), key=lambda i: -i[1])}
    coincidence = 0.0
    if len(letters) > 1:
        coincidence = sum(v * (v - 1) for v in counts.values()) / (len(letters) * (len(letters) - 1))
    return {"counts": counts, "frequencies_pct": freq, "index_of_coincidence": round(coincidence, 4),
            "likely_monoalphabetic": coincidence > 0.06}


def _hash_id(text: str) -> list[str]:
    value = text.strip()
    return [label for pattern, label in _HASH_PATTERNS if re.match(pattern, value)]


def _modinv(a: int, m: int) -> int | None:
    try:
        return pow(a, -1, m)
    except ValueError:
        return None


def _factor(n: int) -> tuple[int, int] | None:
    if n % 2 == 0:
        return 2, n // 2
    f = 3
    while f * f <= n and f < 1_000_000:
        if n % f == 0:
            return f, n // f
        f += 2
    a = math.isqrt(n)
    for _ in range(200_000):
        a += 1
        b2 = a * a - n
        b = math.isqrt(b2)
        if b * b == b2:
            return a - b, a + b
    return None


def _rsa_attack(blob: str, overrides: dict, fmt) -> dict:
    def pick(name: str) -> int | None:
        if overrides.get(name) is not None:
            try:
                return int(str(overrides[name]), 0)
            except ValueError:
                return None
        match = re.search(rf"{name}\s*[=:]\s*(0x[0-9a-fA-F]+|\d+)", blob)
        return int(match.group(1), 0) if match else None

    n, e, c = pick("n"), pick("e"), pick("c")
    result: dict = {"n": n, "e": e, "c": c, "findings": []}
    if n is None or e is None:
        result["error"] = "RSA mode needs n and e (as n=..., e=... or explicit args)."
        return result
    if e == 1 and c is not None:
        result["findings"].append("e=1: plaintext == ciphertext (no encryption)")
        result["plaintext"] = _int_to_text(c)
        return result
    factors = _factor(n)
    if factors:
        p, q = factors
        phi = (p - 1) * (q - 1)
        d = _modinv(e, phi)
        result["findings"].append(f"factored n = {p} * {q}")
        if d and c is not None:
            m = pow(c, d, n)
            result["private_exponent"] = d
            result["plaintext"] = _int_to_text(m)
        return result
    result["findings"].append("n not factored within bounds (trial division + Fermat limited)")
    return result


def _int_to_text(value: int) -> str:
    length = max(1, (value.bit_length() + 7) // 8)
    raw = value.to_bytes(length, "big")
    return raw.decode("utf-8", errors="replace")


def _jwt_decode(text: str) -> dict | None:
    value = text.strip()
    if value.count(".") != 2:
        return None
    parts = value.split(".")
    header = _b64url_json(parts[0])
    payload = _b64url_json(parts[1])
    if header is None and payload is None:
        return None
    risks = []
    alg = str(header.get("alg", "")).lower() if header else ""
    if alg == "none":
        risks.append("alg=none (unverified JWT)")
    elif alg in ("hs256", "hs384", "hs512"):
        risks.append(f"{alg} (HMAC: brute-forceable with a weak secret)")
    return {"header": header, "payload": payload, "risks": risks}


def _b64url_json(segment: str):
    padded = segment + "=" * (-len(segment) % 4)
    try:
        return json.loads(base64.urlsafe_b64decode(padded).decode("utf-8", errors="replace"))
    except (binascii.Error, ValueError):
        return None


def analyze_crypto(
    root: Path,
    path: str | None,
    input_text: str | None,
    mode: str,
    key: str | None,
    max_key_length: int,
    fmt=None,
) -> ToolResult:
    started = datetime.now(UTC)
    if path and input_text:
        from ..tools.base import ToolError

        raise ToolError("Provide either 'path' or 'input', not both.")
    if not path and not input_text:
        from ..tools.base import ToolError

        raise ToolError("Provide 'path' (a challenge file) or 'input' (a string).")
    if path:
        target = resolve_inside(root, path)
        data, size = read_bounded(target, MAX_SCAN_BYTES)
        text = data.decode("utf-8", errors="replace")
        label = relative_label(root, target)
    else:
        text = input_text or ""
        size = len(text)
        label = "(inline input)"
        data = text.encode("latin-1", errors="replace")

    mode = (mode or "auto").lower()
    if mode not in MODES:
        from ..tools.base import ToolError

        raise ToolError(f"Unknown mode {mode!r}; choose from {', '.join(MODES)}.")
    max_key = max(1, min(int(max_key_length), 16))

    findings: dict = {"mode": mode, "path": label, "candidates": [], "notes": []}
    candidates: list[dict] = []

    def add(method: str, value: str, detail: str = "") -> None:
        if not value:
            return
        candidates.append({
            "method": method,
            "value": value[:2000],
            "detail": detail,
            "score": round(_score(value), 2),
            "flags": fmt.find(value) if fmt else [],
        })

    def run_all() -> None:
        freq = _frequency_report(text)
        findings["frequency"] = freq
        for shift, decoded in _caesar(text):
            add("caesar", decoded, f"shift={shift}")
        add("atbash", _atbash(text))
        for key_byte, decoded in _xor_single(data):
            add("xor-single", _text(decoded), f"key=0x{key_byte:02x}")
        for xor_key, decoded in _xor_repeating(data, max_key):
            add("xor-repeating", _text(decoded), f"key={xor_key!r}")
        if key:
            add("vigenere", _vigenere(text, key), f"key={key!r}")
        else:
            for vig_key, decoded in _vigenere_auto(text, max_key):
                add("vigenere-auto", decoded, f"key={vig_key!r}")
        for rails, decoded in _railfence_brute(text):
            add("railfence", decoded, f"rails={rails}")

    if mode in ("auto",):
        run_all()
        for label_name in _hash_id(text):
            findings["notes"].append(f"hash-like input: {label_name}")
        jwt = _jwt_decode(text)
        if jwt:
            findings["jwt"] = jwt
        rsa = _rsa_attack(text, {}, fmt)
        if rsa.get("plaintext"):
            add("rsa", rsa["plaintext"], "decrypted")
            findings["rsa"] = rsa
    elif mode == "frequency":
        findings["frequency"] = _frequency_report(text)
    elif mode == "caesar":
        for shift, decoded in _caesar(text):
            add("caesar", decoded, f"shift={shift}")
    elif mode == "atbash":
        add("atbash", _atbash(text))
    elif mode == "xor":
        for key_byte, decoded in _xor_single(data):
            add("xor-single", _text(decoded), f"key=0x{key_byte:02x}")
        for xor_key, decoded in _xor_repeating(data, max_key):
            add("xor-repeating", _text(decoded), f"key={xor_key!r}")
    elif mode == "vigenere":
        if key:
            add("vigenere", _vigenere(text, key), f"key={key!r}")
        else:
            findings["notes"].append("no key supplied; attempting auto-crack")
            for vig_key, decoded in _vigenere_auto(text, max_key):
                add("vigenere-auto", decoded, f"key={vig_key!r}")
    elif mode == "railfence":
        for rails, decoded in _railfence_brute(text):
            add("railfence", decoded, f"rails={rails}")
    elif mode == "hash":
        findings["hashes"] = _hash_id(text)
        if not findings["hashes"]:
            findings["notes"].append("input did not match a known hash format")
    elif mode == "jwt":
        jwt = _jwt_decode(text)
        if jwt:
            findings["jwt"] = jwt
            add("jwt-payload", json.dumps(jwt.get("payload"), default=str), "decoded payload")
        else:
            findings["notes"].append("input is not a three-part JWT")
    elif mode == "rsa":
        findings["rsa"] = _rsa_attack(text, {"key": key}, fmt)
        if findings["rsa"].get("plaintext"):
            add("rsa", findings["rsa"]["plaintext"], "decrypted")

    candidates.sort(key=lambda item: (not item["flags"], item["score"]))
    findings["candidates"] = candidates[:30]
    findings["size"] = size

    lines = [f"Crypto analysis of {label} (mode={mode}, {size} bytes)"]
    if findings.get("frequency"):
        freq = findings["frequency"]
        top = list(freq["frequencies_pct"].items())[:8]
        lines.append(
            f"Frequency: IoC={freq['index_of_coincidence']} "
            f"(monoalphabetic={freq['likely_monoalphabetic']}), top={top}"
        )
    if findings.get("hashes"):
        lines.append("Hash-like: " + ", ".join(findings["hashes"]))
    if findings.get("jwt"):
        lines.append(f"JWT header={findings['jwt']['header']}")
        lines.append(f"JWT payload={json.dumps(findings['jwt']['payload'], default=str)[:500]}")
        if findings["jwt"]["risks"]:
            lines.append("JWT risks: " + ", ".join(findings["jwt"]["risks"]))
    if findings.get("rsa"):
        rsa = findings["rsa"]
        lines.append(f"RSA: {rsa.get('findings')}")
        if rsa.get("plaintext"):
            lines.append(f"RSA plaintext: {rsa['plaintext']!r}")
        if rsa.get("error"):
            lines.append(f"RSA: {rsa['error']}")
    for note in findings["notes"]:
        lines.append(f"Note: {note}")
    lines.append(f"Ranked candidates ({len(candidates)}):")
    for index, cand in enumerate(candidates[:20], start=1):
        marker = " [FLAG]" if cand["flags"] else ""
        detail = f" ({cand['detail']})" if cand["detail"] else ""
        lines.append(f"[{index}] {cand['method']}{detail}{marker} score={cand['score']}")
        lines.append("    " + cand["value"][:300].replace("\n", "\n    "))

    return attach_flags(
        ToolResult(
            tool="crypto_analyze",
            target=label,
            display=f"crypto_analyze(path={path!r}, mode={mode!r})" if path else f"crypto_analyze(mode={mode!r})",
            returncode=0,
            output="\n".join(lines)[:20000],
            network_active=False,
            activity="passive",
            started_at=started.isoformat(),
            duration_seconds=duration_since(started),
            data=findings,
        ),
        fmt,
    )


def _text(data: bytes) -> str:
    return data.decode("latin-1", errors="replace")


def crypto_analyze_spec(root: Path, timeout: int, out_limit: int, fmt=None) -> ToolSpec:
    return ToolSpec(
        name="crypto_analyze",
        description=(
            "Analyze classical/weak crypto offline: frequency & index-of-coincidence, "
            "Caesar/ROT/Atbash, single-byte and repeating-key XOR, Vigenere (keyed or "
            "auto-cracked), Rail-fence, JWT decode with alg=none/HS256 flags, hash-type "
            "identification, and a bounded RSA attack (small modulus, close primes, e=1). "
            "mode='auto' runs the applicable analyses and ranks candidates. Read-only."
        ),
        purpose="Recover plaintext/flags from classical and misused modern crypto.",
        input_schema={
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Path relative to the challenge directory."},
                "input": {"type": "string", "description": "Inline ciphertext or token."},
                "mode": {"type": "string", "enum": list(MODES)},
                "key": {"type": "string", "description": "Key for Vigenere (or RSA override)."},
                "max_key_length": {"type": "integer", "minimum": 1, "maximum": 16},
            },
            "additionalProperties": False,
        },
        risk="informational",
        side_effects="None: pure in-memory computation on provided data.",
        network_active=False,
        approval_policy="none",
        timeout=min(timeout, 30),
        max_output_chars=out_limit,
        activity="passive",
        approval_level=1,
        scope_requirements="Confined to the challenge directory; no network access.",
        result_schema={"type": "object", "properties": {
            "candidates": {"type": "array"}, "frequency": {"type": "object"}, "jwt": {"type": "object"},
        }},
        show=lambda args: (
            f"crypto_analyze(path={args.get('path')!r}, mode={args.get('mode', 'auto')!r})"
            if args.get("path") else f"crypto_analyze(mode={args.get('mode', 'auto')!r})"
        ),
        execute=lambda args, scope_items, evidence=None: analyze_crypto(
            root,
            args.get("path"),
            args.get("input"),
            str(args.get("mode", "auto")),
            args.get("key"),
            int(args.get("max_key_length", 12)),
            fmt,
        ),
    )
