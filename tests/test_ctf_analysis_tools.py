"""Offline tests for the Phase-2 CTF analysis tools.

Every fixture is synthesized in-memory/tmp_path: encodings, compressed and
malformed archives, images with appended data, a hand-built PCAP, documents, and
classical-crypto challenges. No network, no external binaries are required (the
built-in parsers are exercised; `file`/`exiftool` are only used if present).
"""

from __future__ import annotations

import base64
import gzip
import io
import json
import struct
import tarfile
import zipfile
import zlib

import pytest

from gryphos.ctf.tools import build_solver_registry
from gryphos.tools import ToolError

FLAG_RE = r"flag\{[^}]*\}"


@pytest.fixture
def root(tmp_path):
    return tmp_path


@pytest.fixture
def registry(root):
    return build_solver_registry(root, timeout=10, out_limit=8192, flag_pattern=FLAG_RE)


def run(registry, tool, **args):
    return registry[tool].execute(args, (), [])


# --- fixtures ---------------------------------------------------------------

def make_png(width=8, height=4, text=b"", tail=b"") -> bytes:
    def chunk(tag: bytes, data: bytes) -> bytes:
        body = tag + data
        return struct.pack(">I", len(data)) + body + struct.pack(">I", zlib.crc32(body) & 0xFFFFFFFF)

    ihdr = struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)
    return (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", ihdr)
        + (chunk(b"tEXt", text) if text else b"")
        + chunk(b"IDAT", b"\x00" * 12)
        + chunk(b"IEND", b"")
        + tail
    )


def make_pcap() -> bytes:
    def eth(payload: bytes, ethertype: int = 0x0800) -> bytes:
        return b"\xaa" * 6 + b"\xbb" * 6 + struct.pack(">H", ethertype) + payload

    def ip4(proto: int, src: str, dst: str, payload: bytes) -> bytes:
        header = struct.pack(
            ">BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), 0, 0, 64, proto, 0,
            bytes(map(int, src.split("."))), bytes(map(int, dst.split("."))),
        )
        return header + payload

    def udp(sp: int, dp: int, payload: bytes) -> bytes:
        return struct.pack(">HHHH", sp, dp, 8 + len(payload), 0) + payload

    def tcp(sp: int, dp: int, payload: bytes) -> bytes:
        return struct.pack(">HHIIBBHHH", sp, dp, 0, 0, 5 << 4, 0x18, 8192, 0, 0) + payload

    dns = (
        b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
        + b"\x04flag\x07example\x00\x00\x01\x00\x01"
    )
    packets = [
        eth(ip4(17, "10.0.0.1", "8.8.8.8", udp(40000, 53, dns))),
        eth(ip4(6, "10.0.0.1", "10.0.0.2",
                tcp(50000, 80, b"GET /flag{pcap_http} HTTP/1.1\r\nHost: x\r\n\r\n"))),
    ]
    body = b"".join(struct.pack("<IIII", 1000 + i, 0, len(p), len(p)) + p for i, p in enumerate(packets))
    return b"\xd4\xc3\xb2\xa1" + struct.pack("<HHIIII", 2, 4, 0, 0, 65535, 1) + body


def make_zip(members: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, data in members.items():
            archive.writestr(name, data)
    return buf.getvalue()


# --- registry / capabilities ------------------------------------------------

def test_capabilities_tool_reports(registry):
    result = run(registry, "list_capabilities")
    assert "capabilities" in result.data
    assert result.network_active is False
    assert "Optional capabilities" in result.output


def test_all_tools_are_offline_and_bounded(registry):
    for spec in registry.values():
        assert spec.network_active is False
        assert spec.max_output_chars > 0
        assert spec.timeout > 0


# --- file identification ----------------------------------------------------

def test_file_identify_png_and_hashes(root, registry):
    (root / "img.png").write_bytes(make_png())
    result = run(registry, "file_identify", path="img.png")
    assert result.data["type"] == "PNG image"
    assert result.data["hashes"]["sha256"]
    assert result.data["entropy"] >= 0


def test_file_identify_finds_strings_and_flag(root, registry):
    (root / "notes.txt").write_text("prefix flag{hello_strings} suffix\n", encoding="utf-8")
    result = run(registry, "file_identify", path="notes.txt")
    assert "flag{hello_strings}" in result.output
    assert result.data["flags"] == ["flag{hello_strings}"]


def test_file_identify_detects_appended_data(root, registry):
    (root / "img.png").write_bytes(make_png(tail=b"EXTRAflag{tail_here}"))
    result = run(registry, "file_identify", path="img.png")
    assert result.data["appended_bytes_after_end"] > 0
    assert any("flag{tail_here}" in s["value"] for s in result.data["strings_sample"])


def test_file_identify_rejects_traversal(registry):
    with pytest.raises(ToolError, match="escapes"):
        run(registry, "file_identify", path="../../etc/passwd")


# --- artifact carving -------------------------------------------------------

def test_artifact_extract_scans_embedded(root, registry):
    (root / "img.png").write_bytes(make_png(tail=b"\x89PNG\r\n\x1a\n" + b"flag{embedded_png}"))
    result = run(registry, "artifact_extract", path="img.png")
    assert any(obj["name"] == "PNG image" for obj in result.data["objects"])


def test_artifact_extract_carves_range(root, registry):
    (root / "blob.bin").write_bytes(b"A" * 10 + b"flag{carved}" + b"B" * 10)
    result = run(registry, "artifact_extract", path="blob.bin", offset=10, length=15)
    assert result.data["length"] == 15
    assert result.data["hashes"]["sha256"]


def test_artifact_extract_offset_beyond_end_rejected(root, registry):
    (root / "blob.bin").write_bytes(b"small")
    with pytest.raises(ToolError, match="beyond"):
        run(registry, "artifact_extract", path="blob.bin", offset=999999)


# --- encodings --------------------------------------------------------------

def test_encoding_decode_base64(root, registry):
    (root / "msg.txt").write_text(base64.b64encode(b"flag{base64_ok}").decode(), encoding="utf-8")
    result = run(registry, "encoding_decode", path="msg.txt")
    assert "flag{base64_ok}" in result.output
    assert result.data["candidates"][0]["flags"] == ["flag{base64_ok}"]


def test_encoding_decode_hex_inline(registry):
    payload = b"flag{hex_ok}".hex()
    result = run(registry, "encoding_decode", input=payload)
    assert any("flag{hex_ok}" in c["text"] for c in result.data["candidates"])


def test_encoding_decode_binary_bits(registry):
    bits = "".join(f"{b:08b}" for b in b"flag{bits_ok}")
    result = run(registry, "encoding_decode", input=bits)
    assert any("flag{bits_ok}" in c["text"] for c in result.data["candidates"])


def test_encoding_decode_url(registry):
    result = run(registry, "encoding_decode", input="flag%7Burl_ok%7D")
    assert any("flag{url_ok}" in c["text"] for c in result.data["candidates"])


def test_encoding_decode_finds_blob_inside_prose(root, registry):
    blob = base64.b64encode(b"flag{embedded_blob}").decode()
    (root / "note.txt").write_text(f"the answer is {blob} enjoy\n", encoding="utf-8")
    result = run(registry, "encoding_decode", path="note.txt")
    assert "flag{embedded_blob}" in result.output
    assert result.data["candidates"][0]["flags"] == ["flag{embedded_blob}"]


def test_encoding_decode_requires_input(registry):
    with pytest.raises(ToolError, match="Provide"):
        run(registry, "encoding_decode")


def test_encoding_decode_rejects_both_inputs(registry):
    with pytest.raises(ToolError, match="not both"):
        run(registry, "encoding_decode", path="x.txt", input="hi")


# --- archives ---------------------------------------------------------------

def test_archive_inspect_zip_lists_members(root, registry):
    (root / "bundle.zip").write_bytes(make_zip({"a.txt": b"hello", "b.txt": b"world!"}))
    result = run(registry, "archive_inspect", path="bundle.zip")
    assert result.data["kind"] == "zip"
    assert {m["name"] for m in result.data["members"]} == {"a.txt", "b.txt"}


def test_archive_inspect_flags_traversal(root, registry):
    (root / "evil.zip").write_bytes(make_zip({"../evil.sh": b"echo no", "ok.txt": b"y"}))
    result = run(registry, "archive_inspect", path="evil.zip")
    flagged = {m["name"]: m["flags"] for m in result.data["members"]}
    assert "path-traversal" in flagged["../evil.sh"]


def test_archive_inspect_malformed_zip(root, registry):
    (root / "broken.zip").write_bytes(b"PK\x03\x04" + b"\x00" * 40)
    result = run(registry, "archive_inspect", path="broken.zip")
    assert result.data.get("error")
    assert result.network_active is False


def test_archive_inspect_tar(root, registry):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as archive:
        info = tarfile.TarInfo("note.txt")
        data = b"hi there"
        info.size = len(data)
        archive.addfile(info, io.BytesIO(data))
    (root / "bundle.tar").write_bytes(buf.getvalue())
    result = run(registry, "archive_inspect", path="bundle.tar")
    assert result.data["kind"] == "tar"
    assert result.data["members"][0]["name"] == "note.txt"


def test_archive_inspect_gzip_stream(root, registry):
    (root / "data.gz").write_bytes(gzip.compress(b"flag{gzip_stream} " * 4))
    result = run(registry, "archive_inspect", path="data.gz")
    assert result.data["kind"] == "gzip"
    assert "flag{gzip_stream}" in result.data["preview"]


def test_zip_in_zip_nested_detected(root, registry):
    inner = make_zip({"inner.txt": b"deep"})
    (root / "outer.zip").write_bytes(make_zip({"inner.zip": inner}))
    result = run(registry, "archive_inspect", path="outer.zip", max_depth=3)
    assert result.data["nested"]
    assert result.data["nested"][0]["summary"]["kind"] == "zip"


def test_member_flag_ratio_detects_bomb():
    from gryphos.ctf.archives import _member_flags

    assert "high-compression-ratio" in _member_flags("a.bin", 50_000_000, 1000, None)
    assert "oversize" in _member_flags("a.bin", 10_000_000_000, 1, None)


# --- images -----------------------------------------------------------------

def test_image_triage_dimensions_and_comment(root, registry):
    (root / "pic.png").write_bytes(make_png(width=16, height=9, text=b"Author\x00flag{in_text}"))
    result = run(registry, "image_triage", path="pic.png")
    assert result.data["format"] == "PNG"
    assert result.data["width"] == 16 and result.data["height"] == 9
    assert "flag{in_text}" in result.output


def test_image_triage_appended_tail(root, registry):
    (root / "pic.png").write_bytes(make_png(tail=b"SECRET flag{in_tail}"))
    result = run(registry, "image_triage", path="pic.png")
    assert result.data["tail"]["size"] > 0
    assert result.data["flags"] == ["flag{in_tail}"]


# --- pcap -------------------------------------------------------------------

def test_pcap_summary_protocols_and_flags(root, registry):
    (root / "cap.pcap").write_bytes(make_pcap())
    result = run(registry, "pcap_summary", path="cap.pcap")
    assert result.data["format"] == "pcap"
    assert result.data["packet_count"] == 2
    assert "flag.example" in result.data["dns_queries"]
    assert "flag{pcap_http}" in result.data["flags"]


def test_pcap_summary_malformed(root, registry):
    (root / "bad.pcap").write_bytes(b"\x00\x01\x02\x03nonsense")
    result = run(registry, "pcap_summary", path="bad.pcap")
    assert result.data.get("error")


# --- documents --------------------------------------------------------------

def test_document_parse_json(root, registry):
    (root / "a.json").write_text(json.dumps({"note": "flag{json_ok}"}), encoding="utf-8")
    result = run(registry, "document_parse", path="a.json")
    assert result.data["format"] == "json"
    assert "flag{json_ok}" in result.output


def test_document_parse_html_comment(root, registry):
    (root / "a.html").write_text("<html><!-- flag{html_ok} --><body>hi</body></html>", encoding="utf-8")
    result = run(registry, "document_parse", path="a.html")
    assert result.data["format"] == "html"
    assert "flag{html_ok}" in result.output


def test_document_parse_xml_flags_entity_risk(root, registry):
    payload = '<?xml version="1.0"?><!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/passwd">]><x>flag{xml_ok}</x>'
    (root / "a.xml").write_text(payload, encoding="utf-8")
    result = run(registry, "document_parse", path="a.xml")
    assert result.data["format"] == "xml"
    assert any("ENTITY" in risk for risk in result.data["risks"])
    assert "flag{xml_ok}" in result.output


def test_document_parse_malformed_json(root, registry):
    (root / "bad.json").write_text("{ not valid", encoding="utf-8")
    result = run(registry, "document_parse", path="bad.json")
    assert result.data.get("error")


def test_document_parse_csv(root, registry):
    (root / "rows.csv").write_text("a,b\n1,2\n3,4\n", encoding="utf-8")
    result = run(registry, "document_parse", path="rows.csv")
    assert result.data["format"] == "tabular"
    assert result.data["rows"] == 3


# --- crypto -----------------------------------------------------------------

def test_crypto_caesar_recovers_flag(registry):
    def rot(text, n):
        return "".join(chr((ord(c) - 97 + n) % 26 + 97) if c.islower() else c for c in text)

    result = run(registry, "crypto_analyze", input=rot("flag{caesar_ok}", 3), mode="caesar")
    assert "flag{caesar_ok}" in result.output
    assert result.data["candidates"][0]["flags"] == ["flag{caesar_ok}"]


def test_crypto_xor_single_byte(registry):
    cipher = bytes(b ^ 0x42 for b in b"flag{xor_ok}").decode("latin-1")
    result = run(registry, "crypto_analyze", input=cipher, mode="xor")
    assert "flag{xor_ok}" in result.output


def test_crypto_vigenere_with_key(registry):
    def encrypt(text, key):
        letters = [c for c in key if c.isalpha()]
        out, i = [], 0
        for ch in text:
            if ch.isalpha():
                shift = ord(letters[i % len(letters)]) - 97
                base = 97 if ch.islower() else 65
                out.append(chr((ord(ch) - base + shift) % 26 + base))
                i += 1
            else:
                out.append(ch)
        return "".join(out)

    cipher = encrypt("flag{vigenere_ok}", "lemon")
    result = run(registry, "crypto_analyze", input=cipher, mode="vigenere", key="lemon")
    assert "flag{vigenere_ok}" in result.output


def test_crypto_jwt_flags_alg_none(registry):
    header = base64.urlsafe_b64encode(json.dumps({"alg": "none", "typ": "JWT"}).encode()).rstrip(b"=")
    payload = base64.urlsafe_b64encode(json.dumps({"flag": "flag{jwt_ok}"}).encode()).rstrip(b"=")
    token = f"{header.decode()}.{payload.decode()}.sig"
    result = run(registry, "crypto_analyze", input=token, mode="jwt")
    assert result.data["jwt"]["header"]["alg"] == "none"
    assert "flag{jwt_ok}" in result.output


def test_crypto_rsa_small_modulus(registry):
    result = run(registry, "crypto_analyze", input="n=3233 e=17 c=855", mode="rsa")
    assert result.data["rsa"]["findings"]
    assert "plaintext" in result.data["rsa"]


def test_crypto_hash_identification(registry):
    result = run(registry, "crypto_analyze", input="d41d8cd98f00b204e9800998ecf8427e", mode="hash")
    assert any("MD5" in item for item in result.data["hashes"])


def test_crypto_frequency_report(registry):
    result = run(registry, "crypto_analyze", input="the quick brown fox jumps over the lazy dog", mode="frequency")
    assert "index_of_coincidence" in result.data["frequency"]


def test_crypto_unknown_mode_rejected(registry):
    with pytest.raises(ToolError, match="Unknown mode"):
        run(registry, "crypto_analyze", input="x", mode="magic")


# --- resource limits --------------------------------------------------------

def test_read_bounded_truncates(tmp_path):
    from gryphos.ctf.sandbox import read_bounded

    path = tmp_path / "limit-probe.bin"
    path.write_bytes(b"A" * 1000)
    data, size = read_bounded(path, 100)
    assert len(data) == 100 and size == 1000


def test_encoding_decode_respects_round_cap(registry):
    # A deep nested base64 chain must terminate within the round cap.
    payload = b"flag{deep}"
    for _ in range(6):
        payload = base64.b64encode(payload)
    result = run(registry, "encoding_decode", input=payload.decode(), max_rounds=2)
    assert result.data["candidates"] is not None
    for candidate in result.data["candidates"]:
        assert len(candidate["chain"]) <= 2
