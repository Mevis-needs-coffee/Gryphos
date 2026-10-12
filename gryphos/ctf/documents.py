"""Safe parsing of documents, text, and structured data.

Extracts readable text and metadata from PDF, JSON, XML, HTML, CSV/TSV, TOML,
INI, RTF, plain text, and Office Open XML (docx/xlsx/pptx, which are zips).
Never executes macros, scripts, or embedded programs: PDF JavaScript/Launch/
EmbeddedFile and XML DOCTYPE/ENTITY are *flagged* as risks, not run. All output
is character-bounded.
"""

from __future__ import annotations

import csv
import io
import json
import re
import tomllib
import zlib
from datetime import UTC, datetime
from pathlib import Path

from ..tools.base import ToolResult, ToolSpec, duration_since
from .sandbox import MAX_SCAN_BYTES, attach_flags, read_bounded, relative_label, resolve_inside

_PRINTABLE = re.compile(rb"[\x20-\x7e]{4,}")
_TAG = re.compile(r"<[^>]+>")
_HTML_COMMENT = re.compile(r"<!--(.*?)-->", re.DOTALL)
_HTML_LINK = re.compile(r"(?:href|src)\s*=\s*[\"']([^\"']+)[\"']", re.IGNORECASE)
_RTF_CONTROL = re.compile(rb"\\[a-zA-Z]+-?\d* ?|[{}]")


def _pdf(data: bytes, max_chars: int) -> dict:
    metadata: dict[str, str] = {}
    for match in re.finditer(rb"/(Title|Author|Subject|Creator|Producer|Keywords)\s*\(([^)]*)\)", data):
        metadata[match.group(1).decode("latin-1")] = match.group(2).decode("latin-1", errors="replace")
    risks: list[str] = []
    for token, label in (
        (b"/JavaScript", "embedded JavaScript"), (b"/JS", "embedded JavaScript"),
        (b"/Launch", "launch action"), (b"/OpenAction", "open action"),
        (b"/EmbeddedFile", "embedded file"),
    ):
        if token in data and label not in risks:
            risks.append(label)
    runs: list[str] = []
    for match in re.finditer(rb"stream\r?\n", data):
        start = match.end()
        end = data.find(b"endstream", start)
        if end < 0:
            continue
        raw = data[start:end].rstrip(b"\r\n")
        try:
            decoded = zlib.decompress(raw)
        except zlib.error:
            continue
        for chunk in _PRINTABLE.findall(decoded):
            runs.append(chunk.decode("latin-1", errors="replace"))
        if sum(len(r) for r in runs) > max_chars:
            break
    text = "\n".join(runs)[:max_chars]
    return {"format": "pdf", "metadata": metadata, "risks": risks, "text": text,
            "note": "streams decoded with zlib; text extraction is best-effort"}


def _json(data: bytes, max_chars: int) -> dict:
    try:
        value = json.loads(data.decode("utf-8", errors="replace"))
    except json.JSONDecodeError as exc:
        return {"format": "json", "error": f"invalid JSON: {exc.msg} (line {exc.lineno})"}
    flat: list[str] = []

    def walk(node, depth=0):
        if depth > 6 or len(flat) > 500:
            return
        if isinstance(node, dict):
            for key, val in node.items():
                flat.append(str(key))
                walk(val, depth + 1)
        elif isinstance(node, list):
            for item in node:
                walk(item, depth + 1)
        else:
            flat.append(str(node))

    walk(value)
    return {"format": "json", "keys": flat[:200], "text": "\n".join(flat)[:max_chars]}


def _hardened_fromstring(data: bytes):
    """Parse XML with defusedxml when present; else stdlib with entity risks flagged."""
    import xml.etree.ElementTree as ET

    from .deps import optional_module

    defused = optional_module("defusedxml")
    if defused is not None:
        return defused.fromstring(data)
    return ET.fromstring(data)  # noqa: S314 - DOCTYPE/ENTITY flagged; external entities never resolved


def _xml(data: bytes, max_chars: int) -> dict:
    import xml.etree.ElementTree as ET

    risks: list[str] = []
    if b"<!DOCTYPE" in data:
        risks.append("DOCTYPE declaration")
    if b"<!ENTITY" in data:
        risks.append("ENTITY declaration (potential XXE / bomb)")
    tags: list[str] = []
    texts: list[str] = []
    try:
        root = _hardened_fromstring(data)
        for element in root.iter():
            tags.append(element.tag)
            if element.text and element.text.strip():
                texts.append(element.text.strip())
            if len(texts) > 500:
                break
    except ET.ParseError as exc:
        return {"format": "xml", "error": f"parse error: {exc}", "risks": risks,
                "text": _fallback_text(data)[:max_chars]}
    except ValueError as exc:
        return {"format": "xml", "error": f"refused unsafe XML: {type(exc).__name__}", "risks": risks,
                "text": _fallback_text(data)[:max_chars]}
    return {"format": "xml", "tags": tags[:200], "risks": risks, "text": "\n".join(texts)[:max_chars]}


def _fallback_text(data: bytes) -> str:
    stripped = _TAG.sub(" ", data.decode("utf-8", errors="replace"))
    return re.sub(r"\s+", " ", stripped).strip()


def _html(data: bytes, max_chars: int) -> dict:
    text = data.decode("utf-8", errors="replace")
    comments = [c.strip() for c in _HTML_COMMENT.findall(text)]
    links = _HTML_LINK.findall(text)
    risks = ["inline <script>" ] if "<script" in text.lower() else []
    body = _TAG.sub(" ", _HTML_COMMENT.sub(" ", text))
    body = re.sub(r"\s+", " ", body).strip()
    joined = "\n".join([*comments, body])
    return {"format": "html", "comments": comments[:50], "links": links[:100], "risks": risks,
            "text": joined[:max_chars]}


def _tabular(data: bytes, max_chars: int) -> dict:
    text = data.decode("utf-8", errors="replace")
    sample = text[:8192]
    try:
        dialect = csv.Sniffer().sniff(sample, delimiters=",\t;|")
        delimiter = dialect.delimiter
    except csv.Error:
        delimiter = "\t" if "\t" in sample else ","
    rows = list(csv.reader(io.StringIO(text), delimiter=delimiter))
    preview = "\n".join(delimiter.join(row) for row in rows[:50])
    return {"format": "tabular", "delimiter": repr(delimiter), "rows": len(rows),
            "columns": len(rows[0]) if rows else 0, "header": rows[0][:50] if rows else [],
            "text": preview[:max_chars]}


def _rtf(data: bytes, max_chars: int) -> dict:
    stripped = _RTF_CONTROL.sub(b" ", data)
    runs = [c.decode("latin-1", errors="replace") for c in _PRINTABLE.findall(stripped)]
    return {"format": "rtf", "text": " ".join(runs)[:max_chars]}


def _ooxml(data: bytes, max_chars: int) -> dict:
    import zipfile

    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        names = archive.namelist()
        pieces: list[str] = []
        for name in ("word/document.xml", "xl/sharedStrings.xml", "ppt/slides/slide1.xml"):
            if name in names:
                raw = archive.read(name)
                text = _TAG.sub(" ", raw.decode("utf-8", errors="replace"))
                text = re.sub(r"\s+", " ", text).strip()
                pieces.append(text)
        macros = [n for n in names if n.endswith(("vbaProject.bin", ".vbs", ".js"))]
    risks = [f"macro/script part: {m}" for m in macros]
    return {"format": "ooxml", "members": names[:100], "risks": risks, "text": "\n".join(pieces)[:max_chars]}


def _toml(data: bytes, max_chars: int) -> dict:
    try:
        value = tomllib.loads(data.decode("utf-8", errors="replace"))
    except tomllib.TOMLDecodeError as exc:
        return {"format": "toml", "error": f"invalid TOML: {exc}"}
    text = json.dumps(value, default=str)[:max_chars]
    return {"format": "toml", "keys": list(value)[:200], "text": text}


def _text(data: bytes, max_chars: int) -> dict:
    text = data.decode("utf-8", errors="replace")
    lines = text.splitlines()
    return {"format": "text", "lines": len(lines), "text": text[:max_chars]}


def parse_document(root: Path, path: str, max_chars: int, fmt=None) -> ToolResult:
    started = datetime.now(UTC)
    target = resolve_inside(root, path)
    data, size = read_bounded(target, MAX_SCAN_BYTES)
    label = relative_label(root, target)
    cap = max(200, min(int(max_chars), 20000))
    head = data[:16]

    if head[:5] == b"%PDF-":
        info = _pdf(data, cap)
    elif head[:2] == b"PK" and target.suffix.lower() in (".docx", ".xlsx", ".pptx", ".docm", ".xlsm", ".pptm"):
        info = _ooxml(data, cap)
    elif head[:5] == b"{\\rtf":
        info = _rtf(data, cap)
    elif head[:1] in (b"{", b"[") and target.suffix.lower() == ".json":
        info = _json(data, cap)
    elif head[:1] == b"<":
        stripped = data[:512].lstrip()
        if stripped[:1] == b"<" and re.search(rb"<!doctype\s+html|<html", data[:1024], re.IGNORECASE):
            info = _html(data, cap)
        else:
            info = _xml(data, cap)
    elif target.suffix.lower() in (".toml",):
        info = _toml(data, cap)
    elif target.suffix.lower() in (".csv", ".tsv"):
        info = _tabular(data, cap)
    elif target.suffix.lower() in (".json",):
        info = _json(data, cap)
    else:
        printable = all(9 <= b <= 13 or 32 <= b <= 126 for b in data[:4096]) if data else False
        info = _text(data, cap) if printable else (
            {"format": "binary",
             "strings": [c.decode("latin-1", errors="replace") for c in _PRINTABLE.findall(data)][:200],
             "text": "\n".join(c.decode("latin-1", errors="replace") for c in _PRINTABLE.findall(data))[:cap]}
        )

    info["path"] = label
    info["size"] = size
    lines = [f"Document: {label} ({size} bytes)", f"Format: {info.get('format')}"]
    if info.get("error"):
        lines.append(f"Error: {info['error']}")
    if info.get("note"):
        lines.append(f"Note: {info['note']}")
    if info.get("risks"):
        lines.append("Risks (not executed): " + ", ".join(info["risks"]))
    if info.get("metadata"):
        lines.append("Metadata: " + ", ".join(f"{k}={v}" for k, v in info["metadata"].items()))
    if info.get("delimiter") is not None:
        lines.append(f"Tabular: delimiter={info['delimiter']}, rows={info.get('rows')}, columns={info.get('columns')}")
    if info.get("comments"):
        lines.append(f"Comments ({len(info['comments'])}):")
        lines.extend(f"  {c[:200]}" for c in info["comments"][:20])
    if info.get("links"):
        lines.append("Links: " + ", ".join(info["links"][:20]))
    if info.get("tags"):
        lines.append("XML tags: " + ", ".join(dict.fromkeys(info["tags"]))[:500])
    lines.append("Extracted text:")
    lines.append((info.get("text") or "")[:cap])

    return attach_flags(
        ToolResult(
            tool="document_parse", target=label, display=f"document_parse(path={path!r})",
            returncode=0, output="\n".join(lines)[:20000], network_active=False, activity="passive",
            started_at=started.isoformat(), duration_seconds=duration_since(started), data=info,
        ),
        fmt,
    )


def document_parse_spec(root: Path, timeout: int, out_limit: int, fmt=None) -> ToolSpec:
    return ToolSpec(
        name="document_parse",
        description=(
            "Extract text and metadata from documents/structured data: PDF (bounded Flate "
            "stream decode), JSON, XML, HTML, CSV/TSV, TOML, RTF, plain text, and OOXML "
            "(docx/xlsx/pptx). Flags risky constructs (PDF JavaScript/Launch/EmbeddedFile, "
            "XML DOCTYPE/ENTITY, Office macros) without executing them."
        ),
        purpose="Read challenge documents for hidden text, comments, and flag-shaped content.",
        input_schema={
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Path relative to the challenge directory."},
                "max_chars": {"type": "integer", "minimum": 200, "maximum": 20000},
            },
            "required": ["path"],
            "additionalProperties": False,
        },
        risk="informational",
        side_effects="None: read-only parsing; never executes macros, scripts, or embedded programs.",
        network_active=False,
        approval_policy="none",
        timeout=min(timeout, 30),
        max_output_chars=out_limit,
        activity="passive",
        approval_level=1,
        scope_requirements="Confined to the challenge directory; no network access.",
        result_schema={"type": "object", "properties": {
            "format": {"type": "string"}, "risks": {"type": "array"}, "text": {"type": "string"},
        }},
        show=lambda args: f"document_parse(path={args.get('path')!r})",
        execute=lambda args, scope_items, evidence=None: parse_document(
            root, str(args.get("path", "")), int(args.get("max_chars", 4000)), fmt
        ),
    )
