"""Optional dependency discovery for CTF tools.

Gryphos never installs anything. This module probes for optional system
binaries and Python modules and exposes them so that:

- a tool can use a richer external utility *when it is present* and fall back to
  a bounded pure-Python implementation otherwise, and
- when a capability genuinely has no fallback, the tool raises a clear
  `ToolDependencyError` naming the binary/module and an install hint.

`capabilities_report()` is surfaced to the operator and to the solver (as the
`list_capabilities` tool) so what is missing is discoverable, not a mystery.
"""

from __future__ import annotations

import importlib.util
import shutil
from dataclasses import dataclass

from ..tools.base import ToolDependencyError


@dataclass(frozen=True)
class Capability:
    name: str
    kind: str  # "binary" | "module"
    purpose: str
    install_hint: str


# Optional tools that improve fidelity. None are required: every one has a
# bounded standard-library fallback unless noted in `purpose`.
CAPABILITIES: tuple[Capability, ...] = (
    Capability("file", "binary", "libmagic file-type identification (fallback: built-in signature table)",
               "apt install file / brew install file"),
    Capability("strings", "binary", "GNU strings extraction (fallback: built-in strings scanner)",
               "apt install binutils / brew install binutils"),
    Capability("binwalk", "binary", "Signature carving of embedded files (fallback: built-in carver)",
               "apt install binwalk / pip install binwalk"),
    Capability("exiftool", "binary", "Rich image/document metadata (fallback: built-in header parsers)",
               "apt install libimage-exiftool-perl / brew install exiftool"),
    Capability("7z", "binary", "7z/rar listing (fallback: zip/tar/gz/bz2/xz via stdlib)",
               "apt install p7zip-full / brew install p7zip"),
    Capability("unzip", "binary", "Additional zip inspection (fallback: stdlib zipfile)",
               "apt install unzip"),
    Capability("tcpdump", "binary", "Packet capture reading (fallback: built-in pcap parser)",
               "apt install tcpdump"),
    Capability("tshark", "binary", "Deep packet dissection (fallback: built-in pcap parser)",
               "apt install tshark"),
    Capability("PIL", "module", "Image pixel access for LSB stego triage (fallback: header parsing only)",
               "pip install Pillow"),
    Capability("scapy", "module", "Rich packet dissection (fallback: built-in pcap parser)",
               "pip install scapy"),
    Capability("dpkt", "module", "Fast packet parsing (fallback: built-in pcap parser)",
               "pip install dpkt"),
    Capability("yaml", "module", "YAML document parsing", "pip install PyYAML"),
    Capability("defusedxml", "module", "Hardened XML parsing (fallback: bounds + DOCTYPE refusal)",
               "pip install defusedxml"),
    Capability("olefile", "module", "Legacy OLE/CFB (doc/xls/ppt) stream listing",
               "pip install olefile"),
    Capability("pefile", "module", "PE executable metadata", "pip install pefile"),
    Capability("Crypto", "module", "Extra cryptography helpers (fallback: stdlib classical ciphers)",
               "pip install pycryptodome"),
)


def has_binary(name: str) -> bool:
    return shutil.which(name) is not None


def has_module(name: str) -> bool:
    try:
        return importlib.util.find_spec(name) is not None
    except (ImportError, ValueError):
        return False


def _present(cap: Capability) -> bool:
    return has_binary(cap.name) if cap.kind == "binary" else has_module(cap.name)


def optional_binary(name: str) -> str | None:
    return shutil.which(name)


def optional_module(name: str):
    """Import and return a module if available, else None (never raises)."""
    if not has_module(name):
        return None
    try:
        return importlib.import_module(name)
    except Exception:  # noqa: BLE001 - a broken optional module is treated as absent
        return None


def require_binary(name: str, install_hint: str) -> str:
    path = shutil.which(name)
    if not path:
        raise ToolDependencyError(f"{name} is not installed. {install_hint}")
    return path


def capability_status() -> list[dict]:
    return [
        {
            "name": cap.name,
            "kind": cap.kind,
            "available": _present(cap),
            "purpose": cap.purpose,
            "install_hint": cap.install_hint,
        }
        for cap in CAPABILITIES
    ]


def capabilities_report() -> str:
    lines = ["Optional capabilities (Gryphos never installs these):"]
    for cap in CAPABILITIES:
        mark = "available" if _present(cap) else "MISSING  "
        lines.append(f"- [{mark}] {cap.name} ({cap.kind}): {cap.purpose}")
        if not _present(cap):
            lines.append(f"    install: {cap.install_hint}")
    available = sum(1 for cap in CAPABILITIES if _present(cap))
    lines.append(f"{available}/{len(CAPABILITIES)} optional capabilities available.")
    return "\n".join(lines)
