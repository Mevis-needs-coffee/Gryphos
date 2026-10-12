"""PCAP / PCAP-NG summary and lightweight protocol dissection (stdlib only).

Parses the capture header and per-packet records without scapy: link type,
packet/byte counts, time span, Ethernet/EtherType, IPv4/IPv6 addresses, TCP/UDP
ports, DNS queries, HTTP request lines, and printable strings from payloads (with
flag detection). Per-packet dissection is bounded by count and byte budget.
"""

from __future__ import annotations

import re
import struct
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path

from ..tools.base import ToolResult, ToolSpec, duration_since
from .sandbox import MAX_SCAN_BYTES, attach_flags, read_bounded, relative_label, resolve_inside

_ETH_IPV4 = 0x0800
_ETH_IPV6 = 0x86DD
_ETH_ARP = 0x0806
_HTTP_METHODS = (b"GET ", b"POST ", b"HEAD ", b"PUT ", b"DELETE ", b"OPTIONS ", b"PATCH ", b"HTTP/")
_PRINTABLE = re.compile(rb"[\x20-\x7e]{5,}")
_MAX_STRINGS = 60


def _parse_ethernet(payload: bytes) -> dict | None:
    if len(payload) < 14:
        return None
    ethertype = struct.unpack(">H", payload[12:14])[0]
    body = payload[14:]
    result: dict = {"ethertype": ethertype}
    if ethertype == _ETH_IPV4 and len(body) >= 20:
        ihl = (body[0] & 0x0F) * 4
        proto = body[9]
        result.update(
            protocol="ipv4",
            src=".".join(str(b) for b in body[12:16]),
            dst=".".join(str(b) for b in body[16:20]),
            ip_proto=proto,
            transport=body[ihl:],
            total_len=struct.unpack(">H", body[2:4])[0],
        )
    elif ethertype == _ETH_IPV6 and len(body) >= 40:
        next_header = body[6]
        result.update(
            protocol="ipv6",
            src=_ipv6(body[8:24]),
            dst=_ipv6(body[24:40]),
            ip_proto=next_header,
            transport=body[40:],
        )
    elif ethertype == _ETH_ARP:
        result.update(protocol="arp")
    else:
        result.update(protocol=f"ethertype-0x{ethertype:04x}", transport=body)
    return result


def _ipv6(raw: bytes) -> str:
    parts = [f"{raw[i] << 8 | raw[i + 1]:x}" for i in range(0, 16, 2)]
    return ":".join(parts)


def _dissect_transport(entry: dict) -> dict:
    proto = entry.pop("ip_proto", None)
    transport = entry.pop("transport", b"")
    out: dict = {}
    if proto == 6 and len(transport) >= 20:
        sport, dport = struct.unpack(">HH", transport[:4])
        doff = (transport[12] >> 4) * 4
        out.update(proto="tcp", sport=sport, dport=dport, app_payload=transport[doff:])
    elif proto == 17 and len(transport) >= 8:
        sport, dport = struct.unpack(">HH", transport[:4])
        out.update(proto="udp", sport=sport, dport=dport, app_payload=transport[8:])
    elif proto == 1:
        out.update(proto="icmp")
    elif proto is not None:
        out.update(proto=f"ip-proto-{proto}")
    return out


def _parse_dns_query(payload: bytes) -> str | None:
    if len(payload) < 12:
        return None
    qdcount = struct.unpack(">H", payload[4:6])[0]
    if qdcount < 1:
        return None
    pos = 12
    labels: list[str] = []
    while pos < len(payload):
        length = payload[pos]
        if length == 0:
            break
        if length & 0xC0:
            break
        pos += 1
        labels.append(payload[pos : pos + length].decode("latin-1", errors="replace"))
        pos += length
    return ".".join(labels) if labels else None


def _parse_pcap(data: bytes, max_packets: int) -> dict:
    magic = data[:4]
    if magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
        endian = ">"
    elif magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
        endian = "<"
    else:
        return {"format": "pcap", "error": "unrecognized pcap magic"}
    if len(data) < 24:
        return {"format": "pcap", "error": "truncated global header"}
    _, _, _, _, _, snaplen, network = struct.unpack(endian + "IHHIIII", data[:24])
    pos = 24
    packets = []
    times: list[float] = []
    total_bytes = 0
    while pos + 16 <= len(data) and len(packets) < max_packets:
        ts_sec, ts_frac, incl_len, orig_len = struct.unpack(endian + "IIII", data[pos : pos + 16])
        pos += 16
        frame = data[pos : pos + incl_len]
        pos += incl_len
        total_bytes += orig_len
        times.append(ts_sec + ts_frac / 1_000_000)
        packets.append(frame)
    return {
        "format": "pcap",
        "link_type": network,
        "snaplen": snaplen,
        "packet_count": len(packets),
        "total_bytes": total_bytes,
        "first_ts": _ts(times[0]) if times else None,
        "last_ts": _ts(times[-1]) if times else None,
        "packets": packets[:max_packets],
        "truncated": len(packets) >= max_packets,
    }


def _parse_pcapng(data: bytes, max_packets: int) -> dict:
    packets: list[bytes] = []
    link_types: list[int] = []
    pos = 0
    endian = "<"
    while pos + 12 <= len(data):
        if data[pos : pos + 4] == b"\x0a\x0d\x0d\x0a":
            bom = data[pos + 8 : pos + 12]
            endian = "<" if bom == b"\x4d\x3c\x2b\x1a" else ">"
        block_type, block_len = struct.unpack(endian + "II", data[pos : pos + 8])
        if block_len < 12 or pos + block_len > len(data):
            break
        body = data[pos + 8 : pos + block_len - 4]
        if block_type == 0x00000001 and len(body) >= 2:  # Interface Description Block
            link_types.append(struct.unpack(endian + "H", body[:2])[0])
        elif block_type == 0x00000006 and len(body) >= 20:  # Enhanced Packet Block
            cap_len = struct.unpack(endian + "I", body[12:16])[0]
            packets.append(body[20 : 20 + cap_len])
            if len(packets) >= max_packets:
                break
        pos += block_len
    return {
        "format": "pcapng",
        "link_type": link_types[0] if link_types else None,
        "interfaces": len(link_types),
        "packet_count": len(packets),
        "packets": packets,
        "truncated": len(packets) >= max_packets,
    }


def _ts(value: float) -> str:
    try:
        return datetime.fromtimestamp(value, tz=UTC).isoformat()
    except (OverflowError, OSError, ValueError):
        return str(value)


def summarize_pcap(root: Path, path: str, max_packets: int, include_strings: bool, fmt=None) -> ToolResult:
    started = datetime.now(UTC)
    target = resolve_inside(root, path)
    data, size = read_bounded(target, MAX_SCAN_BYTES)
    label = relative_label(root, target)
    cap = max(1, min(int(max_packets), 20000))

    parsed = _parse_pcapng(data, cap) if data[:4] == b"\x0a\x0d\x0d\x0a" else _parse_pcap(data, cap)

    if parsed.get("error"):
        return attach_flags(
            ToolResult(
                tool="pcap_summary", target=label, display=f"pcap_summary(path={path!r})",
                returncode=0, output=f"PCAP: {label}\nError: {parsed['error']}",
                network_active=False, activity="passive", started_at=started.isoformat(),
                duration_seconds=duration_since(started), data={"path": label, **parsed},
            ),
            fmt,
        )

    counters: Counter = Counter()
    conversations: Counter = Counter()
    ports: Counter = Counter()
    dns_queries: list[str] = []
    http_requests: list[str] = []
    strings: list[str] = []
    link_type = parsed.get("link_type")

    for frame in parsed["packets"]:
        entry = _parse_ethernet(frame) if link_type in (1, None, 0) else None
        if not entry:
            continue
        counters[entry.get("protocol", "unknown")] += 1
        dissected = _dissect_transport(entry)
        counters[dissected.get("proto", entry.get("protocol", "unknown"))] += 1
        if "src" in entry and "dst" in entry:
            conversations[f"{entry['src']} -> {entry['dst']}"] += 1
        sport, dport = dissected.get("sport"), dissected.get("dport")
        for port in (sport, dport):
            if port is not None:
                ports[port] += 1
        payload = dissected.get("app_payload", b"")
        if dissected.get("proto") == "udp" and (sport == 53 or dport == 53):
            query = _parse_dns_query(payload)
            if query:
                dns_queries.append(query)
        if dissected.get("proto") == "tcp" and payload.startswith(_HTTP_METHODS):
            line = payload.split(b"\r\n", 1)[0]
            http_requests.append(line[:200].decode("latin-1", errors="replace"))
        if include_strings and payload:
            for match in _PRINTABLE.finditer(payload):
                value = match.group(0).decode("latin-1", errors="replace")
                if value not in strings:
                    strings.append(value)
                if len(strings) >= _MAX_STRINGS:
                    break

    data_out = {
        "path": label,
        "size": size,
        "format": parsed.get("format"),
        "link_type": link_type,
        "packet_count": parsed.get("packet_count"),
        "total_bytes": parsed.get("total_bytes"),
        "first_ts": parsed.get("first_ts"),
        "last_ts": parsed.get("last_ts"),
        "protocols": dict(counters),
        "top_conversations": conversations.most_common(10),
        "top_ports": ports.most_common(10),
        "dns_queries": dns_queries[:40],
        "http_requests": http_requests[:40],
        "strings": strings[: _MAX_STRINGS],
        "truncated": parsed.get("truncated", False),
    }
    lines = [
        f"Capture: {label} ({size} bytes)",
        f"Format: {data_out['format']}, link_type={link_type}",
        f"Packets: {data_out['packet_count']} (total {data_out.get('total_bytes')} bytes)",
    ]
    if data_out.get("first_ts"):
        lines.append(f"Time span: {data_out['first_ts']} .. {data_out['last_ts']}")
    lines.append("Protocols: " + ", ".join(f"{k}={v}" for k, v in counters.items()))
    if conversations:
        lines.append("Top conversations:")
        lines.extend(f"  {conv} x{count}" for conv, count in conversations.most_common(10))
    if ports:
        lines.append("Top ports: " + ", ".join(f"{p}={c}" for p, c in ports.most_common(10)))
    if dns_queries:
        lines.append("DNS queries: " + ", ".join(dict.fromkeys(dns_queries[:20])))
    if http_requests:
        lines.append("HTTP requests:")
        lines.extend(f"  {req}" for req in http_requests[:20])
    if strings:
        lines.append(f"Payload strings ({len(strings)}):")
        lines.extend(f"  {value}" for value in strings[: _MAX_STRINGS])

    return attach_flags(
        ToolResult(
            tool="pcap_summary", target=label, display=f"pcap_summary(path={path!r})",
            returncode=0, output="\n".join(lines)[:20000], network_active=False, activity="passive",
            started_at=started.isoformat(), duration_seconds=duration_since(started), data=data_out,
        ),
        fmt,
    )


def pcap_summary_spec(root: Path, timeout: int, out_limit: int, fmt=None) -> ToolSpec:
    return ToolSpec(
        name="pcap_summary",
        description=(
            "Summarize a PCAP or PCAP-NG capture offline: link type, packet/byte counts, time "
            "span, Ethernet/EtherType, IPv4/IPv6 conversations, TCP/UDP ports, DNS queries, "
            "HTTP request lines, and printable payload strings (with flag detection). Stdlib "
            "only; no scapy/tshark required."
        ),
        purpose="Characterize network-traffic challenges without live capture or external tools.",
        input_schema={
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Path relative to the challenge directory."},
                "max_packets": {"type": "integer", "minimum": 1, "maximum": 20000},
                "include_strings": {"type": "boolean"},
            },
            "required": ["path"],
            "additionalProperties": False,
        },
        risk="informational",
        side_effects="None: reads a capture file; opens no sockets.",
        network_active=False,
        approval_policy="none",
        timeout=min(timeout, 30),
        max_output_chars=out_limit,
        activity="passive",
        approval_level=1,
        scope_requirements="Confined to the challenge directory; no network access.",
        result_schema={"type": "object", "properties": {
            "protocols": {"type": "object"}, "dns_queries": {"type": "array"}, "strings": {"type": "array"},
        }},
        show=lambda args: f"pcap_summary(path={args.get('path')!r})",
        execute=lambda args, scope_items, evidence=None: summarize_pcap(
            root, str(args.get("path", "")), int(args.get("max_packets", 5000)),
            bool(args.get("include_strings", True)), fmt,
        ),
    )
