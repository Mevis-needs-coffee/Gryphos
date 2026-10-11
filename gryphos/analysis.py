"""Evidence analysis: cross-tool correlation, contradiction detection, summaries.

This is the internal 'reasoning over our own results' layer (phase-4 Tool 10).
Nothing here ever performs network or system activity; it only reads evidence
already collected in the current session or in saved sessions. It normalizes
observation records produced by tools, correlates them, surfaces
contradictions between tools, and can diff two sessions without re-executing
anything.
"""

from __future__ import annotations

from datetime import UTC, datetime

from .tools.base import ToolResult, ToolSpec


def normalize_observations(evidence: list) -> list[dict]:
    """Flatten tool_result evidence into comparable observation records."""
    observations: list[dict] = []
    for item in evidence or []:
        if not isinstance(item, dict) or item.get("kind") != "tool_result":
            continue
        tool = item.get("tool", "?")
        data = item.get("data") or {}
        if tool == "nmap_basic":
            for port in data.get("open_ports", []):
                observations.append({
                    "tool": tool, "target": item.get("target"), "port": port.get("port"),
                    "value": port.get("service") or port.get("version") or "open", "kind": "open_port",
                })
        elif tool in {"http_headers", "http_redirects", "web_tech"}:
            observations.append({
                "tool": tool, "target": item.get("target"),
                "value": item.get("returncode") == 0, "kind": "http_ok",
            })
            tech_names = list(data.get("technology_hints") or [])
            tech_names += [t.get("name") for t in (data.get("technologies") or [])]
            for name in tech_names:
                if name:
                    observations.append({
                        "tool": tool, "target": item.get("target"),
                        "value": name, "kind": "tech",
                    })
        elif tool == "local_ports":
            for listener in data.get("listeners", []):
                observations.append({
                    "tool": tool, "target": "local",
                    "port": f"{listener.get('port')}/{listener.get('protocol', '').replace('6', '')}",
                    "value": listener.get("listener"), "kind": "listener",
                })
        elif tool in {"source_scan", "secret_detect", "dependency_audit"}:
            counts = data.get("counts") or {}
            if tool == "source_scan":
                total = sum(
                    counts.get(key, 0) for key in ("bandit", "semgrep")
                ) if isinstance(counts, dict) else 0
            elif tool == "dependency_audit":
                total = data.get("vulnerable_packages", 0)
            else:
                total = counts.get("total", 0) if isinstance(counts, dict) else 0
            observations.append({
                "tool": tool, "target": item.get("target"),
                "value": total, "kind": "finding_count",
            })
        elif tool == "tls_cert" and data.get("expired"):
            observations.append({
                "tool": tool, "target": item.get("target"),
                "value": data.get("subject_cn"), "kind": "expired_cert",
            })
    return observations


def summarize_evidence(evidence: list) -> ToolResult:
    """Collapse collected evidence into a compact, reviewable summary."""
    facts: list[str] = []
    counts: dict[str, int] = {}
    for item in evidence or []:
        if not isinstance(item, dict) or item.get("kind") != "tool_result":
            continue
        tool = item.get("tool", "?")
        counts[tool] = counts.get(tool, 0) + 1
        target = item.get("target", "?")
        data = item.get("data") or {}
        if tool == "nmap_basic":
            ports = data.get("open_ports", [])
            if ports:
                facts.append(f"{target}: {len(ports)} open port(s) — " + ", ".join(
                    f"{p.get('port')} ({p.get('service', '?')})" for p in ports
                ))
            else:
                facts.append(f"{target}: no open ports among top 100 TCP")
        elif tool == "http_headers":
            status = data.get("status_code")
            facts.append(f"{target}: HTTP {status or '?'} headers fetched")
        elif tool == "http_redirects":
            hops = data.get("hops", [])
            facts.append(f"{target}: redirect chain {len(hops)} hop(s), blocked={bool(data.get('blocked'))}")
        elif tool == "tls_cert":
            days = data.get("days_until_expiry")
            status = "EXPIRED" if data.get("expired") else f"{days} days" if days is not None else "unknown"
            facts.append(f"{target}: TLS cert {data.get('subject_cn', '?')} expiry {status}")
        elif tool == "local_ports":
            counts_l = data.get("counts", {})
            facts.append(
                f"local listeners: {counts_l.get('total', 0)} "
                f"(wildcard {counts_l.get('exposed_wildcard', 0)})"
            )
        elif tool == "secret_detect":
            facts.append(f"secret scan: {data.get('counts', {}).get('total', 0)} potential secret(s), values redacted")
        elif tool == "source_scan":
            scan_counts = data.get("counts") or {}
            facts.append(
                "source_scan: "
                f"{scan_counts.get('bandit', 0)} bandit + {scan_counts.get('semgrep', 0)} semgrep finding(s)"
            )
        elif tool == "dependency_audit":
            facts.append(
                f"dependency_audit: {data.get('vulnerable_packages', 0)} vulnerable package(s)"
                + (", data unavailable" if data.get("data_unavailable") else "")
            )
        elif tool == "local_audit":
            facts.append(f"local_audit[{data.get('mode', '?')}]: command exited {item.get('returncode')}")
        elif tool == "web_tech":
            facts.append(f"{target}: technologies " + ", ".join(
                t.get("name", "?") for t in (data.get("technologies") or [])
            ) or "none inferred")
        else:
            facts.append(f"{tool}: executed ({dict(counts).get(tool)})")
    obs = normalize_observations(evidence)
    contradictions = detect_contradictions(evidence)
    tool_results = [
        item for item in (evidence or [])
        if isinstance(item, dict) and item.get("kind") == "tool_result"
    ]
    lines = [
        f"Evidence summary: {len(facts)} fact(s), {len(tool_results)} tool result(s)"
    ]
    lines.extend(f"- {fact}" for fact in facts)
    if contradictions:
        lines.append("Cross-tool contradictions:")
        lines.extend(f"- {c['message']}" for c in contradictions[:10])
    if obs:
        lines.append(f"Normalized observations: {len(obs)}")
    return ToolResult(
        tool="summarize_evidence", target="(whole session)", display="summarize_evidence (offline, no network)",
        returncode=0, output="\n".join(lines), network_active=False, activity="passive",
        data={"facts": facts, "tool_counts": counts, "observations": obs[:200],
              "contradictions": contradictions, "normalized_count": len(obs),
              "correlation": correlate(evidence)},
    )


def correlate(evidence: list) -> list[dict]:
    """Group normalized observations by target for cross-tool correlation."""
    observations = normalize_observations(evidence)
    groups: dict[str, list[dict]] = {}
    for obs in observations:
        groups.setdefault(str(obs.get("target") or "?"), []).append(obs)
    return [
        {
            "target": target,
            "kinds": {obs["kind"] for obs in items},
            "observation_count": len(items),
            "tools": sorted({obs["tool"] for obs in items}),
            "notes": _correlation_notes(target, items),
        }
        for target, items in sorted(groups.items())
    ]


def _correlation_notes(target: str, items: list[dict]) -> list[str]:
    notes: list[str] = []
    open_ports = {o["port"] for o in items if o["kind"] == "open_port"}
    techs = {o["value"] for o in items if o["kind"] == "tech"}
    if open_ports:
        notes.append(f"Open ports: {', '.join(sorted(str(p) for p in open_ports)) or '(names only)'}")
    if techs:
        notes.append(f"Identified technology: {', '.join(str(t) for t in sorted(techs))}")
    listeners = [o for o in items if o["kind"] == "listener"]
    if any(o["value"].startswith("wildcard") for o in listeners):
        notes.append("A local listener is bound to all interfaces (exposed beyond loopback).")
    return notes


def detect_contradictions(evidence: list) -> list[dict]:
    """Find conflicting signals between tools (e.g. port reported closed but an
    HTTP probe succeeded on it)."""
    contradictions: list[dict] = []
    nmap_open: dict[str, set] = {}
    for item in _tool_results(evidence, "nmap_basic"):
        if item.get("returncode") != 0:
            continue
        target = str(item.get("target"))
        ports = nmap_open.setdefault(target, set())
        for port in (item.get("data") or {}).get("open_ports", []):
            ports.add(str(port.get("port")).split("/")[0] or "")
    for item in _tool_results(evidence, ("http_headers", "http_redirects", "web_tech", "tls_cert")):
        target = str(item.get("target"))
        port = str((item.get("data") or {}).get("port", ""))
        if not port:
            continue
        nmap_ports = nmap_open.get(target, set())
        if item.get("returncode") == 0 and target in nmap_open and port not in nmap_ports:
            contradictions.append({
                "message": (
                    f"{item.get('tool')} succeeded on {target}:{port}, but nmap "
                    "reported it closed/not open among the top 100 ports."
                ),
                "evidence": [item.get("tool"), "nmap_basic"],
                "severity": "medium",
            })
    for item in _tool_results(evidence, "dependency_audit"):
        if (item.get("data") or {}).get("data_unavailable") and (item.get("data") or {}).get("clean"):
            contradictions.append({
                "message": f"dependency_audit for {item.get('target')} reported both 'clean' and 'data unavailable'.",
                "evidence": ["dependency_audit"],
                "severity": "high",
            })
    # 'clean' may legitimately coexist with data_unavailable only when no
    # vulnerabilities AND full resolution succeeded; guard against the flag combo.
    return contradictions[:20]


def _tool_results(evidence: list, tools: str | tuple[str, ...]) -> list[dict]:
    names = {tools} if isinstance(tools, str) else set(tools)
    return [
        item for item in (evidence or [])
        if isinstance(item, dict) and item.get("kind") == "tool_result" and item.get("tool") in names
    ]


def compare_sessions(existing: dict, prior: dict, session_label: str, prior_label: str) -> dict:
    """Diff two saved sessions by normalized observations without re-executing."""
    existing_obs = normalize_observations(existing.get("evidence", []))
    prior_obs = normalize_observations(prior.get("evidence", []))
    ensure_key = lambda obs: (  # noqa: E731 - local helper
        f"{obs.get('tool')}|{obs.get('target')}|{obs.get('kind')}|{obs.get('port', '')}|{obs.get('value')}"
    )
    existing_keys = {ensure_key(o) for o in existing_obs}
    prior_keys = {ensure_key(o) for o in prior_obs}
    return {
        "session": session_label,
        "prior_session": prior_label,
        "new_observations": [o for o in existing_obs if ensure_key(o) not in prior_keys][:100],
        "gone_observations": [o for o in prior_obs if ensure_key(o) not in existing_keys][:100],
        "unchanged_count": len(existing_keys & prior_keys),
        "analysis_date": datetime.now(UTC).date().isoformat(),
        "note": "Diff is by tool+target+kind+port+value; no tools were re-executed.",
    }


def summarize_evidence_spec(timeout: int, out_limit: int) -> ToolSpec:
    return ToolSpec(
        name="summarize_evidence",
        description=(
            "Produce a compact offline summary of all evidence collected so far "
            "(per-target open ports, HTTP/TLS results, local listeners, secret "
            "and dependency findings). Correlates cross-tool observations and "
            "surfaces contradictions. No network activity and no tools re-run."
        ),
        purpose="Give the model and the operator a trustworthy digest of collected evidence before concluding.",
        input_schema={"type": "object", "properties": {}, "additionalProperties": False},
        risk="informational",
        side_effects="None: reads current-session evidence only.",
        network_active=False,
        approval_policy="none",
        timeout=min(timeout, 15),
        max_output_chars=out_limit,
        activity="passive",
        approval_level=0,
        scope_requirements="None: operates on already-collected evidence only.",
        result_schema={"type": "object", "properties": {
            "facts": {"type": "array"},
            "tool_counts": {"type": "object"},
            "observations": {"type": "array"},
            "contradictions": {"type": "array"},
        }},
        execute=lambda args, scope_items, evidence=None: summarize_evidence(evidence or []),
    )
