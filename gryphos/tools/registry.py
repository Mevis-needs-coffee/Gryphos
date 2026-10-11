"""Tool registry assembly.

build_registry() returns the complete, fixed set of tools Gryphos may ever
execute, filtered by the configured approval-level ceiling. The model can only
propose names present here; anything else is rejected by the agent before
validation. Per-tool timeout and output limits are derived centrally from
settings so no tool can raise its own bounds. Tools above the ceiling (Level 4
is disabled by default) are never registered.
"""

from __future__ import annotations

from ..approval import DEFAULT_MAX_ENABLED_LEVEL, level_allowed
from .base import ToolSpec
from .dependency_audit import dependency_audit_spec
from .http import http_headers_spec, http_redirects_spec
from .local_audit import local_audit_spec
from .local_ports import local_ports_spec
from .nmap import nmap_spec
from .secret_detect import secret_detect_spec
from .source_scan import source_scan_spec
from .tcp_banner import tcp_banner_spec
from .tech import web_tech_spec
from .tls import tls_cert_spec


def build_registry(settings) -> dict[str, ToolSpec]:
    # Imported lazily to avoid the analysis -> tools -> registry cycle.
    from ..analysis import summarize_evidence_spec

    timeout = int(getattr(settings, "command_timeout", 60))
    out_limit = int(getattr(settings, "max_output_chars", 5000))
    max_level = int(getattr(settings, "max_approval_level", DEFAULT_MAX_ENABLED_LEVEL))
    specs: list[ToolSpec] = [
        # Level 2 — active network tools (approval required, scope-enforced):
        nmap_spec(timeout, out_limit),
        http_headers_spec(timeout, out_limit),
        http_redirects_spec(timeout, out_limit),
        tls_cert_spec(timeout, out_limit),
        web_tech_spec(timeout, out_limit),
        # Level 3 — more intrusive, tightly constrained (approval required):
        tcp_banner_spec(timeout, out_limit),
        # Level 1 — passive local, read-only tools (no network, no prompt):
        local_ports_spec(timeout, out_limit),
        local_audit_spec(timeout, out_limit),
        source_scan_spec(timeout, out_limit),
        dependency_audit_spec(timeout, out_limit),
        secret_detect_spec(timeout, out_limit),
        # Level 0 — offline evidence analysis:
        summarize_evidence_spec(timeout, out_limit),
    ]
    enabled = [spec for spec in specs if level_allowed(spec.approval_level, max_level)]
    registry = {spec.name: spec for spec in enabled}
    if len(registry) != len(enabled):
        raise ValueError("Duplicate tool name in registry.")
    return registry
