"""Tool registry assembly.

build_registry() returns the complete, fixed set of tools Gryphos may ever
execute. The model can only propose names present here; anything else is
rejected by the agent before validation. Per-tool timeout and output limits are
derived centrally from settings so no tool can raise its own bounds.
"""

from __future__ import annotations

from ..analysis import summarize_evidence_spec
from .base import ToolSpec
from .dependency_audit import dependency_audit_spec
from .http import http_headers_spec, http_redirects_spec
from .local_audit import local_audit_spec
from .local_ports import local_ports_spec
from .nmap import nmap_spec
from .secret_detect import secret_detect_spec
from .source_scan import source_scan_spec
from .tech import web_tech_spec
from .tls import tls_cert_spec


def build_registry(settings) -> dict[str, ToolSpec]:
    timeout = int(getattr(settings, "command_timeout", 60))
    out_limit = int(getattr(settings, "max_output_chars", 5000))
    specs: list[ToolSpec] = [
        # Active network tools (approval required, scope-enforced):
        nmap_spec(timeout, out_limit),
        http_headers_spec(timeout, out_limit),
        http_redirects_spec(timeout, out_limit),
        tls_cert_spec(timeout, out_limit),
        web_tech_spec(timeout, out_limit),
        # Passive local, read-only tools (no network approval needed):
        local_ports_spec(timeout, out_limit),
        local_audit_spec(timeout, out_limit),
        source_scan_spec(timeout, out_limit),
        dependency_audit_spec(timeout, out_limit),
        secret_detect_spec(timeout, out_limit),
        # Offline evidence analysis:
        summarize_evidence_spec(timeout, out_limit),
    ]
    registry = {spec.name: spec for spec in specs}
    if len(registry) != len(specs):
        raise ValueError("Duplicate tool name in registry.")
    return registry
