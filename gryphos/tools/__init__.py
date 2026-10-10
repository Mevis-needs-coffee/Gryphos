"""Tool package: core interfaces plus the fixed, registered tool set.

Public API (stable for callers and tests):
    ToolError, ToolDependencyError, ToolResult, ToolSpec, validate_args
    build_registry(settings)
    _parse_nmap_output, _run_nmap_basic   (nmap helpers)

Registration is fixed: only tools returned by build_registry() can ever run.
"""

from __future__ import annotations

from .base import (
    ToolDependencyError,
    ToolError,
    ToolResult,
    ToolSpec,
    validate_args,
)
from .nmap import _parse_nmap_output, _run_nmap_basic
from .registry import build_registry

__all__ = [
    "ToolDependencyError",
    "ToolError",
    "ToolResult",
    "ToolSpec",
    "_parse_nmap_output",
    "_run_nmap_basic",
    "build_registry",
    "validate_args",
]
