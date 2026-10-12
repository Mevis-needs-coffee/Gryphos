"""Path confinement and bounded, safe local I/O for CTF solver tools.

Every solver tool reads only *inside* the configured challenge directory. The
path is resolved with symlinks followed and required to stay within the root, so
traversal (`..`), absolute paths, and symlink escapes are refused. Reads are
bounded by a per-call byte cap and a hard scan cap; extraction always targets a
private temporary directory, never the challenge tree, and never executes the
bytes it handles.

These helpers are the single place where 'what counts as an allowed local
artifact' is decided, so the confinement rule cannot drift between tools.
"""

from __future__ import annotations

import tempfile
from contextlib import contextmanager
from pathlib import Path

from ..tools.base import ToolError

# Per-call read ceiling for previews (matches the classic challenge_file reader).
MAX_READ_BYTES = 65536
# Hard ceiling for whole-file scans (strings, signatures, entropy, carving).
MAX_SCAN_BYTES = 8 * 1024 * 1024
# Archive limits: members, aggregate and per-entry bytes, compression ratio,
# and nesting depth for nested archives.
MAX_ARCHIVE_MEMBERS = 2000
MAX_ARCHIVE_TOTAL_BYTES = 128 * 1024 * 1024
MAX_ARCHIVE_ENTRY_BYTES = 32 * 1024 * 1024
MAX_ARCHIVE_RATIO = 2000
MAX_ARCHIVE_DEPTH = 3
# Bounded recursive decoding / carving.
MAX_DECODE_ROUNDS = 5
MAX_CARVE_OBJECTS = 40


def is_inside(root: Path, candidate: Path) -> bool:
    try:
        candidate.resolve().relative_to(Path(root).resolve())
        return True
    except ValueError:
        return False


def resolve_inside(root: Path, path: str) -> Path:
    """Resolve a challenge-relative path, refusing anything outside the root.

    Raises ToolError (safe to show users) for empty, absolute, traversal, or
    symlink-escaping paths, and for missing files.
    """
    raw = (path or "").strip()
    if not raw:
        raise ToolError("A file path within the challenge directory is required.")
    if Path(raw).is_absolute() or raw.startswith("~"):
        raise ToolError("Path must be relative to the challenge directory (no absolute paths).")
    root = Path(root).resolve()
    target = (root / raw).resolve()
    if not is_inside(root, target):
        raise ToolError(
            "Refused: the path escapes the challenge directory. Only files inside "
            "the configured challenge may be read."
        )
    if not target.exists():
        raise ToolError(f"No such file in the challenge: {raw}")
    return target


def read_bounded(path: Path, max_bytes: int) -> tuple[bytes, int]:
    """Read at most `max_bytes` from a file; return (data, total_size)."""
    cap = max(0, int(max_bytes))
    try:
        size = path.stat().st_size
        with path.open("rb") as handle:
            data = handle.read(cap) if cap else b""
    except OSError as exc:
        raise ToolError(f"Could not read {path.name}: {type(exc).__name__}") from exc
    return data, size


@contextmanager
def safe_tempdir():
    """A private temporary directory that is always removed on exit.

    Used for bounded, non-executing artifact extraction so nothing is written
    into the challenge directory.
    """
    with tempfile.TemporaryDirectory(prefix="gryphos-ctf-") as name:
        yield Path(name)


def relative_label(root: Path, path: Path) -> str:
    try:
        return path.resolve().relative_to(Path(root).resolve()).as_posix()
    except ValueError:
        return path.name


def find_flags(text: str, fmt=None) -> list[str]:
    """Locate flag-shaped strings in untrusted text using the challenge format."""
    from .flag import FlagFormat

    return (fmt or FlagFormat()).find(text or "")


def attach_flags(result, fmt=None):
    """Record any flag-shaped strings found in a tool's output onto its result.

    Detection only: the solver still verifies candidates. This makes flags that
    surface inside a tool's own rendering visible in structured evidence.
    """
    found = find_flags(getattr(result, "output", "") or "", fmt)
    if found:
        data = getattr(result, "data", None)
        if isinstance(data, dict):
            data.setdefault("flags", found)
        result.output = (
            (result.output or "").rstrip()
            + "\n\nFlag-shaped strings detected: "
            + ", ".join(found)
        )
    return result
