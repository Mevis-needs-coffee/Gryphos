"""Challenge loading and discovery.

A challenge lives in its own directory:

    challenges/<id>/challenge.json
    challenges/<id>/<provided files...>

The JSON declares identity, category, description, task, and optional flag
format / submit configuration. Loading is strictly read-only and confined to the
challenge directory; the identifier is validated so it cannot escape the
challenges root.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from .models import Challenge

_CHALLENGE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
MAX_PROVIDED_FILES = 500
MAX_FILE_BYTES_LISTING = 50 * 1024 * 1024


class ChallengeError(ValueError):
    """Raised when a challenge cannot be located or is invalid."""


def _validate_id(challenge_id: str) -> str:
    text = (challenge_id or "").strip()
    if not _CHALLENGE_ID_RE.match(text):
        raise ChallengeError(
            f"Invalid challenge id {challenge_id!r}. Use letters, digits, '.', '_', or '-'."
        )
    return text


def _list_files(root: Path) -> tuple[str, ...]:
    files: list[str] = []
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        name = path.relative_to(root).as_posix()
        if name == "challenge.json":
            continue
        files.append(name)
        if len(files) >= MAX_PROVIDED_FILES:
            break
    return tuple(files)


def load_challenge(challenges_dir: Path | str, challenge_id: str) -> Challenge:
    """Load and validate one challenge by id."""
    base = Path(challenges_dir)
    cid = _validate_id(challenge_id)
    root = (base / cid).resolve()
    # Defense in depth: the resolved directory must stay inside the base.
    try:
        root.relative_to(base.resolve())
    except ValueError as exc:
        raise ChallengeError(f"Challenge path escapes the challenges directory: {cid!r}") from exc
    manifest = root / "challenge.json"
    if not root.is_dir() or not manifest.is_file():
        raise ChallengeError(
            f"No challenge {cid!r} in {base}. Expected {manifest}."
        )
    try:
        data = json.loads(manifest.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ChallengeError(f"Could not read {manifest}: {exc}") from exc
    if not isinstance(data, dict):
        raise ChallengeError(f"{manifest} must contain a JSON object.")
    data.setdefault("id", cid)
    data["id"] = cid
    try:
        challenge = Challenge.from_dict(data, root=root)
    except (KeyError, ValueError) as exc:
        raise ChallengeError(f"Invalid challenge {cid!r}: {exc}") from exc
    if not challenge.files:
        challenge.files = _list_files(root)
    return challenge


def discover_challenges(challenges_dir: Path | str) -> list[dict]:
    """List loadable challenges (id, name, category) newest-name-first."""
    base = Path(challenges_dir)
    if not base.is_dir():
        return []
    entries: list[dict] = []
    for child in sorted(base.iterdir()):
        if not child.is_dir() or not (child / "challenge.json").is_file():
            continue
        try:
            challenge = load_challenge(base, child.name)
        except ChallengeError as exc:
            entries.append({"id": child.name, "name": child.name, "category": "?", "error": str(exc)})
            continue
        entries.append({"id": challenge.id, "name": challenge.name, "category": challenge.category})
    return entries
