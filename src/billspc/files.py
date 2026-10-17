"""Small file helpers shared by the modules: an atomic, private JSON writer and its reader."""
from __future__ import annotations

import json
import os
from pathlib import Path


def write_json(path: Path, data: dict) -> None:
    """Write `data` as JSON, whole or not at all, readable by the owner only (0600).

    The text goes to a temporary file beside the target, which is then renamed over it, so a reader
    never sees half a file. Listings name the user's files and consent pages carry rclone's state
    value, so neither is readable by other users."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as out:
        out.write(json.dumps(data, indent=1, ensure_ascii=False, default=str) + "\n")
    os.replace(tmp, path)


def read_json(path: Path) -> dict:
    """The JSON object in `path`, or {} when the file is missing, unreadable or not an object."""
    try:
        data = json.loads(Path(path).read_text())
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}
