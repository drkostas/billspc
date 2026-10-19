"""List the files changed under a folder since a moment, for a catch-up copy or a health check.

`changed_since()` walks one folder and returns a listing: every file whose content (mtime) or place
and name (ctime, since a move keeps the mtime) changed after `since`. Symbolic links are counted and
never followed. A path the `exclude` function rejects is left out, and an excluded folder is not
entered. A file the caller already copied and checked (`uploaded`) is left out until it changes
again. `write_json()` keeps the listing atomically.

A folder moved or renamed after `since` brings every file under it, because a move changes the
folder's ctime and leaves the times of the files inside alone. A folder counts as moved in three
ways:

- its date added (APFS keeps one, macOS only) is after `since` while the folder was made before:
  it was moved in from another folder, whatever changed inside it since
- it was made before `since`, and its ctime is after `since` and later than its mtime: renamed
  where it is (or tagged, or given a mode) after the last change inside it. An entry made, removed
  or renamed inside a folder sets its mtime and ctime to the same nanosecond, while a rename of the
  folder itself moves its ctime alone
- an earlier listing saw it moved and it is the same folder (its inode), since the ctime rule
  forgets a rename at the folder's next change

A folder renamed in place and then changed inside before any listing saw it is not caught: that
change sets both times together. Past `cap`, files under moved folders are counted
(`moved_unlisted`) and not named, so one moved tree of a million files cannot fill the listing.

The oldest change in a listing is a lower bound: a file's times say only its last change.
"""
from __future__ import annotations

import os
import struct
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Optional

from billspc.files import read_json, write_json
from billspc.filters import FilterSet

__all__ = ["changed_since", "write_json", "read_json", "added_at", "unsynced", "oldest_hours",
           "background", "MOVED_CAP"]

#: how many files under moved folders one listing names
MOVED_CAP = 20_000
#: the walk's priority (background()): nice 10, and macOS's throttled disk tier
NICE = 10
IOPOL_TYPE_DISK, IOPOL_SCOPE_PROCESS, IOPOL_THROTTLE = 0, 0, 3
#: getattrlist(2) for the date added (sys/attr.h): five attribute groups, ATTR_CMN_ADDEDTIME, and
#: FSOPT_NOFOLLOW so a link is never followed
ATTR_BIT_MAP_COUNT, ATTR_CMN_ADDEDTIME, FSOPT_NOFOLLOW = 5, 0x10000000, 0x00000001

Exclude = Callable[[str, bool], object]
_LIBC = None


def added_at(path: str) -> float | None:
    """When the item was put in the folder that holds it (APFS's date added, the "Date Added" Finder
    shows), or None when the file system does not say or the system is not macOS. Set when the item
    is made or moved into another folder, kept by a rename in place and by every change after."""
    global _LIBC
    if sys.platform != "darwin":
        return None
    try:
        import ctypes
        if _LIBC is None:
            lib = ctypes.CDLL("/usr/lib/libSystem.B.dylib", use_errno=True)
            lib.getattrlist.argtypes = [ctypes.c_char_p, ctypes.c_void_p, ctypes.c_void_p,
                                        ctypes.c_size_t, ctypes.c_uint]
            lib.getattrlist.restype = ctypes.c_int
            _LIBC = lib
        want = ctypes.create_string_buffer(struct.pack("=HHIIIII", ATTR_BIT_MAP_COUNT, 0,
                                                       ATTR_CMN_ADDEDTIME, 0, 0, 0, 0))
        buf = ctypes.create_string_buffer(32)
        if _LIBC.getattrlist(os.fsencode(path), want, buf, ctypes.sizeof(buf), FSOPT_NOFOLLOW) != 0:
            return None
        # the answer's own length, then a struct timespec, packed to four bytes
        length, sec, nsec = struct.unpack_from("=Iqq", buf.raw)
    except (OSError, AttributeError, struct.error, ValueError):
        return None
    return sec + nsec / 1e9 if length >= 20 else None


def _moved(rel: str, path: str, st: os.stat_result, cut: float, seen: dict) -> dict | None:
    """Whether the folder at `rel` was moved or renamed after `cut`, as {"path", "at", "ino", "how"},
    or None. The three ways are at the top of the module."""
    added = added_at(path)
    birth = getattr(st, "st_birthtime", None)
    if added is not None and added > cut and birth is not None and birth <= cut:
        return {"path": rel, "at": added, "ino": st.st_ino, "how": "moved in"}
    if st.st_ctime > cut and st.st_ctime_ns > st.st_mtime_ns and (birth is None or birth <= cut):
        return {"path": rel, "at": st.st_ctime, "ino": st.st_ino, "how": "renamed"}
    before = seen.get(rel) or {}
    at = before.get("at") or before.get("ctime")
    if before.get("ino") == st.st_ino and isinstance(at, (int, float)) and at > cut:
        return {"path": rel, "at": at, "ino": st.st_ino, "how": before.get("how") or "renamed"}
    return None


def _default_exclude() -> Exclude:
    fs = FilterSet()
    return fs.excluded


def changed_since(root: Path, since: datetime, *, exclude: Optional[Exclude] = None,
                  uploaded: dict | None = None, remembered: list[dict] | None = None,
                  cap: int | None = None, now: float | None = None, key: str | None = None) -> dict:
    """What changed under `root` after `since` and has no checked copy, as a listing:

        {"folder", "root", "since", "made_at", "exists", "files": [{"path", "size", "mtime",
         "mtime_ns", "ctime", "changed_at"}], "links", "never", "unreadable", "uploaded",
         "moved": [{"path", "at", "ino", "how"}], "moved_unlisted"}

    `exclude(rel, is_dir)` returns something true for a path to leave out (by default the built-in
    never-copied list). `uploaded` is {"uploaded": {path: {"size", "mtime_ns", "verified"}}}: a file
    whose size and mtime still match a verified entry is counted, not listed. `remembered` is the
    "moved" list of an earlier listing. `cap` bounds the files named under moved folders."""
    exclude = exclude or _default_exclude()
    cap = MOVED_CAP if cap is None else cap
    root = Path(root)
    now = time.time() if now is None else now
    out = {"folder": key, "root": str(root), "since": since.isoformat(),
           "made_at": datetime.fromtimestamp(now, timezone.utc).isoformat(), "exists": root.is_dir(),
           "files": [], "links": 0, "never": 0, "unreadable": 0, "uploaded": 0, "moved": [],
           "moved_unlisted": 0}
    if not out["exists"]:
        return out
    cut = since.timestamp()
    done = (uploaded or {}).get("uploaded") or {}
    seen = {m["path"]: m for m in (remembered or []) if isinstance(m, dict) and isinstance(m.get("path"), str)}
    under_moved = 0
    # (the folder's path from the top, its place on disk, when a folder above it moved, or None)
    stack: list[tuple[str, str, float | None]] = [("", str(root), None)]
    while stack:
        rel_dir, path, moved_at = stack.pop()
        try:
            entries = os.scandir(path)
        except OSError:
            out["unreadable"] += 1
            continue
        with entries:
            for e in entries:
                rel = f"{rel_dir}/{e.name}" if rel_dir else e.name
                try:
                    if e.is_symlink():
                        out["links"] += 1
                        continue
                    is_dir = e.is_dir(follow_symlinks=False)
                    if exclude(rel, is_dir):
                        out["never"] += 1
                        continue
                    st = e.stat(follow_symlinks=False)
                except OSError:
                    out["unreadable"] += 1
                    continue
                if is_dir:
                    here = moved_at
                    moved = _moved(rel, e.path, st, cut, seen)
                    if moved is not None:
                        here = max(moved_at or 0.0, moved["at"])
                        out["moved"].append(moved)
                    stack.append((rel, e.path, here))
                    continue
                own = max(st.st_mtime, st.st_ctime) > cut
                if not own and moved_at is None:
                    continue
                prior = done.get(rel)
                if (prior and prior.get("verified", True) and prior.get("size") == st.st_size
                        and prior.get("mtime_ns") == st.st_mtime_ns):
                    out["uploaded"] += 1
                    continue
                # the change the listing counts from: the content's, else the move's (only ctime
                # says it), else the move of a folder above it
                at = (st.st_mtime if st.st_mtime > cut else st.st_ctime) if own else moved_at
                # a copy that kept its source's time (cp -p, rsync -t, an unpacked archive) first held
                # this content at this path when it was made. macOS moves its birth back with the
                # mtime, so only its date added says so (asked only when its ctime is later than its
                # mtime, which a plain write never leaves). Counted from the mtime, a backup made
                # today of a file changed three days ago read as three days without a copy
                if own and st.st_ctime_ns > st.st_mtime_ns:
                    added = added_at(e.path)
                    if added is not None and added > at:
                        at = added
                if not own:
                    under_moved += 1
                    if under_moved > cap:
                        out["moved_unlisted"] += 1
                        continue
                out["files"].append({"path": rel, "size": st.st_size, "mtime": st.st_mtime,
                                     "mtime_ns": st.st_mtime_ns, "ctime": st.st_ctime, "changed_at": at})
    out["files"].sort(key=lambda f: f["path"])
    return out


def unsynced(listing: dict) -> int:
    """How many files a listing says have no checked copy: those it names and those it only counts."""
    return len(listing.get("files") or ()) + int(listing.get("moved_unlisted") or 0)


def oldest_hours(files, now: float, moves: list[dict] | None = None) -> float:
    """The age of the oldest change among `files` (a list, or a listing), in hours, 0 for none.
    `moves` speak for files past the cap, which are counted and not named."""
    if isinstance(files, dict):
        listing = files
        files = list(listing.get("files") or ())
        moves = list(listing.get("moved") or ()) if listing.get("moved_unlisted") else moves
    changes = [f.get("changed_at") or max(f["mtime"], f["ctime"]) for f in files]
    changes += [m.get("at") or m.get("ctime") for m in moves or () if (m.get("at") or m.get("ctime"))]
    return round(max(0.0, now - min(changes)) / 3600, 2) if changes else 0.0


def background() -> dict:
    """Lower this process to background priority before a large walk: nice 10, and on macOS the
    throttled disk tier, so the walk yields to everything else. Lasts for the rest of the process.
    Returns what it set, read back ({"nice", "io"}, io None off macOS)."""
    try:
        if os.getpriority(os.PRIO_PROCESS, 0) < NICE:
            os.setpriority(os.PRIO_PROCESS, 0, NICE)
    except OSError:
        pass
    io = None
    if sys.platform == "darwin":
        try:
            import ctypes
            libc = ctypes.CDLL("/usr/lib/libSystem.B.dylib", use_errno=True)
            libc.setiopolicy_np(IOPOL_TYPE_DISK, IOPOL_SCOPE_PROCESS, IOPOL_THROTTLE)
            io = libc.getiopolicy_np(IOPOL_TYPE_DISK, IOPOL_SCOPE_PROCESS)
        except (OSError, AttributeError):
            pass
    return {"nice": os.getpriority(os.PRIO_PROCESS, 0), "io": io}
