"""The files changed under a folder since a moment.

A planted folder holds files changed before and after the moment, a file moved after it (a move keeps
its content's time and changes its place's, so only ctime says so), a whole tree moved after it, a
repository's .git, Finder's junk, a rebuildable folder and a symbolic link. The moment is a time
inside the test run, so the planted times are seconds apart.
"""
from __future__ import annotations

import json
import os
import stat
import subprocess
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from billspc import scan
from billspc.filters import FilterSet, GlobRules

mac_only = pytest.mark.skipif(sys.platform != "darwin", reason="APFS's date added is read on macOS only")


def put(root: Path, rel: str, text: str = "x") -> Path:
    f = root / rel
    f.parent.mkdir(parents=True, exist_ok=True)
    f.write_text(text)
    return f


def mark() -> datetime:
    """A moment with a clear second on each side of it."""
    time.sleep(1.2)
    t = datetime.now(timezone.utc)
    time.sleep(1.2)
    return t


@pytest.fixture
def tree(tmp_path):
    g = tmp_path / "Drive"
    old = put(g, "Projects/thesis/old.tex")
    moved = put(g, "Projects/thesis/draft.tex")
    put(g, "Projects/oldtree/a.txt")
    put(g, "Projects/oldtree/sub/b.txt")
    start = mark()
    changed = put(g, "Projects/site/src/x.py", "new")
    put(g, "Projects/site/.git/HEAD", "ref")
    put(g, "Projects/site/.DS_Store", "junk")
    put(g, "Projects/web/node_modules/a/index.js", "rebuilt")
    put(g, "Documents/Papers.gddoc", "{}")
    moved.rename(moved.with_name("draft-moved.tex"))
    (g / "Projects/oldtree").rename(g / "Projects/newtree")
    os.symlink(str(old), str(g / "Projects/link-to-old.tex"))
    return g, start, changed


def names(listing) -> list[str]:
    return [f["path"] for f in listing["files"]]


def test_the_listing_is_what_changed(tree):
    g, start, _changed = tree
    listing = scan.changed_since(g, start, key="main")
    assert names(listing) == ["Projects/newtree/a.txt", "Projects/newtree/sub/b.txt",
                              "Projects/site/src/x.py", "Projects/thesis/draft-moved.tex"]
    b = next(f for f in listing["files"] if f["path"] == "Projects/newtree/sub/b.txt")
    assert [m["path"] for m in listing["moved"]] == ["Projects/newtree"]
    assert b["changed_at"] > start.timestamp() and b["mtime"] < start.timestamp() and b["ctime"] < start.timestamp()
    assert listing["links"] == 1 and listing["never"] >= 4
    assert listing["folder"] == "main" and listing["exists"]
    assert scan.unsynced(listing) == 4


def test_a_missing_folder_says_so(tmp_path):
    listing = scan.changed_since(tmp_path / "nope", datetime.now(timezone.utc))
    assert listing["exists"] is False and listing["files"] == []


def test_past_the_cap_files_are_counted_not_named(tree):
    g, start, _changed = tree
    capped = scan.changed_since(g, start, cap=1)
    assert len(capped["files"]) == 3 and capped["moved_unlisted"] == 1 and scan.unsynced(capped) == 4
    assert scan.oldest_hours(capped, time.time()) >= 0


def test_an_uploaded_and_checked_file_leaves_until_it_changes(tree):
    g, start, changed = tree
    st = changed.stat()
    rel = "Projects/site/src/x.py"
    unchecked = {"uploaded": {rel: {"size": st.st_size, "mtime_ns": st.st_mtime_ns, "verified": False}}}
    assert rel in names(scan.changed_since(g, start, uploaded=unchecked))
    checked = {"uploaded": {rel: {"size": st.st_size, "mtime_ns": st.st_mtime_ns, "verified": True}}}
    listing = scan.changed_since(g, start, uploaded=checked)
    assert rel not in names(listing) and listing["uploaded"] == 1
    time.sleep(0.05)
    changed.write_text("changed again, longer")
    assert rel in names(scan.changed_since(g, start, uploaded=checked))


def test_an_earlier_moment_lists_more(tree):
    g, start, _changed = tree
    plain = names(scan.changed_since(g, start))
    margined = names(scan.changed_since(g, start - timedelta(hours=1)))
    assert "Projects/thesis/old.tex" in margined and "Projects/thesis/old.tex" not in plain


def test_a_filter_set_decides_what_is_left_out(tree):
    g, start, _changed = tree
    fs = FilterSet(patterns=GlobRules.from_lines(["*.tex"]), include=("Projects",))
    listing = scan.changed_since(g, start, exclude=fs.excluded)
    assert names(listing) == ["Projects/newtree/a.txt", "Projects/newtree/sub/b.txt", "Projects/site/src/x.py"]


def test_oldest_hours():
    now = 10_000.0
    files = [{"mtime": now - 7200, "ctime": now - 7200, "changed_at": now - 7200}, {"mtime": now, "ctime": now}]
    assert scan.oldest_hours(files, now) == 2.0
    assert scan.oldest_hours([], now) == 0.0
    listing = {"files": [], "moved_unlisted": 3, "moved": [{"path": "x", "at": now - 3600}]}
    assert scan.oldest_hours(listing, now) == 1.0


def test_write_json_is_atomic_and_private(tmp_path):
    p = tmp_path / "state" / "scan" / "main.json"
    scan.write_json(p, {"files": [{"path": "a"}]})
    assert json.loads(p.read_text()) == {"files": [{"path": "a"}]}
    assert stat.S_IMODE(p.stat().st_mode) == 0o600
    assert not p.with_name(p.name + ".tmp").exists()
    assert scan.read_json(tmp_path / "missing.json") == {}


def test_background_lowers_only_its_own_process():
    code = "import json; from billspc import scan; print(json.dumps(scan.background()))"
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, timeout=60)
    got = json.loads(out.stdout)
    assert got["nice"] >= scan.NICE
    if sys.platform == "darwin":
        assert got["io"] == scan.IOPOL_THROTTLE


@mac_only
def test_moved_in_then_given_an_entry_and_renamed_in_place(tmp_path):
    """A folder moved into another folder and then given an entry (its mtime moved too) still brings
    its older files, by its date added. A folder renamed where it is, seen by a listing, then changed
    inside, is remembered by the next listing."""
    g = tmp_path / "Drive"
    put(g, "Archive/inner/sub/old.txt", "older than the move")
    put(g, "Projects/inplace/a.txt", "older than the rename")
    start = mark()
    (g / "Archive/inner").rename(g / "Projects/inner")
    put(g, "Projects/inner/new.txt", "added after the move")
    (g / "Projects/inplace").rename(g / "Projects/inplace2")
    seen1 = scan.changed_since(g, start)
    put(g, "Projects/inplace2/b.txt", "added after a listing saw the rename")
    seen2 = scan.changed_since(g, start, remembered=seen1["moved"])
    how = {m["path"]: m.get("how") for m in seen2["moved"]}
    assert "Projects/inner/sub/old.txt" in names(seen1) and "Projects/inner/sub/old.txt" in names(seen2)
    assert how.get("Projects/inner") == "moved in" and os.stat(g / "Projects/inner").st_mtime > start.timestamp()
    assert "Projects/inplace2/a.txt" in names(seen1) and "Projects/inplace2/a.txt" in names(seen2)
    assert scan.added_at(str(g / "Projects/inner")) > start.timestamp() > scan.added_at(str(g / "Projects/inplace2"))


def test_changed_inside_then_renamed_in_place(tmp_path):
    """A folder changed inside after the moment and then renamed where it is brings its older files,
    by its ctime past its mtime. A folder made after the moment and given a mode is no move."""
    g = tmp_path / "Drive"
    put(g, "A3/edit_then_rename/old.txt", "older than the moment")
    put(g, "A3/rename_then_edit/old.txt", "older than the moment")
    start = mark()
    put(g, "A3/edit_then_rename/new.txt", "added after the moment")
    (g / "A3/edit_then_rename").rename(g / "A3/edit_then_rename2")
    (g / "A3/rename_then_edit").rename(g / "A3/rename_then_edit2")
    put(g, "A3/rename_then_edit2/new.txt", "added after the rename, before any listing")
    put(g, "A3/made_after/new.txt", "a folder made after the moment")
    os.chmod(g / "A3/made_after", 0o700)
    listing = scan.changed_since(g, start, remembered=[])
    st = os.stat(g / "A3/edit_then_rename2")
    assert "A3/edit_then_rename2/old.txt" in names(listing)
    assert st.st_ctime_ns > st.st_mtime_ns and st.st_mtime > start.timestamp()
    assert "A3/made_after/new.txt" in names(listing)
    assert "A3/made_after" not in [m["path"] for m in listing["moved"]]


@mac_only
def test_moved_into_a_folder_renamed_after_it(tmp_path):
    g = tmp_path / "Drive"
    put(g, "A3/moved_then_renamed_inside/old.txt", "older than the moment")
    (g / "C3").mkdir()
    start = mark()
    (g / "A3/moved_then_renamed_inside").rename(g / "C3/moved_then_renamed_inside")
    (g / "C3").rename(g / "C3b")
    assert "C3b/moved_then_renamed_inside/old.txt" in names(scan.changed_since(g, start, remembered=[]))
