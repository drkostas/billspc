"""What never reaches the remote, said once and read the same way by the Python matcher and by rclone.

A planted tree is listed by real rclone with the filter lines and by the matcher, and the two must
agree file for file: the built-in list (with the Finder icon file, whose name ends in a carriage
return), ignore patterns written as regular expression blocks, and included folders.
"""
from __future__ import annotations

import hashlib
import json
import stat

import pytest

from conftest import needs_rclone, raw
from billspc import filters as f
from billspc.filters import FilterSet, GlobRules, Rule

EXTRA = (Rule("path", "Projects/app/live.db", "a live database, written while it runs", folder="main"),
         Rule("path", "backup-target", "the backup's own folder", folder="main"),
         Rule("pair", ".claude/worktrees", "scratch worktrees"))
RULES = f.DEFAULT_NEVER + EXTRA

OUT = {  # path, is_dir -> the value of the rule that keeps it out
    ("Projects/site/.git/HEAD", False): ".git",
    ("Projects/site-wt/.git", False): ".git",
    ("Projects/site/.claude/worktrees/agent-1/x.py", False): ".claude/worktrees",
    ("Projects/site/node_modules/react/index.js", False): "node_modules",
    ("Projects/x/__pycache__/m.cpython-314.pyc", False): "__pycache__",
    ("Projects/x/m.pyc", False): ".pyc",
    ("Downloads/movie.mp4.crdownload", False): ".crdownload",
    ("Projects/app/state.db-wal", False): "-wal",
    ("Projects/app/state.db-journal", False): "-journal",
    ("Projects/app/live.db", False): "Projects/app/live.db",
    ("Documents/.DS_Store", False): ".DS_Store",
    ("Documents/._report.pdf", False): "._",
    ("Documents/Icon\r", False): "Icon\r",
    ("Papers.gddoc", False): ".gddoc",
    ("Budget.gsheet", False): ".gsheet",
    ("backup-target/repo/config", False): "backup-target",
    ("Projects/x/.venv", True): ".venv",
    ("Projects/x/node_modules", True): "node_modules",
}
KEPT = [("Projects/site/src/main.py", False), ("Projects/site/dist/index.html", False),
        ("Projects/paper/build/main.pdf", False), ("Projects/app/run.py", False),
        ("Documents/Icons/logo.png", False), ("backups/vault-20260101-042001.tar.gz.enc", False),
        ("Projects/app/state.db", False), ("Projects/gitignore-notes.md", False),
        ("Projects/backup-target-notes.md", False), ("Projects/x", True)]


@pytest.mark.parametrize("path,is_dir", list(OUT))
def test_never_copied(path, is_dir):
    r = f.never(path, is_dir, RULES, "main")
    assert r is not None and r.value == OUT[(path, is_dir)]


@pytest.mark.parametrize("path,is_dir", KEPT)
def test_kept(path, is_dir):
    assert f.never(path, is_dir, RULES, "main") is None


def test_case_blind_and_rules_of_one_folder():
    assert f.never("Documents/.ds_store", False) is not None
    assert f.never("a/NODE_MODULES/b.js", False) is not None
    assert f.never("backup-target/x", False, RULES, "other") is None
    assert f.never("Projects/app/live.db", False, RULES, "other") is None
    assert all(r.why.strip() for r in RULES)
    assert any(l.startswith("- /backup-target") for l in f.rule_lines(RULES, "main"))
    assert not any("backup-target" in l for l in f.rule_lines(RULES, "other"))


# ---------------------------------------------------------------- ignore patterns

PATTERNS = """# a comment, then rules in the shapes a desktop client keeps
__pycache__/
*.py[cod]
*.log
**/node_modules/
**/Projects/**/data
*Scan0[69]_(Left|Right)*.+(jpg|png)
stamp-h?
**/*.pth
**/.DS_Store
Cache/
build/
"""


def test_glob_rules_match():
    g = GlobRules.from_lines(PATTERNS.splitlines())
    assert len(g) == 11
    for path, want in (("Projects/a/NOTES.md", None), ("Projects/a/.env", None), ("Projects/a/x.py", None),
                       ("Projects/a/.tool/console-1.log", "*.log"),
                       ("node_modules/a.js", "**/node_modules/"), ("Projects/x/node_modules/a.js", "**/node_modules/"),
                       ("Projects/z/data/a.csv", "**/Projects/**/data"), ("Projects/q/course/data/x", "**/Projects/**/data"),
                       ("Projects/m/Scan06_Left_1.png", "*Scan0[69]_(Left|Right)*.+(jpg|png)"),
                       ("Projects/m/Scan06_Left_1.txt", None), ("Projects/v/stamp-h1", "stamp-h?"),
                       ("Projects/w/x.pth", "**/*.pth"), ("A/B/.DS_STORE", "**/.DS_Store"), ("Projects/u/Cache/a", "Cache/"),
                       ("Projects/m/x.pyc", "*.py[cod]")):
        assert g.match(path) == want, path
    assert f.glob_regex("+(a|b)") == "(?:a|b)+" and f.glob_regex("*") == ".*"


def test_filter_set_excluded_and_includes():
    fs = FilterSet(never=RULES, patterns=GlobRules.from_lines(["*.log"]), include=("Projects/site", "Documents"),
                   folder="main")
    assert fs.excluded("Projects/site/src/main.py", False) is None
    assert fs.excluded("Projects/site", True) is None
    assert fs.excluded("Projects", True) is None, "a folder that holds an included one is entered"
    assert fs.excluded("Projects/notes.md", False) == "outside the included folders"
    assert fs.excluded("Projects/other", True) == "outside the included folders"
    assert fs.excluded("documents/a.txt", False) is None
    assert fs.excluded("Documents/a.log", False).startswith("*.log")
    assert fs.excluded("Documents/.DS_Store", False).startswith(".DS_Store")
    assert FilterSet().excluded("anything/at/all.txt", False) is None


def test_write_filter_file(tmp_path):
    lines = FilterSet(include=("A",)).lines()
    md5 = f.write_filter_file(tmp_path / "filters.txt", lines, header="made by a test")
    data = (tmp_path / "filters.txt").read_bytes()
    assert md5 == hashlib.md5(data).hexdigest()
    assert data.decode().startswith("# made by a test\n") and data.decode().endswith("+ /A/**\n- **\n")
    assert stat.S_IMODE((tmp_path / "filters.txt").stat().st_mode) == 0o600


# ---------------------------------------------------------------- rclone reads it the same way

def plant(tree, files):
    for rel in files:
        p = tree / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text("x")


def rclone_keeps(tmp_path, tree, lines) -> list[str]:
    rules = tmp_path / "filters.txt"
    f.write_filter_file(rules, lines)
    empty = tmp_path / "empty.conf"
    empty.write_text("")
    r = raw("lsjson", "-R", "--files-only", str(tree), "--filter-from", str(rules), "--ignore-case",
            "--config", str(empty))
    assert r.returncode == 0, r.stderr
    return sorted(o["Path"].replace("␍", "\r") for o in json.loads(r.stdout or "[]"))


def matcher_keeps(tree, excluded) -> list[str]:
    out = []
    for p in tree.rglob("*"):
        if not p.is_file():
            continue
        rel = p.relative_to(tree)
        if excluded(str(rel), False):
            continue
        if any(excluded("/".join(rel.parts[:i]), True) for i in range(1, len(rel.parts))):
            continue
        out.append(str(rel))
    return sorted(out)


@needs_rclone
def test_rclone_agrees_with_the_built_in_list(tmp_path):
    tree = tmp_path / "Drive"
    plant(tree, [p for (p, d) in OUT if not d] + [p for p, d in KEPT if not d]
          + ["Projects/x/.venv/bin/python", "Projects/x/node_modules/a/i.js"])
    fs = FilterSet(never=RULES, folder="main")
    by_rclone = rclone_keeps(tmp_path, tree, fs.lines())
    assert by_rclone and by_rclone == matcher_keeps(tree, fs.excluded)
    assert "Documents/Icon\r" not in by_rclone and "Documents/Icons/logo.png" in by_rclone


@needs_rclone
def test_rclone_agrees_with_patterns_and_includes(tmp_path):
    tree = tmp_path / "Drive"
    plant(tree, ["Projects/a/NOTES.md", "Projects/a/.tool/console-1.log", "Projects/a/x.py", "Projects/a/x.pyc",
                 "node_modules/a.js", "Projects/x/node_modules/a.js", "Projects/z/data/a.csv",
                 "Projects/q/course/data/x", "Projects/m/Scan06_Left_1.png", "Projects/m/Scan06_Left_1.txt",
                 "Projects/m/scan09_right_2.JPG", "Projects/v/stamp-h1", "Projects/v/stamp-h12",
                 "Projects/w/x.pth", "A/B/.DS_STORE", "Projects/u/Cache/a", "Projects/u/cache/b",
                 "Projects/u/Caches/c", "Projects/p/build/out.o", "Projects/p/builds/keep.txt",
                 "Projects/LOGS.txt", "Documents/report.log", "Documents/report.txt", "Music/song.mp3",
                 "Projects/site/data.json", "Projects/site/index.html"])
    patterns = GlobRules.from_lines(PATTERNS.splitlines())
    for fs in (FilterSet(patterns=patterns),
               FilterSet(patterns=patterns, include=("Projects/m", "Documents", "Projects/site"))):
        by_rclone = rclone_keeps(tmp_path, tree, fs.lines())
        by_matcher = matcher_keeps(tree, fs.excluded)
        assert by_rclone and by_rclone == by_matcher, sorted(set(by_rclone) ^ set(by_matcher))
    assert "Music/song.mp3" not in by_rclone and "Projects/m/Scan06_Left_1.txt" in by_rclone
