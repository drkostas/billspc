"""What a Drive sync never copies, said once and read the same way by Python and by rclone.

A FilterSet holds three kinds of rule:

- `never`: built-in rules with a reason each (a repository's .git, folders a build makes again,
  files caught mid-write, Finder's and Windows' bookkeeping, link files to Google documents)
- `patterns`: ignore patterns in the style of a desktop sync client's ignore list (`*.log`,
  `**/node_modules/`, `+(a|b)`), read by GlobRules
- `include`: the folders to keep (selective sync). Empty keeps everything

`FilterSet.excluded()` answers for one path in Python (for a scan of changed files), and
`FilterSet.lines()` writes the same rules as rclone filter lines (for `--filter-from` or bisync's
`--filters-file`). The tests run real rclone over a planted tree with the lines and hold its choice
to the Python matcher, file for file.

Everything is case-blind, as macOS's default file system is. Run rclone with `--ignore-case`.
"""
from __future__ import annotations

import hashlib
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable


@dataclass(frozen=True)
class Rule:
    """One never-copied entry. `kind` says how `value` is matched against a path relative to the
    synced folder's top:

    - "dir": a folder of that name at any depth
    - "file": a file of that name
    - "name": a file or a folder of that name
    - "prefix" or "suffix": of a file's name
    - "path": a path from the top (and everything under it)
    - "pair": two folders in a row ("a/b")

    `folder` limits a rule to one synced folder, by the key the caller gives it."""
    kind: str
    value: str
    why: str
    folder: str | None = None


_GIT = "a repository's history, which is backed up as a repository and never file by file"
_REBUILT = "made again by a build or a test run"
_TORN = "a file caught while it is being written"
_JUNK = "Finder's or Windows' own bookkeeping"
_LINK = "a desktop client's link to a Google document, which Drive holds itself"

#: the built-in never-copied list. dist/ and build/ are not on it, because in a paper or a site
#: they can be the work itself
DEFAULT_NEVER: tuple[Rule, ...] = (
    Rule("dir", ".git", _GIT),
    Rule("file", ".git", "a linked worktree's pointer to its repository's history"),
    *(Rule("dir", d, _REBUILT) for d in ("node_modules", "__pycache__", ".venv", "venv", ".next",
                                         ".pytest_cache", ".mypy_cache", ".ruff_cache", ".tox",
                                         ".gradle", ".turbo", ".expo", ".parcel-cache")),
    *(Rule("suffix", s, _REBUILT) for s in (".pyc", ".pyo")),
    *(Rule("suffix", s, _TORN) for s in (".partial", ".part", ".crdownload", "-journal", "-wal",
                                         "-shm")),
    *(Rule("name", n, _JUNK) for n in (".DS_Store", "Icon\r", "Thumbs.db", "desktop.ini")),
    Rule("prefix", "._", _JUNK),
    *(Rule("suffix", s, _LINK) for s in (".gddoc", ".gdsheet", ".gdslides", ".gddraw", ".gdform",
                                         ".gdmap", ".gdsite", ".gdjam", ".gdoc", ".gsheet",
                                         ".gslides", ".gdraw", ".gform", ".gmap", ".gsite",
                                         ".gjam")),
)


def never(rel: str, is_dir: bool, rules: Iterable[Rule] = DEFAULT_NEVER, folder: str | None = None) -> Rule | None:
    """The rule that keeps this path out of every copy, or None.

    `rel` is the path from the folder's top with '/' between its parts. `is_dir` says whether the
    last part is a folder. A rule with a `folder` applies only when `folder` is that key."""
    rules = tuple(rules)
    parts = [p for p in rel.split("/") if p]
    if not parts:
        return None
    low = [p.casefold() for p in parts]
    dirs = low if is_dir else low[:-1]
    name = low[-1]
    path = "/".join(low)
    for r in rules:
        if r.folder is not None and r.folder != folder:
            continue
        v = r.value.casefold()
        if r.kind == "dir" and v in dirs:
            return r
        if r.kind == "pair":
            a, b = v.split("/", 1)
            if any(dirs[i] == a and dirs[i + 1] == b for i in range(len(dirs) - 1)):
                return r
        if r.kind == "path" and (path == v or path.startswith(v + "/")):
            return r
        if is_dir:
            continue
        if r.kind in ("file", "name") and name == v:
            return r
        if r.kind == "prefix" and name.startswith(v):
            return r
        if r.kind == "suffix" and name.endswith(v):
            return r
    # a folder is kept out by its own name too, so a walk never enters it
    for r in rules:
        if r.folder is not None and r.folder != folder:
            continue
        if is_dir and r.kind == "name" and name == r.value.casefold():
            return r
    return None


def _glob(text: str) -> str:
    """A literal name as an rclone glob: its special characters escaped, and a carriage return
    (Icon\\r, Finder's custom-icon file) as U+240D. rclone's local backend lists that file as
    "Icon␍" and matches filters against that spelling."""
    out = []
    for ch in text:
        if ch == "\r":
            out.append("␍")
        elif ch in "*?[]{}\\":
            out.append("\\" + ch)
        else:
            out.append(ch)
    return "".join(out)


def rule_lines(rules: Iterable[Rule] = DEFAULT_NEVER, folder: str | None = None) -> list[str]:
    """The never-copied rules as rclone filter lines for a copy rooted at the folder's top."""
    lines = []
    for r in rules:
        if r.folder is not None and r.folder != folder:
            continue
        g = _glob(r.value)
        if r.kind in ("dir", "pair"):
            lines.append(f"- {g}/**")
        elif r.kind == "path":
            lines += [f"- /{g}", f"- /{g}/**"]
        elif r.kind == "file":
            lines.append(f"- {g}")
        elif r.kind == "name":
            lines += [f"- {g}", f"- {g}/**"]
        elif r.kind == "prefix":
            lines.append(f"- {g}*")
        elif r.kind == "suffix":
            lines.append(f"- *{g}")
    return lines


# ------------------------------------------------------------------------------------ ignore patterns

#: characters escaped in a literal, for Python's re and Go's RE2 alike
_META = set("\\.+*?()|[]{}^$")


def _lit(c: str) -> str:
    return "\\" + c if c in _META else c


def glob_regex(glob: str) -> str:
    """One ignore pattern as a regular expression that Python's re and rclone's RE2 both read.

    It is read loosely on purpose: `*` crosses '/' as well, `+(a|b)`, `@(a|b)` and a bare `(a|b)`
    are alternatives, `**/` is any number of folders, and anything else is literal. A looser
    reading matches more paths, and a path a pattern matches is one that stays local."""
    out, i = [], 0
    while i < len(glob):
        c = glob[i]
        if glob.startswith("**/", i) and (i == 0 or glob[i - 1] == "/"):
            out.append("(?:.*/)?")
            i += 3
            continue
        if glob.startswith("/**", i) and i + 3 == len(glob):
            out.append("(?:/.*)?")
            i += 3
            continue
        if c in "+@*?!" and glob[i + 1:i + 2] == "(" and ")" in glob[i:]:
            j = glob.index(")", i)
            out.append("(?:" + "|".join(glob_regex(a) for a in glob[i + 2:j].split("|")) + ")"
                       + ("+" if c in "+*" else ""))
            i = j + 1
            continue
        if c == "(" and ")" in glob[i:]:
            j = glob.index(")", i)
            out.append("(?:" + "|".join(glob_regex(a) for a in glob[i + 1:j].split("|")) + ")")
            i = j + 1
            continue
        if c == "[" and "]" in glob[i + 1:]:
            j = glob.index("]", i + 1)
            out.append("[" + glob[i + 1:j].replace("\\", "\\\\") + "]")
            i = j + 1
            continue
        out.append(".*" if c == "*" else "." if c == "?" else _lit(c))
        i += 1
    return "".join(out)


@dataclass(frozen=True)
class GlobRules:
    """A list of ignore patterns, one per line, comments (#) and blank lines left out. A trailing
    '/' is dropped, so `logs/` matches a file named logs too (the looser reading)."""
    rules: tuple[tuple[str, str], ...] = ()

    @classmethod
    def from_lines(cls, lines: Iterable[str]) -> "GlobRules":
        out = []
        for line in lines:
            rule = line.strip()
            if not rule or rule.startswith("#"):
                continue
            out.append((rule, glob_regex(rule.rstrip("/"))))
        return cls(tuple(out))

    @classmethod
    def from_file(cls, path: Path) -> "GlobRules":
        return cls.from_lines(Path(path).read_text().splitlines())

    def __len__(self) -> int:
        return len(self.rules)

    def _compiled(self):
        cache = self.__dict__.get("_rx")
        if cache is None:
            cache = [(rule, re.compile(rx, re.IGNORECASE)) for rule, rx in self.rules]
            object.__setattr__(self, "_rx", cache)
        return cache

    def match(self, rel: str) -> str | None:
        """The first pattern that matches this path, or None. A pattern is tried against every run of
        the path's parts, so `logs` matches a folder named logs anywhere, `*.log` any file ending
        .log, and `*/build/data` that folder under any parent. Case-blind."""
        parts = [p for p in rel.split("/") if p]
        runs = ["/".join(parts[i:j]) for i in range(len(parts)) for j in range(i + 1, len(parts) + 1)]
        for rule, rx in self._compiled():
            if any(rx.fullmatch(r) for r in runs):
                return rule
        return None

    def lines(self) -> list[str]:
        """The patterns as rclone filter lines. Each pattern becomes a regular expression block
        ({{ }}) twice: once for a path that ends at a match, once for everything under a match. rclone
        matches an unanchored pattern from any '/' to the end of the path, so the two lines cover
        every run of parts that match() tries."""
        out = []
        for _rule, rx in self.rules:
            out += [f"- {{{{{rx}}}}}", f"- {{{{{rx}}}}}/**"]
        return out


# ------------------------------------------------------------------------------------ the whole set

@dataclass(frozen=True)
class FilterSet:
    """Everything that decides what one synced folder copies. See the module's top."""
    never: tuple[Rule, ...] = DEFAULT_NEVER
    patterns: GlobRules = field(default_factory=GlobRules)
    include: tuple[str, ...] = ()
    folder: str | None = None

    def _includes(self) -> list[str]:
        return [p.strip("/").casefold() for p in self.include if p.strip("/")]

    def excluded(self, rel: str, is_dir: bool) -> str | None:
        """Why this path is not copied, or None when it is. A folder that holds an included folder is
        not excluded (a walk enters it), but a file directly inside it is."""
        r = never(rel, is_dir, self.never, self.folder)
        if r is not None:
            return f"{r.value}: {r.why}"
        p = self.patterns.match(rel)
        if p is not None:
            return f"{p}: an ignore pattern"
        inc = self._includes()
        if inc:
            low = "/".join(x for x in rel.casefold().split("/") if x)
            if any(low == i or low.startswith(i + "/") for i in inc):
                return None
            if is_dir and any(i.startswith(low + "/") for i in inc):
                return None
            return "outside the included folders"
        return None

    def lines(self) -> list[str]:
        """The set as rclone filter lines, first match wins: the never-copied rules, the ignore
        patterns, then each included folder and `- **` when there are any."""
        out = rule_lines(self.never, self.folder) + self.patterns.lines()
        inc = [p.strip("/") for p in self.include if p.strip("/")]
        if inc:
            out += [f"+ /{_glob(p)}/**" for p in inc] + ["- **"]
        return out


def write_filter_file(path: Path, lines: Iterable[str], header: str | None = None) -> str:
    """Write rclone filter lines to `path` atomically (0600) and return the MD5 of what was written.

    bisync remembers the MD5 of its filters file and asks for a --resync when it changes, so the
    caller can compare it with the last one before running."""
    text = "".join(f"# {h}\n" for h in (header or "").splitlines()) + "".join(f"{l}\n" for l in lines)
    data = text.encode("utf-8")
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as out:
        out.write(data)
    os.replace(tmp, path)
    return hashlib.md5(data).hexdigest()
