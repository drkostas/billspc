"""Read an Insync setup, to move its rules to rclone and stop using Insync.

Insync keeps its settings in SQLite files under its data folder (on macOS
~/Library/Application Support/Insync): settings.db, data/<account>.db and live/live-<account>.db.
Each account's ignore rules are in that account's database, in the table sync_prefs under the key
IGNORE_RULES. The same files hold Insync's sign-ins, so this module reads them carefully.

- `show()` prints each database's tables and columns and never a row. Read it first, to see what a
  database holds before reading any value.
- Every row that is read goes through `Reader.rows()`, which runs one SELECT and nothing else, reads
  only the (table, column) pairs it is given (SQLite's own authorizer enforces it as each statement
  is prepared, so an alias cannot rename a column past it), and returns any value shaped like a token
  or a key as "[refused: <what it looked like>]".
- `ignore_rules()` returns one account's ignore rules, each line through the same guard.

Databases are opened read only (mode=ro with query_only). SQLite then reads an unfolded WAL (Insync
quit while its files were open leaves one) and changes neither the database nor the WAL. Opening
with immutable=1 would write nothing at all, but it would also miss tables that live only in the WAL.

    billspc insync schema [file.db ...]
    billspc insync rules [file.db]
"""
from __future__ import annotations

import json
import math
import re
import sqlite3
import sys
from collections import Counter
from pathlib import Path
from urllib.parse import quote

#: where Insync keeps its databases on macOS
DATA_DIR = Path.home() / "Library" / "Application Support" / "Insync"

#: what a secret looks like, each with its words
SHAPES = (
    (re.compile(r"\bya29\.[\w-]{10,}"), "a Google access token"),
    (re.compile(r"(^|[^\w/])1//[\w-]{20,}"), "a Google refresh token"),
    (re.compile(r"\beyJ[\w-]{8,}\.[\w-]{8,}\.[\w-]*"), "a JSON web token"),
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"), "a private key"),
    (re.compile(r"\b(AKIA|ASIA)[A-Z0-9]{16}\b"), "an AWS key"),
    (re.compile(r"\b(gh[pousr]_[A-Za-z0-9]{20,}|github_pat_\w{20,})"), "a GitHub token"),
    (re.compile(r"\b(sk-[\w-]{16,}|xox[abprs]-[\w-]{10,})"), "an API key"),
    (re.compile(r"\bEw[ABC][\w+/=-]{40,}"), "a Microsoft token"),
    (re.compile(r"\bM\.[CR]\d{3}_[\w.!*$-]{20,}"), "a Microsoft refresh token"),
    # anywhere in the value: a URL or `refresh=` can carry one
    (re.compile(r"[0-9a-f]{32,}", re.I), "a long hexadecimal secret"),
)
#: a run long and random enough to be a key, whatever it calls itself
RUN = re.compile(r"[A-Za-z0-9+=_\-.~]{24,}")
#: the (table -> columns) a Reader may read by default: the account database's preferences
RULES_COLUMNS: dict[str, frozenset[str]] = {"sync_prefs": frozenset({"key", "encoded_value"})}


class Refused(ValueError):
    """A query the reader does not run, or rules it does not return."""


def _entropy(s: str) -> float:
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in Counter(s).values()) if n else 0.0


def _mixes(run: str) -> int:
    """How often a letter and a digit stand next to each other: often in a random run, rarely in a
    name, where digits come in blocks (a date, a version)."""
    return sum(1 for a, b in zip(run, run[1:]) if (a.isalpha() and b.isdigit()) or (a.isdigit() and b.isalpha()))


def secret_shaped(value) -> str | None:
    """What a value looks like when it looks like a secret, or None.

    Names, paths and ignore patterns are not. A run of 24 characters or more counts as random in two
    ways: upper and lower case letters with four digits and high entropy, or two digits at least,
    standing beside letters three times or more, with entropy of 3.6 bits a character (which catches
    a lowercase base32 run). Raw bytes are always refused, since they may hold a sealed token."""
    if isinstance(value, (bytes, bytearray, memoryview)):
        return "raw bytes, which may hold a sealed token" if len(value) else None
    if not isinstance(value, str):
        return None
    v = value.strip()
    for rx, what in SHAPES:
        if rx.search(v):
            return what
    for run in RUN.findall(v):
        digits = sum(ch.isdigit() for ch in run)
        if (any(ch.islower() for ch in run) and any(ch.isupper() for ch in run)
                and digits >= 4 and _entropy(run) >= 4.0):
            return "a long random string"
        if digits >= 2 and _mixes(run) >= 3 and _entropy(run) >= 3.6:
            return "a long random string"
    low = v.lower()
    if v.startswith("{") and any(w in low for w in ("token", "secret", "password", "refresh")):
        return "a JSON document that names a token or a secret"
    return None


def _guard(value):
    what = secret_shaped(value)
    return f"[refused: {what}]" if what else value


class Reader:
    """One SQLite database, opened read only (mode=ro, query_only). The only door to its rows, and
    those only from the columns `allow` names ({table: {column}}, RULES_COLUMNS by default)."""

    def __init__(self, path: Path, allow: dict[str, frozenset[str] | set[str]] | None = None):
        self.path = Path(path)
        self.db = sqlite3.connect(f"file:{quote(str(self.path))}?mode=ro", uri=True)
        self.db.execute("PRAGMA query_only = ON")
        self.refused = 0
        self.allow = {t: frozenset(c) for t, c in (RULES_COLUMNS if allow is None else allow).items()}
        self.denied: list[str] = []

    def _authorize(self, action, arg1, arg2, _db, _source):
        """SQLite's authorizer while a statement is prepared: a SELECT of allowed columns and the
        functions it calls, nothing else (no write, no PRAGMA, no other table's column)."""
        if action == sqlite3.SQLITE_READ:
            if arg2 in self.allow.get(arg1, ()):
                return sqlite3.SQLITE_OK
            self.denied.append(f"{arg1}.{arg2}")
            return sqlite3.SQLITE_DENY
        if action in (sqlite3.SQLITE_SELECT, sqlite3.SQLITE_FUNCTION):
            return sqlite3.SQLITE_OK
        self.denied.append(f"action {action}")
        return sqlite3.SQLITE_DENY

    def close(self) -> None:
        self.db.close()

    def __enter__(self) -> "Reader":
        return self

    def __exit__(self, *_exc) -> None:
        self.close()

    def schema(self) -> list[tuple[str, list[str]]]:
        """[(table, [column, ...])], names only, each through the guard as well."""
        out = []
        names = [r[0] for r in self.db.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name")]
        for t in names:
            cols = [r[1] for r in self.db.execute(f"PRAGMA table_info(\"{t.replace(chr(34), chr(34) * 2)}\")")]
            out.append((_guard(t), [_guard(c) for c in cols]))
        return out

    def _select(self, text: str, params: tuple) -> list[tuple]:
        self.denied = []
        self.db.set_authorizer(self._authorize)
        try:
            return list(self.db.execute(text, params))
        except sqlite3.DatabaseError:
            if self.denied:
                raise Refused(f"the reader reads only its allowed columns, not {', '.join(self.denied[:4])}") from None
            raise
        finally:
            self.db.set_authorizer(None)

    def rows(self, sql: str, params: tuple = ()) -> list[tuple]:
        """The rows of one SELECT, every value through the guard: a secret-shaped one comes back as
        "[refused: ...]" and is counted in `refused`."""
        text = sql.strip().rstrip(";")
        if not re.match(r"(?is)^select\b", text) or ";" in text:
            raise Refused("the reader runs one SELECT and nothing else")
        out = []
        for row in self._select(text, params):
            vals = []
            for v in row:
                g = _guard(v)
                if g is not v:
                    self.refused += 1
                vals.append(g)
            out.append(tuple(vals))
        return out


def ignore_rules(path: Path) -> list[str]:
    """One account's ignore rules, a line each, as Insync kept them (sync_prefs IGNORE_RULES).

    The value is JSON in bytes holding one string of lines, so rows() would refuse it whole as raw
    bytes. It is decoded here, and each line then goes through the guard. The rules are refused whole
    when any line looks like a secret, and the message never prints the line."""
    with Reader(path) as reader:
        rows = reader._select("SELECT encoded_value FROM sync_prefs WHERE key = 'IGNORE_RULES'", ())
    if not rows:
        return []
    raw = rows[0][0]
    text = json.loads(raw.decode("utf-8") if isinstance(raw, (bytes, bytearray)) else raw)
    if not isinstance(text, str):
        raise Refused("IGNORE_RULES is not one string of lines")
    lines = text.splitlines()
    bad = [secret_shaped(line) for line in lines if secret_shaped(line)]
    if bad:
        raise Refused(f"{len(bad)} line(s) of the ignore rules look like secrets ({bad[0]}); nothing read")
    return lines


def databases(root: Path = DATA_DIR) -> list[Path]:
    """Insync's SQLite files: those at the top (settings.db, logs.db) and each account's in data/
    and live/."""
    root = Path(root)
    if not root.is_dir():
        return []
    return sorted(p for p in [*root.glob("*.db"), *root.glob("data/*.db"), *root.glob("live/*.db")]
                  if p.is_file())


def account_databases(root: Path = DATA_DIR) -> list[Path]:
    """The account databases, the ones that may hold ignore rules (data/*.db)."""
    return [p for p in databases(root) if p.parent.name == "data"]


def _stamp(path: Path) -> tuple:
    out = []
    for p in (path, path.with_name(path.name + "-wal")):
        try:
            st = p.stat()
            out.append((p.name, st.st_size, st.st_mtime_ns))
        except OSError:
            out.append((p.name, None, None))
    return tuple(out)


def show(paths: list[Path], root: Path = DATA_DIR, out=None) -> int:
    """Print each database's tables and columns, never a row (to `out`, standard output by default).
    Returns how many files changed size or time during the read (0 is the expected answer)."""
    out = out or sys.stdout
    moved = 0
    for path in paths:
        path = Path(path)
        try:
            rel = path.relative_to(root)
        except ValueError:
            rel = path
        before = _stamp(path)
        try:
            with Reader(path) as reader:
                tables = reader.schema()
        except sqlite3.Error as e:
            print(f"{rel}: not readable ({type(e).__name__}: {str(e)[:100]})", file=out)
            continue
        if _stamp(path) != before:
            moved += 1
            print(f"{rel}: its size or time changed during the read", file=out)
        wal = path.with_name(path.name + "-wal")
        print(f"{rel}: {len(tables)} tables" + (f", WAL {wal.stat().st_size} bytes read" if wal.exists() else ""),
              file=out)
        for t, cols in tables:
            print(f"  {t}: {', '.join(cols)}", file=out)
    return moved
