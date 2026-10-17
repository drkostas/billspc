"""Insync's databases read without a row reaching anyone, and no secret ever.

A database made the way Insync's are left when it quits (a writer killed while its WAL held the
newest commits) stands in for Insync's, with a rules table and an accounts table holding planted
tokens of each shape the reader knows, made at run time so no literal here looks like a key.
"""
from __future__ import annotations

import hashlib
import io
import json
import secrets
import sqlite3
import string
import subprocess
import sys
from pathlib import Path

import pytest

from billspc import insync as ir
from billspc._env import clean_env
from billspc.cli import main


def rand(n: int, alphabet: str = string.ascii_letters + string.digits + "-_") -> str:
    return "".join(secrets.choice(alphabet) for _ in range(n))


PLANTED = {
    "a Google access token": "ya" + "29." + rand(60),
    "a Google refresh token": "1/" + "/" + rand(70),
    "a JSON web token": "ey" + "J" + rand(20) + "." + rand(30) + "." + rand(20),
    "a Microsoft token": "Ew" + "B" + rand(80, string.ascii_letters + string.digits + "+/"),
    "a long random string": rand(20, string.ascii_uppercase) + rand(20, string.ascii_lowercase) + rand(8, string.digits),
    "a long hexadecimal secret": secrets.token_hex(32),
    "a token inside an address": "https://example.org/dl?access" + "_token=" + secrets.token_hex(32),
    "a refresh value of hex": "refresh=" + secrets.token_hex(24),
    "a lowercase base32 run": rand(48, string.ascii_lowercase + "234567"),
}
PLAIN = ["node_modules", "/home/someone/Drive/Projects/site/src", "*.pyc", "Jane-Doe-Resume-CoverLetter-Final.pdf",
         "0d0e0f10-1111-4222-8333-944455556601", "someone@example.org", "Projects/3.Old Projects/**",
         "vault-20260114-042001.tar.gz.enc", "Data-Collection-2024-v2-final", "IMG_20260114_120102_HDR.jpg",
         "2026-01-14T12:49:03.123456+00:00", "example-drivesync-260115-project", 167, None, 3.5]


@pytest.mark.parametrize("what", list(PLANTED))
def test_planted_secret_is_caught(what):
    assert ir.secret_shaped(PLANTED[what]) is not None


@pytest.mark.parametrize("value", PLAIN)
def test_plain_value_is_not(value):
    assert ir.secret_shaped(value) is None


def test_bytes_and_hex_inside_a_value():
    assert ir.secret_shaped(b"\x00\x01sealed") is not None
    # only the reason proves the hex rule reads inside a value
    assert ir.secret_shaped("md5 " + secrets.token_hex(16)) == "a long hexadecimal secret"


WRITER = """
import sqlite3, os, signal, sys
db = sqlite3.connect(sys.argv[1]); db.execute("PRAGMA journal_mode=WAL"); db.execute("PRAGMA wal_autocheckpoint=0")
db.execute("CREATE TABLE ignore_rules(id INTEGER PRIMARY KEY, pattern TEXT, kind TEXT)")
db.executemany("INSERT INTO ignore_rules(pattern, kind) VALUES(?, ?)", [("node_modules", "name"), ("*.pyc", "glob"),
                                                                         (sys.argv[4], "glob")])
db.commit()
db.execute("CREATE TABLE accounts(email TEXT, access_token TEXT, refresh_token TEXT, blob BLOB)")
db.execute("INSERT INTO accounts VALUES(?, ?, ?, ?)", ("someone@example.org", sys.argv[2], sys.argv[3], b"\\x00sealed"))
db.commit()
os.kill(os.getpid(), signal.SIGKILL)
"""


@pytest.fixture
def left(tmp_path):
    """A data folder with an account database whose writer was killed with its WAL unfolded."""
    root = tmp_path / "Insync"
    (root / "data").mkdir(parents=True)
    db = root / "data" / "gd-1234.db"
    subprocess.run([sys.executable, "-c", WRITER, str(db), PLANTED["a Google access token"],
                    PLANTED["a Google refresh token"], PLANTED["a token inside an address"]],
                   env=clean_env("/usr/bin:/bin"), capture_output=True)
    (root / "settings.db").write_bytes(b"")
    assert (root / "data" / "gd-1234.db-wal").exists()
    return root, db


def digest(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest() if p.exists() else "-"


def test_schema_prints_names_and_never_a_row(left):
    root, db = left
    before = {p.name: digest(p) for p in (db, db.with_name(db.name + "-wal"))}
    buf = io.StringIO()
    moved = ir.show(ir.databases(root), root=root, out=buf)
    text = buf.getvalue()
    assert "ignore_rules: id, pattern, kind" in text
    assert "accounts: email, access_token, refresh_token, blob" in text
    assert not any(v in text for v in PLANTED.values()) and "node_modules" not in text and "example.org" not in text
    after = {p.name: digest(p) for p in (db, db.with_name(db.name + "-wal"))}
    assert moved == 0 and before == after
    assert sorted(str(p.relative_to(root)) for p in ir.databases(root)) == ["data/gd-1234.db", "settings.db"]
    assert ir.account_databases(root) == [db]


def test_default_reader_reads_only_the_preferences(left):
    _root, db = left
    assert ir.RULES_COLUMNS == {"sync_prefs": frozenset({"key", "encoded_value"})}
    with ir.Reader(db) as nothing:
        with pytest.raises(ir.Refused):
            nothing.rows("SELECT pattern FROM ignore_rules")


def test_rows_refuse_every_secret(left):
    _root, db = left
    with ir.Reader(db, allow={"ignore_rules": {"id", "pattern", "kind"},
                              "accounts": {"email", "access_token", "refresh_token", "blob"}}) as r:
        rules = r.rows("SELECT pattern, kind FROM ignore_rules ORDER BY id")
        assert rules[:2] == [("node_modules", "name"), ("*.pyc", "glob")]
        assert str(rules[2][0]).startswith("[refused: ") and r.refused == 1
        acct = r.rows("SELECT email, access_token, refresh_token, blob FROM accounts")[0]
        assert acct[0] == "someone@example.org"
        assert all(str(v).startswith("[refused: ") for v in acct[1:]) and r.refused == 4


@pytest.mark.parametrize("bad", ["SELECT email, access_token FROM accounts", "SELECT access_token AS pattern FROM accounts",
                                 "SELECT pattern FROM ignore_rules UNION SELECT refresh_token FROM accounts",
                                 "SELECT (SELECT access_token FROM accounts) FROM ignore_rules",
                                 "UPDATE ignore_rules SET pattern = 'x'", "DELETE FROM accounts",
                                 "SELECT 1; DELETE FROM accounts", "PRAGMA writable_schema = ON"])
def test_only_allowed_columns_and_only_select(left, bad):
    _root, db = left
    before = digest(db)
    with ir.Reader(db, allow={"ignore_rules": {"id", "pattern", "kind"}}) as r:
        with pytest.raises(ir.Refused):
            r.rows(bad)
        with pytest.raises(Exception):
            r.db.execute("DELETE FROM accounts")
    assert digest(db) == before


def prefs_db(path: Path, rules_text: str) -> Path:
    d = sqlite3.connect(path)
    d.execute("CREATE TABLE sync_prefs(key TEXT, encoded_value BLOB)")
    d.execute("INSERT INTO sync_prefs VALUES ('IGNORE_RULES', ?)", (json.dumps(rules_text).encode(),))
    d.execute("INSERT INTO sync_prefs VALUES ('PAUSED_STORAGES', ?)", (json.dumps(PLANTED["a JSON web token"]).encode(),))
    d.commit()
    d.close()
    return path


def test_ignore_rules(tmp_path):
    db = prefs_db(tmp_path / "gd-prefs.db", "# a comment\nnode_modules/\n*.log\n")
    assert ir.ignore_rules(db) == ["# a comment", "node_modules/", "*.log"]
    bad = prefs_db(tmp_path / "gd-bad.db", "*.log\n" + PLANTED["a Google access token"])
    with pytest.raises(ir.Refused) as e:
        ir.ignore_rules(bad)
    assert PLANTED["a Google access token"] not in str(e.value)


def test_cli_reads_rules_from_a_data_folder(tmp_path, capsys):
    root = tmp_path / "Insync"
    (root / "data").mkdir(parents=True)
    prefs_db(root / "data" / "gd-1.db", "*.log\nCache/\n")
    out = tmp_path / "ignore.txt"
    assert main(["insync", "rules", "--root", str(root), "--out", str(out)]) == 0
    assert out.read_text() == "*.log\nCache/\n"
    assert main(["insync", "schema", "--root", str(root)]) == 0
    assert "sync_prefs: key, encoded_value" in capsys.readouterr().out
