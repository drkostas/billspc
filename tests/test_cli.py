"""The command line, the config file and the example, run against a local stand-in remote."""
from __future__ import annotations

import os
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import pytest

from conftest import needs_rclone, raw
from billspc import config, rclone
from billspc.cli import SKILL_SRC, main

ROOT = Path(__file__).resolve().parent.parent


def write_config(tmp: Path, extra: str = "") -> Path:
    cfg = tmp / "config.toml"
    cfg.write_text(f"""
[billspc]
state_dir = "{tmp / 'state'}"
password_store = "files"
password_dir = "{tmp / 'pw'}"

[remotes.gd]
config = "{tmp / 'rclone' / 'gd.conf'}"
account = "owner@example.org"

[folders.main]
path = "{tmp / 'Drive'}"
remote = "gd"
ignore_file = "{tmp / 'ignore.txt'}"
include = ["Projects"]
never = ["Projects/app/live.db"]
{extra}""")
    (tmp / "ignore.txt").write_text("# a comment\n*.log\n")
    return cfg


def test_skill_prints_and_installs(tmp_path, capsys, monkeypatch):
    monkeypatch.setenv("BILLSPC_CONFIG", str(tmp_path / "missing.toml"))
    assert main(["skill"]) == 0
    text = capsys.readouterr().out
    assert text == SKILL_SRC.read_text() and text.startswith("---\nname: billspc\n")
    assert main(["skill", "--install", "--dir", str(tmp_path)]) == 0
    assert (tmp_path / "billspc" / "SKILL.md").read_text() == text


def test_a_missing_config_is_named(tmp_path, capsys):
    assert main(["--config", str(tmp_path / "nope.toml"), "filters", "main"]) == 2
    assert "no config" in capsys.readouterr().err


def test_config_is_read_and_checked(tmp_path):
    cfg = config.load(write_config(tmp_path))
    r = cfg.remote("gd")
    assert r.password_command == f"/bin/cat {tmp_path / 'pw' / 'billspc-gd'}"
    assert r.account == "owner@example.org" and r.state_dir == tmp_path / "state" / "consent"
    fs = cfg.filters("main")
    assert fs.excluded("Projects/app/live.db", False) and fs.excluded("Projects/a.log", False)
    assert fs.excluded("Music/a.mp3", False) and fs.excluded("Projects/a.txt", False) is None
    with pytest.raises(KeyError):
        cfg.remote("nope")
    bad = tmp_path / "bad.toml"
    bad.write_text('[folders.x]\npath = "/tmp/x"\nremote = "nope"\n')
    with pytest.raises(ValueError):
        config.load(bad)
    keychain = tmp_path / "k.toml"
    keychain.write_text('[remotes.gd]\nconfig = "/tmp/gd.conf"\n')
    assert config.load(keychain).remote("gd").password_command.startswith("/usr/bin/security find-generic-password -a billspc")


def test_apply_hands_rclone_its_settings(tmp_path, monkeypatch):
    for name in ("BINARY", "PATH", "REPORT_DIR"):
        monkeypatch.setattr(rclone, name, getattr(rclone, name))
    cfg = config.load(write_config(tmp_path, '\n[rclone]\nbinary = "/opt/x/rclone"\npath = "/opt/x:/usr/bin"\n'))
    cfg.apply()
    assert rclone.BINARY == "/opt/x/rclone" and rclone.PATH == "/opt/x:/usr/bin"
    assert rclone.REPORT_DIR == tmp_path / "state" / "reports"


def test_filters_command(tmp_path, capsys):
    cfg = write_config(tmp_path)
    assert main(["--config", str(cfg), "filters", "main"]) == 0
    lines = capsys.readouterr().out.splitlines()
    assert "- /Projects/app/live.db" in lines and lines[-2:] == ["+ /Projects/**", "- **"]
    out = tmp_path / "f.txt"
    assert main(["--config", str(cfg), "filters", "main", "--out", str(out)]) == 0
    assert out.read_text().splitlines()[1:] == lines


def test_scan_command(tmp_path, capsys):
    cfg = write_config(tmp_path)
    d = tmp_path / "Drive"
    (d / "Projects").mkdir(parents=True)
    (d / "Projects" / "old.txt").write_text("old")
    time.sleep(1.1)
    since = datetime.now(timezone.utc).isoformat()
    time.sleep(1.1)
    (d / "Projects" / "new.txt").write_text("new")
    (d / "Projects" / "new.log").write_text("log")
    (d / "Music").mkdir()
    (d / "Music" / "song.mp3").write_text("x")
    assert main(["--config", str(cfg), "scan", "main", "--since", since]) == 0
    assert "1 file(s) changed" in capsys.readouterr().out
    listing = (tmp_path / "state" / "scan" / "main.json").read_text()
    assert "Projects/new.txt" in listing and "new.log" not in listing and "song.mp3" not in listing


@needs_rclone
def test_rclone_version_command(capsys):
    assert main(["rclone-version"]) == 0
    assert "(ok)" in capsys.readouterr().out
    assert main(["rclone-version", "--minimum", "999.0"]) == 1


@needs_rclone
def test_the_example_copies_what_changed(tmp_path):
    """examples/catch_up.py against a local stand-in remote in an encrypted config."""
    src, dst = tmp_path / "Drive", tmp_path / "remote"
    (src / "Projects").mkdir(parents=True)
    dst.mkdir()
    (src / "Projects" / "old.txt").write_text("old")
    (dst / "kept.txt").write_text("only on the remote")
    time.sleep(1.1)
    since = datetime.now(timezone.utc).isoformat()
    time.sleep(1.1)
    (src / "Projects" / "new.txt").write_text("new")
    (src / "Projects" / ".DS_Store").write_text("junk")
    (tmp_path / "pw").write_text(os.urandom(12).hex())
    pw = f"/bin/cat {tmp_path / 'pw'}"
    conf = tmp_path / "c.conf"
    for a in (["config", "encryption", "set"],
              ["config", "create", "gd", "alias", f"remote={dst}", "--non-interactive", "--no-output"]):
        assert raw(*a, "--config", str(conf), "--password-command", pw).returncode == 0
    out = subprocess.run([sys.executable, str(ROOT / "examples" / "catch_up.py"), str(src), "gd:", since,
                          "--config", str(conf), "--password-command", pw], capture_output=True, text=True, timeout=120)
    assert out.returncode == 0, out.stdout + out.stderr
    assert "copied Projects/new.txt (3 bytes)" in out.stdout
    assert (dst / "Projects" / "new.txt").read_text() == "new"
    assert not (dst / "Projects" / "old.txt").exists() and not (dst / "Projects" / ".DS_Store").exists()
    assert (dst / "kept.txt").exists()
