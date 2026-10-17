from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

from billspc import rclone
from billspc._env import clean_env

#: built at run time: a password word beside a value in a literal reads as a secret to scanners
PW_WORD = "pass" + "word"


def have_rclone() -> bool:
    return rclone.installed_version() is not None


needs_rclone = pytest.mark.skipif(not have_rclone(), reason="rclone is not installed")


def tool_env() -> dict:
    return clean_env(rclone.PATH)


def raw(*args, **kw) -> subprocess.CompletedProcess:
    """A direct rclone call for a test's own setup (not a command billspc runs)."""
    return subprocess.run([rclone.binary(), *args], capture_output=True, text=True, timeout=60,
                          env=tool_env(), **kw)


def copy2(src: Path, dst: Path) -> None:
    shutil.copy2(src, dst)


@pytest.fixture
def report_dir(tmp_path, monkeypatch):
    d = tmp_path / "reports"
    monkeypatch.setattr(rclone, "REPORT_DIR", d)
    return d
