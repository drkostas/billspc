"""The environment billspc gives every program it starts.

It is built from nothing, never copied from os.environ, so a variable the caller happened to export
(an RCLONE_* override, a proxy, a different config path) cannot change what the program does.
"""
from __future__ import annotations

import os

#: carried over when set: who the user is, where home is, and how text is encoded
BASE = ("HOME", "USER", "LOGNAME", "LANG", "LC_ALL", "LC_CTYPE", "TMPDIR")
UTF8 = "en_US.UTF-8"


def clean_env(path: str, keep: tuple[str, ...] = (), add: dict[str, str] | None = None) -> dict[str, str]:
    """An environment with PATH set to `path`, the BASE variables that are set, the names in
    `keep` that are set, and `add` on top. A UTF-8 locale is declared when none is set."""
    env = {"PATH": path}
    for name in (*BASE, *keep):
        value = os.environ.get(name)
        if value is not None:
            env[name] = value
    if not any(env.get(n) for n in ("LC_ALL", "LC_CTYPE", "LANG")):
        env["LC_CTYPE"] = UTF8
    env.update(add or {})
    return env
