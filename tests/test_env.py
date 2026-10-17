"""Every function that starts a program takes `env`, the whole environment that program gets.

Each function is called twice against stand-in programs (a small Python script in place of rclone,
`security` and a supervisor, which writes down the environment it was started with and answers the
way the real program would). Every Popen is recorded on the way. With `env` given, every program the
function starts gets exactly that environment. With `env=None`, each gets the environment billspc
built for it before `env` existed, and a variable planted in this process's own environment reaches
none of them.
"""
from __future__ import annotations

import json
import os
import secrets
import subprocess
import sys
import time
from pathlib import Path

import pytest

from billspc import consent as cs
from billspc import rclone
from billspc._env import clean_env

STANDIN = '''#!{python} -I
import json, os, sys
args = sys.argv[1:]
with open({log!r}, "a") as f:
    f.write(json.dumps({{"program": os.path.basename(sys.argv[0]), "argv": args, "env": dict(os.environ)}}) + "\\n")
if args[:1] == ["version"]:
    print("rclone v" + os.environ.get("STANDIN_VERSION", "1.75.2"))
elif args[:1] == ["listremotes"]:
    print("gd:")
elif args[:2] == ["config", "redacted"]:
    print("[gd]")
    print("token = XXX")
elif args[:1] == ["lsjson"]:
    print(json.dumps({{"Metadata": {{"owner": "owner@example.org"}}}}))
'''

MARK = "BILLSPC_TEST_MARK"
PLANTED = "BILLSPC_TEST_PLANTED"


class Bench:
    """Stand-ins for rclone, `security` and a supervisor, a remote whose config is there, and every
    Popen recorded as {"argv", "env"}."""

    def __init__(self, tmp: Path, monkeypatch):
        self.tmp = tmp
        self.log = tmp / "children.jsonl"
        self.bin = tmp / "bin"
        self.bin.mkdir()
        for name in ("rclone", "security", "supervisor"):
            f = self.bin / name
            f.write_text(STANDIN.format(python=sys.executable, log=str(self.log)))
            f.chmod(0o755)
        monkeypatch.setattr(rclone, "BINARY", str(self.bin / "rclone"))
        cfg = tmp / "rclone" / "gd.conf"
        cfg.parent.mkdir()
        cfg.write_text("# Encrypted rclone configuration File\n")
        self.remote = cs.Remote(name="gd", config=cfg, password_command="/bin/echo unused",
                                state_dir=tmp / "state")
        self.given = {"PATH": "/usr/bin:/bin", "HOME": str(tmp), MARK: secrets.token_hex(8),
                      "STANDIN_VERSION": "9.0.0"}
        monkeypatch.setenv(PLANTED, "from the parent")
        monkeypatch.setenv("STANDIN_VERSION", "0.0.1")
        # open_page asks whether the consent port is free; here it always is
        monkeypatch.setattr(cs.socket, "create_connection", self._refuse)
        self.calls: list[dict] = []
        real = subprocess.Popen
        calls = self.calls

        class Recorded(real):
            def __init__(self, args, *a, **k):
                calls.append({"argv": [str(x) for x in args], "env": k.get("env")})
                super().__init__(args, *a, **k)
        monkeypatch.setattr(subprocess, "Popen", Recorded)

    @staticmethod
    def _refuse(*_a, **_k):
        raise ConnectionRefusedError

    def standin(self, name: str) -> str:
        return str(self.bin / name)

    def page_file(self, **extra) -> None:
        """A page file whose pids are this test process under identities it does not have, so each
        is looked up with `ps` and nothing is signalled."""
        cs.write_json(cs.paths(self.remote)["page"],
                      {"page": "http://127.0.0.1:53682/auth?state=x", "rclone": os.getpid(),
                       "rclone_id": "Thu Jan 1 00:00:00 2026 /path/to/rclone", "supervisor": os.getpid(),
                       "supervisor_id": "Thu Jan 1 00:00:00 2026 /path/to/python", "at": time.time(), **extra})

    def seen(self) -> list[dict]:
        """What each stand-in wrote down about itself, in order."""
        if not self.log.exists():
            return []
        return [json.loads(line) for line in self.log.read_text().splitlines() if line.strip()]

    def built(self, call: dict) -> dict:
        """The environment billspc built for this program before `env` existed."""
        prog = call["argv"][0]
        if prog == "/bin/ps":
            return clean_env("/bin:/usr/bin")
        if prog in (self.standin("security"), self.standin("supervisor")):
            return clean_env("/usr/bin:/bin")
        if call["argv"][1:3] == ["config", "reconnect"]:
            return rclone.env(f"{cs.shim(self.remote.state_dir)}:{rclone.PATH}")
        return rclone.env()

    def handed(self, call: dict) -> dict:
        """What a program gets when `self.given` is handed in."""
        if call["argv"][1:3] == ["config", "reconnect"]:
            return {**self.given, "PATH": f"{cs.shim(self.remote.state_dir)}:{self.given['PATH']}"}
        return self.given


@pytest.fixture
def bench(tmp_path, monkeypatch):
    return Bench(tmp_path, monkeypatch)


def _popen(b: Bench, env):
    p = rclone.popen(["version"], config=None, password_command=None, env=env, cwd=str(b.tmp))
    p.communicate(timeout=30)


def _spawn(b: Bench, env):
    pid = cs.spawn_command([b.standin("supervisor"), "serve"], b.tmp / "spawn.log", env=env)
    for _ in range(100):
        if not cs.alive(pid):
            return
        time.sleep(0.05)


def _page(b: Bench, env):
    b.page_file()
    cs.page(b.remote, env=env)


def _port_holder(b: Bench, env):
    b.page_file()
    cs.port_holder([b.remote], env=env)


def _stop(b: Bench, env):
    b.page_file()
    cs.stop(b.remote, env=env)


def _end_leftovers(b: Bench, env):
    b.page_file()
    assert cs.end_leftovers([b.remote], env=env)["stale"] == ["gd"]


def _open_page(b: Bench, env):
    b.page_file()
    out = cs.open_page(b.remote, spawn=lambda r: 0, client=("id", "sec"), sleep=lambda s: None,
                       wait_s=1, env=env)
    assert out["outcome"] == "failure" and "did not come up" in out["why"]


def _supervise(b: Bench, env):
    res = cs.supervise(b.remote, env=env, quiet=0.1)
    assert res["account"] == {"outcome": "success", "account": "owner@example.org"}


#: each function that starts a program, called with the environment to hand in (None or a dict)
CALLS = {
    "rclone.run": lambda b, env: rclone.run(["version"], config=None, password_command=None, env=env),
    "rclone.popen": _popen,
    "rclone.installed_version": lambda b, env: rclone.installed_version(env=env),
    "rclone.version_ok": lambda b, env: rclone.version_ok(env=env),
    "MacKeychain.has": lambda b, env: cs.MacKeychain(security=b.standin("security")).has("item", env=env),
    "MacKeychain.add": lambda b, env: cs.MacKeychain(security=b.standin("security")).add("item", "v", env=env),
    "proc_id": lambda b, env: cs.proc_id(os.getpid(), env),
    "ours": lambda b, env: cs.ours(os.getpid(), "not this process", env),
    "spawn_command": _spawn,
    "rc": lambda b, env: cs.rc(b.remote, ["listremotes"], env=env),
    "remotes_in_config": lambda b, env: cs.remotes_in_config(b.remote, env),
    "ensure_config": lambda b, env: cs.ensure_config(b.remote, client=("id", "sec"), env=env),
    "config_ok": lambda b, env: cs.config_ok(b.remote, env),
    "has_token": lambda b, env: cs.has_token(b.remote, env),
    "discard_token": lambda b, env: cs.discard_token(b.remote, client=("id", "sec"), env=env),
    "owner_of_probe": lambda b, env: cs.owner_of_probe(b.remote, env),
    "check_account": lambda b, env: cs.check_account(b.remote, env=env),
    "page": _page,
    "port_holder": _port_holder,
    "stop": _stop,
    "end_leftovers": _end_leftovers,
    "open_page": _open_page,
    "supervise": _supervise,
}


@pytest.mark.parametrize("name", list(CALLS))
def test_a_given_env_reaches_every_child(bench, name):
    CALLS[name](bench, bench.given)
    assert bench.calls, f"{name} started no program"
    for call in bench.calls:
        assert call["env"] == bench.handed(call), call["argv"]
    for child in bench.seen():
        assert child["env"].get(MARK) == bench.given[MARK] and PLANTED not in child["env"], child["argv"]


@pytest.mark.parametrize("name", list(CALLS))
def test_no_env_keeps_the_built_environment(bench, name):
    CALLS[name](bench, None)
    assert bench.calls, f"{name} started no program"
    for call in bench.calls:
        assert call["env"] == bench.built(call), call["argv"]
    for child in bench.seen():
        assert MARK not in child["env"] and PLANTED not in child["env"], child["argv"]


def test_both_runs_start_the_same_programs(bench):
    """env changes only the environment: each function starts the same programs either way."""
    for name, call in CALLS.items():
        bench.calls.clear()
        call(bench, None)
        without = [c["argv"][:2] for c in bench.calls]
        bench.calls.clear()
        call(bench, bench.given)
        assert [c["argv"][:2] for c in bench.calls] == without, name


def test_the_version_is_read_with_the_env_given(bench):
    assert rclone.installed_version(env=bench.given) == "9.0.0"
    assert rclone.installed_version() == "1.75.2", "the parent's STANDIN_VERSION never reaches rclone"
    assert rclone.version_ok(env=bench.given) == (True, "9.0.0")
    assert rclone.version_ok("9.1", env=bench.given) == (False, "9.0.0")


def test_a_given_env_with_a_config_password(bench):
    conf = bench.tmp / "c.conf"
    rclone.run(["listremotes"], config=conf, password_command=None, config_password="pw-1", env=bench.given)
    assert bench.calls[-1]["env"] == {**bench.given, "RCLONE_CONFIG_PASS": "pw-1"}
    assert bench.seen()[-1]["env"]["RCLONE_CONFIG_PASS"] == "pw-1"
    rclone.run(["listremotes"], config=conf, password_command=None, config_password="pw-2")
    assert bench.calls[-1]["env"] == rclone.env(config_password="pw-2")


def test_path_is_not_used_when_env_is_given(bench):
    rclone.run(["version"], config=None, password_command=None, path="/a:/b", env=bench.given)
    assert bench.calls[-1]["env"]["PATH"] == "/usr/bin:/bin"
    rclone.run(["version"], config=None, password_command=None, path="/usr/bin:/bin:/a")
    assert bench.calls[-1]["env"] == rclone.env("/usr/bin:/bin:/a")


@pytest.mark.parametrize("bad", ["RCLONE_CONFIG", "RCLONE_DRIVE_TOKEN", "rclone_drive_root_folder_id",
                                 "RCLONE_CONFIG_PASS"])
def test_an_env_with_an_rclone_variable_is_refused(bench, bad):
    env = {**bench.given, bad: "x"}
    with pytest.raises(rclone.Refused, match=bad):
        rclone.run(["version"], config=None, password_command=None, env=env)
    with pytest.raises(rclone.Refused, match=bad):
        rclone.popen(["version"], config=None, password_command=None, env=env)
    with pytest.raises(rclone.Refused, match=bad):
        rclone.installed_version(env=env)
    with pytest.raises(rclone.Refused, match=bad):
        cs.has_token(bench.remote, env)
    assert bench.calls == [], "nothing runs"


def test_popen_passes_other_keywords_on(bench):
    p = rclone.popen(["version"], config=None, password_command=None, env=bench.given, cwd=str(bench.tmp))
    out, _ = p.communicate(timeout=30)
    assert b"rclone v9.0.0" in out and bench.calls[-1]["env"] == bench.given


def test_a_keychain_takes_its_env_from_the_constructor(bench):
    kc = cs.MacKeychain(security=bench.standin("security"), env=bench.given)
    assert kc.has("item") is True and kc.add("item", "v")
    assert [c["env"] for c in bench.calls] == [bench.given] * 3
    other = {**bench.given, MARK: "per call"}
    bench.calls.clear()
    kc.has("item", env=other)
    assert bench.calls[-1]["env"] == other, "an env given to the call comes first"


def test_spawn_command_without_env_keeps_the_names_it_is_told_to(bench, monkeypatch):
    monkeypatch.setenv("BILLSPC_KEEP_ME", "kept")
    _ = cs.spawn_command([bench.standin("supervisor")], bench.tmp / "s.log", keep=("BILLSPC_KEEP_ME",))
    assert bench.calls[-1]["env"] == clean_env("/usr/bin:/bin", keep=("BILLSPC_KEEP_ME",))
    assert bench.calls[-1]["env"]["BILLSPC_KEEP_ME"] == "kept"
    _ = cs.spawn_command([bench.standin("supervisor")], bench.tmp / "s.log", keep=("BILLSPC_KEEP_ME",),
                         env=bench.given)
    assert bench.calls[-1]["env"] == bench.given, "keep is not used when env is given"


def test_supervise_keeps_the_no_open_folder_first_on_a_given_path(bench):
    no_path = {k: v for k, v in bench.given.items() if k != "PATH"}
    cs.supervise(bench.remote, env=no_path, quiet=0.1)
    reconnect = next(c for c in bench.calls if c["argv"][1:3] == ["config", "reconnect"])
    assert reconnect["env"] == {**no_path, "PATH": str(cs.shim(bench.remote.state_dir))}
    assert all(c["env"] == no_path for c in bench.calls if c is not reconnect)
