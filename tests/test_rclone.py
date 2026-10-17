"""Every rclone command line passes the allowlist first, and the output readers read real rclone.

Each refusal below is a command or spelling that rclone itself reads as the dangerous thing: a flag's
value taken for the subcommand, combined short flags, -v twice, every false spelling of
--drive-use-trash, touch of anything but the probe or with -R, config create keys that point a remote
elsewhere, a copy's own safeguard turned off, a copy the other way or between remotes, a remote named
by a connection string or an on-the-fly backend, and a read whose flag writes a local file. Every flag
`rclone help flags` lists is tried on each command, so a flag a later rclone adds is refused until
someone decides it is safe.
"""
from __future__ import annotations

import os
import re
import time
from pathlib import Path

import pytest

from conftest import PW_WORD, copy2, needs_rclone, raw
from billspc import rclone

HOME_FILE = Path.home() / "Documents" / "notes.txt"


def refused(args) -> str | None:
    try:
        rclone.check(args)
    except rclone.Refused as e:
        return str(e)
    return None


PROBE = "gd:" + rclone.PROBE_PREFIX + "0123456789ab"


def allowed_lines(report_dir: Path):
    return [["version"], ["about", "gd:", "--json"], ["lsjson", "gd:", "--files-only"],
            ["check", "/x", "gd:", "--files-from-raw", "/l", "--one-way"], ["listremotes"],
            ["copy", "/x", "gd:", "--files-from-raw", "/l", "--no-traverse", "--dry-run"],
            ["touch", PROBE], ["deletefile", PROBE],
            ["config", "create", "gd", "drive", "scope=drive", "--non-interactive", "--no-output"],
            ["config", "delete", "gd"], ["config", "reconnect", "gd:"],
            ["config", "redacted", "gd"], ["config", "encryption", "set"],
            ["config", "encryption", "check"], ["copy", "/x", "gd:", "--files-from", "/l", "--log-level", "INFO"],
            ["copy", "/x", "gd:", "--files-from-raw", "/l", "--ignore-existing", "--use-json-log", "-v"],
            ["copy", "/x", "gd:", "--files-from-raw", "/l", "--drive-use-trash=true"],
            ["lsjson", "gd:Projects", "-R", "--files-only"],
            ["check", "/x", "gd:", "--files-from-raw", "/l", "--one-way", "--combined",
             str(report_dir / "catchup" / "rest.check")],
            ["copy", "/x", "gd:", "--files-from-raw", "/l", "--update=true", "-u=t"],
            # a local folder whose name holds a colon (a slash before the colon makes it a path)
            ["copy", "/x/a:b", "gd:Projects/a,b", "--files-from-raw", "/l"],
            ["copy", "/x/a=b", "gd:a=b", "--files-from-raw", "/l"],
            ["dedupe", "--dedupe-mode=skip", "--drive-use-trash=true", "--max-depth=1", "gd:Projects"],
            ["dedupe", "--dedupe-mode=list", "--max-depth=1", "--use-json-log", "--log-level=NOTICE", "gd:Projects"]]


def test_allowed(report_dir):
    for a in allowed_lines(report_dir):
        assert refused(a) is None, a


def never_lines(report_dir: Path) -> dict:
    return {
        "a sync, which deletes what the source lacks": ["sync", "/x", "gd:"],
        "bisync": ["bisync", "gd:", "/x"],
        "a move": ["move", "/x", "gd:"],
        "a moveto": ["moveto", "gd:a", "gd:b"],
        "delete": ["delete", "gd:Projects"],
        "purge": ["purge", "gd:"],
        "rmdirs": ["rmdirs", "gd:"],
        "cleanup, which empties the trash": ["cleanup", "gd:"],
        "dedupe with no mode": ["dedupe", "gd:"],
        "a mount": ["mount", "gd:", "/Volumes/x"],
        "a server": ["serve", "http", "gd:"],
        "config show, which prints the token": ["config", "show", "gd"],
        "config dump": ["config", "dump"],
        "config disconnect, which revokes the grant": ["config", "disconnect", "gd:"],
        "config update": ["config", "update", "gd", "token="],
        "config " + PW_WORD: ["config", PW_WORD, "gd", "x", "y"],
        "--delete-excluded": ["copy", "/x", "gd:", "--files-from", "/l", "--delete-excluded"],
        "--drive-use-trash=false": ["copy", "/x", "gd:", "--files-from", "/l", "--drive-use-trash=false"],
        "--drive-use-trash false": ["copy", "/x", "gd:", "--files-from", "/l", "--drive-use-trash", "false"],
        "following links": ["copy", "/x", "gd:", "--files-from", "/l", "-L"],
        "copying links": ["copy", "/x", "gd:", "--files-from", "/l", "--links"],
        "a dump of the requests": ["about", "gd:", "--dump", "headers"],
        "-vv": ["about", "gd:", "-vv"],
        "DEBUG logs": ["about", "gd:", "--log-level", "DEBUG"],
        "DEBUG logs, one word": ["about", "gd:", "--log-level=DEBUG"],
        "--max-delete": ["copy", "/x", "gd:", "--files-from", "/l", "--max-delete", "5"],
        "--resync": ["copy", "/x", "gd:", "--files-from", "/l", "--resync"],
        "a client on the command line": ["about", "gd:", "--drive-client-" + "secret=x"],
        "a token on the command line": ["about", "gd:", "--drive-token={}"],
        "another root folder": ["lsjson", "gd:", "--drive-root-folder-id=abc"],
        "asking for the config's password": ["about", "gd:", "--ask-password"],
        "deletefile of a real file": ["deletefile", "gd:Projects/thesis.pdf"],
        "deletefile of two": ["deletefile", PROBE, "gd:x"],
        "a copy of everything (no list)": ["copy", "/x", "gd:"],
        "nothing at all": [],
        "a flag's value taken for the subcommand": ["--log-file", "version", "config", "show"],
        "a flag first, then a copy and a sync": ["--log-file", "copy", "sync", "/x", "gd:"],
        "a flag first, then config disconnect": ["--log-file", "about", "config", "disconnect", "gd:"],
        "-v twice": ["about", "gd:", "-v", "-v"],
        "-v twice in front": ["-v", "-v", "about", "gd:"],
        "--verbose given a level": ["about", "gd:", "--verbose=2"],
        "-v given a level": ["about", "gd:", "-v=2"],
        "-v and --verbose": ["about", "gd:", "-v", "--verbose"],
        "-Lv, links in a group": ["copy", "/x", "gd:", "--files-from", "/l", "-Lv"],
        "-vl, links at the end of a group": ["copy", "/x", "gd:", "--files-from", "/l", "-vl"],
        **{f"--drive-use-trash={v}": ["copy", "/x", "gd:", "--files-from", "/l", f"--drive-use-trash={v}"]
           for v in ("f", "F", "False", "FALSE", "0", "nope")},
        "touch of a real folder": ["touch", "gd:Projects"],
        "touch -R of a real folder": ["touch", "gd:Projects", "-R"],
        "touch --recursive of the probe": ["touch", PROBE, "--recursive"],
        "touch -Rv of the probe": ["touch", PROBE, "-Rv"],
        "config create with a token": ["config", "create", "gd", "drive", "token={}"],
        "config create with the trash off": ["config", "create", "gd", "drive", "use_trash=false"],
        "config create with another folder": ["config", "create", "gd", "drive", "root_folder_id=abc"],
        "--update=false": ["copy", "/x", "gd:", "--files-from-raw", "/l", "--update=false"],
        "--ignore-existing=false": ["copy", "/x", "gd:", "--files-from-raw", "/l", "--ignore-existing=false"],
        "-u=false": ["copy", "/x", "gd:", "--files-from-raw", "/l", "-u=false"],
        "-n=0, a dry run that is not one": ["copy", "/x", "gd:", "--files-from-raw", "/l", "-n=0"],
        "--dry-run=false": ["copy", "/x", "gd:", "--files-from-raw", "/l", "--dry-run=false"],
        "--use-json-log=false": ["copy", "/x", "gd:", "--files-from-raw", "/l", "--use-json-log=false"],
        "--immutable=f": ["copy", "/x", "gd:", "--files-from-raw", "/l", "--immutable=f"],
        "a value given to a group of short flags": ["copy", "/x", "gd:", "--files-from-raw", "/l", "-uv=true"],
        "a copy from the remote to a local folder": ["copy", "gd:", str(HOME_FILE.parent), "--files-from-raw", "/l"],
        "a copy between remotes": ["copy", "gd:A", "gd:B", "--files-from-raw", "/l"],
        "a copy between two local folders": ["copy", "/x", "/y", "--files-from-raw", "/l"],
        "a copy from a relative folder": ["copy", "x", "gd:", "--files-from-raw", "/l"],
        "a copy with a third word": ["copy", "/x", "gd:", "/z", "--files-from-raw", "/l"],
        "a copy to an on-the-fly backend": ["copy", "/x", f":local:{HOME_FILE.parent}", "--files-from-raw", "/l"],
        "a copy to a connection string": ["copy", "/x", "gd,root_folder_id=abc:", "--files-from-raw", "/l"],
        "a listing of a connection string": ["lsjson", "gd,shared_with_me=true:"],
        "a listing of an on-the-fly backend": ["lsjson", ":local:/x"],
        "a check's report written over a local file": [
            "check", "/x", "gd:", "--files-from-raw", "/l", "--combined", str(HOME_FILE)],
        "a check's report as one word": ["check", "/x", "gd:", "--files-from-raw", "/l", f"--combined={HOME_FILE}"],
        "a check's report beside the report folder": [
            "check", "/x", "gd:", "--files-from-raw", "/l", "--combined", f"{report_dir}-x/r"],
        "a check's report out of the report folder by ..": [
            "check", "/x", "gd:", "--files-from-raw", "/l", "--combined", f"{report_dir}/../r"],
        "a check's report at a relative path": ["check", "/x", "gd:", "--files-from-raw", "/l", "--combined", "r"],
        "a listing's log in a local folder": ["lsjson", "gd:", "--log-file", str(HOME_FILE)],
        "about's log in a local folder": ["about", "gd:", f"--log-file={HOME_FILE}"],
        "a check that downloads every file": ["check", "/x", "gd:", "--files-from-raw", "/l", "--download"],
        "another config on the command line": ["lsjson", "gd:", "--config", "/other.conf"],
        "dedupe with a bare mode word": ["dedupe", "rename", "gd:Projects"],
        "dedupe that keeps one of two different files": ["dedupe", "--dedupe-mode=newest", "--drive-use-trash=true", "gd:Projects"],
        "dedupe with a mode without its =": ["dedupe", "--dedupe-mode", "skip", "--drive-use-trash=true", "gd:Projects"],
        "dedupe skip without the trash": ["dedupe", "--dedupe-mode=skip", "gd:Projects"],
        "dedupe skip past the trash": ["dedupe", "--dedupe-mode=skip", "--drive-use-trash=false", "gd:Projects"],
        "dedupe by content anywhere": ["dedupe", "--dedupe-mode=list", "--by-hash", "gd:Projects"],
        "dedupe of two paths": ["dedupe", "--dedupe-mode=list", "gd:Projects", "gd:Other"],
        "dedupe of a local folder": ["dedupe", "--dedupe-mode=list", "/tmp/x/Projects"],
        "dedupe with a value without its =": ["dedupe", "--dedupe-mode=list", "--max-depth", "1", "gd:Projects"],
    }


def test_refused(report_dir):
    lines = never_lines(report_dir)
    through = [why for why, a in lines.items() if refused(a) is None]
    assert not through
    plainly = [w for w in lines if "connection string" in w or "on-the-fly" in w]
    assert len(plainly) == 4
    assert all("does not name a remote plainly" in refused(lines[w]) for w in plainly)


def test_no_report_dir_refuses_every_report(monkeypatch, tmp_path):
    monkeypatch.setattr(rclone, "REPORT_DIR", None)
    assert refused(["check", "/x", "gd:", "--files-from-raw", "/l", "--combined", str(tmp_path / "r")])
    monkeypatch.setattr(rclone, "REPORT_DIR", lambda: tmp_path)
    assert refused(["check", "/x", "gd:", "--files-from-raw", "/l", "--combined", str(tmp_path / "r")]) is None


def test_probe_prefix_is_configurable(monkeypatch):
    monkeypatch.setattr(rclone, "PROBE_PREFIX", ".mine-check-")
    assert refused(["deletefile", "gd:.mine-check-0123456789ab"]) is None
    assert refused(["deletefile", PROBE]) is not None


def test_config_needs_a_way_to_open_it():
    with pytest.raises(rclone.Refused):
        rclone.argv(["about", "gd:"], config=Path("/tmp/x.conf"), password_command=None)
    full = rclone.argv(["about", "gd:"], config=Path("/tmp/x.conf"), password_command="/bin/echo x", rclone="rclone")
    assert full[0] == "rclone"
    assert full[-5:] == ["--config", "/tmp/x.conf", "--password-command", "/bin/echo x", "--ask-password=false"]
    by_env = rclone.argv(["about", "gd:"], config=Path("/tmp/x.conf"), password_command=None,
                         config_password="x", rclone="rclone")
    assert by_env[-3:] == ["--config", "/tmp/x.conf", "--ask-password=false"] and "x" not in by_env[1:-3]


def test_redacted_hides_client_values():
    field, planted = "client_" + "secret", os.urandom(12).hex()
    shown = rclone.redacted(["rclone", "config", "create", "gd", "drive", f"client_id={planted}",
                             f"{field}={planted}", "scope=drive"])
    assert planted not in " ".join(shown)
    assert f"{field}=XXX" in shown and "scope=drive" in shown


def test_env_carries_no_rclone_variable(monkeypatch):
    monkeypatch.setenv("RCLONE_DRIVE_ROOT_FOLDER_ID", "planted")
    monkeypatch.setenv("RCLONE_CONFIG_PASS", "planted")
    env = rclone.env()
    assert not any(k.startswith("RCLONE") for k in env)
    assert env["PATH"] == rclone.PATH and "HOME" in env
    assert rclone.env("/a:/b")["PATH"] == "/a:/b"
    assert rclone.env(config_password="given")["RCLONE_CONFIG_PASS"] == "given"


def test_json_log_reads_objects_only():
    assert rclone.json_log('not json\n{"a": 1}\n[1]\n{broken') == [{"a": 1}]


def test_version_comparison(monkeypatch):
    monkeypatch.setattr(rclone, "installed_version", lambda rclone=None, env=None: "1.75.2")
    assert rclone.version_ok("1.75.2") == (True, "1.75.2")
    assert rclone.version_ok("1.80") == (False, "1.75.2")
    assert rclone.version_ok("1.9") == (True, "1.75.2")
    monkeypatch.setattr(rclone, "installed_version", lambda rclone=None, env=None: None)
    assert rclone.version_ok() == (False, None)


# ---------------------------------------------------------------- against the installed rclone

FLAG_LINE = re.compile(r"^\s+(?:-([a-zA-Z]), )?(--[a-z0-9][a-z0-9-]*)(?: ([A-Za-z]+))?\s", re.M)
BASE = {"version": ["version"], "listremotes": ["listremotes"], "about": ["about", "gd:"],
        "lsjson": ["lsjson", "gd:"], "check": ["check", "/x", "gd:"],
        "copy": ["copy", "/x", "gd:", "--files-from-raw", "/l"],
        "touch": ["touch", PROBE], "deletefile": ["deletefile", PROBE],
        "dedupe": ["dedupe", "--dedupe-mode=list", "gd:Projects"],
        "config create": ["config", "create", "gd", "drive"], "config delete": ["config", "delete", "gd"],
        "config reconnect": ["config", "reconnect", "gd:"], "config redacted": ["config", "redacted", "gd"],
        "config encryption set": ["config", "encryption", "set"],
        "config encryption check": ["config", "encryption", "check"]}


@needs_rclone
def test_installed_rclone_is_new_enough():
    ok, got = rclone.version_ok()
    assert ok, f"rclone {got} is older than {rclone.VERSION}"


@needs_rclone
def test_every_listed_flag_is_refused_but_the_chosen_ones():
    assert set(BASE) == set(rclone.FLAGS) == rclone.ALLOWED
    global_help = raw("help", "flags").stdout
    through, unknown = {}, {}
    for cmd, base in BASE.items():
        own = raw(*cmd.split(), "--help").stdout
        listed = {m[1]: m[0] for m in FLAG_LINE.findall(global_help + "\n" + own)}
        assert refused(base) is None, cmd
        gone = [f for f in listed if f not in rclone.FLAGS[cmd] and refused([*base, f]) is None]
        gone += [f"-{s}" for s in set(listed.values()) - {""} if s not in rclone.SHORT.get(cmd, ())
                 and refused([*base, f"-{s}"]) is None]
        if gone:
            through[cmd] = gone[:6]
        missing = [f for f in rclone.FLAGS[cmd] if f not in listed]
        if missing:
            unknown[cmd] = missing
    assert not through
    assert not unknown, "a list holds a flag rclone does not list (a misspelt name)"


@needs_rclone
def test_copy_flags_with_values_are_the_ones_rclone_types():
    typed = {m[1]: m[2] for m in FLAG_LINE.findall(raw("help", "flags").stdout + "\n" + raw("copy", "--help").stdout)}
    wrong = sorted(f for f in rclone.COPY_FLAGS if (f in rclone.COPY_VALUED) != (typed.get(f, "") not in ("", "count")))
    assert not wrong
    assert all(refused([*BASE["copy"], f"{f}=false"]) is not None for f in rclone.COPY_FLAGS
               if f not in rclone.COPY_VALUED and f != "--verbose")


@needs_rclone
def test_copy_carries_only_its_own_flags():
    copy = BASE["copy"]
    for f in ("--ignore-times", "-I", "--no-check-dest", "--ignore-size", "--size-only", "-c", "--modify-window=8760h",
              "--use-server-modtime", "--compare-dest", "--copy-dest", "--max-transfer=1G", "--ignore-case-sync",
              "--local-no-check-updated", "--ignore-checksum", "--drive-shared-with-me", "--name-transform",
              "-M", "-uI", "--refresh-times", "--log-file=/tmp/x"):
        assert refused([*copy, f]) is not None, f
    helps = raw("help", "flags").stdout + "\n" + raw("copy", "--help").stdout
    longs = sorted(set(re.findall(r"^\s+(?:-[a-zA-Z], )?(--[a-z0-9][a-z0-9-]*)", helps, re.M)))
    shorts = sorted(set(re.findall(r"^\s+-([a-zA-Z]), --", helps, re.M)))
    assert len(longs) > 300
    assert [f for f in longs if f not in rclone.COPY_FLAGS and refused([*copy, f]) is None] == []
    assert [s for s in shorts if s not in rclone.COPY_SHORT and refused([*copy, f"-{s}"]) is None] == []
    assert set(rclone.COPY_FLAGS) <= set(longs) and set(rclone.COPY_SHORT) <= set(shorts)
    assert refused([*copy, "--no-traverse", "--update", "--use-json-log", "-v", "--drive-skip-gdocs", "--dry-run"]) is None


@needs_rclone
def test_config_key_in_another_case_is_read_by_no_backend(tmp_path):
    conf = tmp_path / "c.conf"
    conf.write_text("")
    raw("config", "create", "al", "alias", f"Remote={tmp_path}", "--non-interactive", "--no-output", "--config", str(conf))
    inert = raw("lsjson", "al:", "--config", str(conf))
    assert inert.returncode != 0 and "empty remote" in inert.stderr
    assert refused(["config", "create", "gd", "drive", "Token=x"]) is None


@needs_rclone
def test_run_reports_the_version():
    v = rclone.run(["version"], config=None, password_command=None, timeout=30)
    assert v.returncode == 0 and f"rclone v{rclone.installed_version()}" in v.stdout


@pytest.fixture
def planted(tmp_path):
    d = tmp_path
    (d / "src").mkdir()
    (d / "dst").mkdir()
    (d / "src" / "a.txt").write_text("new")
    (d / "dst" / "a.txt").write_text("old!")
    (d / "dst" / "only-on-remote.txt").write_text("keep me")
    (d / "list").write_text("a.txt\n")
    (d / "empty.conf").write_text("")
    return d


def dry(d: Path, *args):
    r = raw(*args, "--dry-run", "--use-json-log", "-v", "--config", str(d / "empty.conf"))
    return rclone.json_log(r.stdout + "\n" + r.stderr)


@needs_rclone
def test_plan_problems_on_real_dry_runs(planted):
    d = planted
    synced = rclone.plan_problems(dry(d, "sync", str(d / "src"), str(d / "dst")))
    assert "delete only-on-remote.txt" in synced and "deletes 1" in synced
    plan = dry(d, "copy", str(d / "src"), str(d / "dst"), "--files-from-raw", str(d / "list"), "--no-traverse")
    assert rclone.plan_problems(plan) == []
    # a copy that replaces a.txt plans {"skipped": "copy"} as a new file would, so the caller names
    # the paths it decided to write, and any other planned copy is a problem
    over = rclone.plan_problems(plan, copies=set())
    assert any(p.startswith("copy a.txt") for p in over)
    assert rclone.plan_problems(plan, copies={"a.txt"}) == []
    assert (d / "dst" / "only-on-remote.txt").exists()


@needs_rclone
def test_combined_reads_a_real_check(planted):
    d = planted
    (d / "src" / "same.txt").write_text("same")
    copy2(d / "src" / "same.txt", d / "dst" / "same.txt")
    (d / "src" / "folder").mkdir()
    (d / "list2").write_text("a.txt\nsame.txt\ngone.txt\nfolder\n")
    raw("check", str(d / "src"), str(d / "dst"), "--files-from-raw", str(d / "list2"), "--one-way",
        "--combined", str(d / "comb"), "--config", str(d / "empty.conf"))
    # a vanished file or a folder in the list has no line, so it is never read as checked
    assert rclone.combined((d / "comb").read_text()) == {"a.txt": "*", "same.txt": "="}


@needs_rclone
def test_copied_reads_a_real_copy(planted):
    d = planted
    (d / "src" / "same.txt").write_text("same")
    (d / "dst2").mkdir()
    copy2(d / "src" / "same.txt", d / "dst2" / "same.txt")
    (d / "list3").write_text("a.txt\nsame.txt\ngone.txt\n")
    wrote = raw("copy", str(d / "src"), str(d / "dst2"), "--files-from-raw", str(d / "list3"), "--no-traverse",
                "--use-json-log", "-v", "--config", str(d / "empty.conf"))
    assert rclone.copied(rclone.json_log(wrote.stdout + "\n" + wrote.stderr)) == {"a.txt": len("new")}
    assert (d / "dst2" / "a.txt").read_text() == "new"


def _encrypted_alias(cut: Path, password: str) -> str:
    """An encrypted config whose remote `gd` is a local folder that streams as a cloud drive does
    (no_clone, since a copy between folders of APFS is otherwise an instant clone)."""
    (cut / "pw").write_text(password)
    pw = f"/bin/cat {cut / 'pw'}"
    for a in (["config", "encryption", "set"],
              ["config", "create", "inner", "local", "no_clone=true", "--non-interactive", "--no-output"],
              ["config", "create", "gd", "alias", f"remote=inner:{cut / 'dst'}", "--non-interactive", "--no-output"]):
        r = raw(*a, "--config", str(cut / "c.conf"), "--password-command", pw)
        assert r.returncode == 0, r.stderr
    return pw


@needs_rclone
def test_a_copy_cut_by_its_timeout_keeps_its_log(tmp_path):
    cut = tmp_path
    (cut / "src").mkdir()
    (cut / "dst").mkdir()
    for i in range(40):
        (cut / "src" / f"f{i:02d}.bin").write_bytes(os.urandom(100_000))
    (cut / "list").write_text("".join(f"f{i:02d}.bin\n" for i in range(40)))
    pw = _encrypted_alias(cut, os.urandom(18).hex())
    t0 = time.monotonic()
    res = rclone.run(["copy", str(cut / "src"), "gd:", "--files-from-raw", str(cut / "list"), "--no-traverse",
                      "--ignore-existing", "--use-json-log", "-v", "--bwlimit", "100k", "--transfers", "1"],
                     config=cut / "c.conf", timeout=5, **{PW_WORD + "_command": pw})
    took = time.monotonic() - t0
    landed = sorted(p.name for p in (cut / "dst").iterdir())
    whole = [n for n in landed if (cut / "dst" / n).read_bytes() == (cut / "src" / n).read_bytes()]
    said = rclone.copied(rclone.json_log(res.stdout + "\n" + res.stderr))
    assert res.returncode == 124 and res.stderr.rstrip().endswith("timed out after 5 s")
    assert 0 < len(whole) < 40
    assert sorted(said) == whole == landed, "every file that landed is named, and no partial one is left"
    assert took < 5 + rclone.TERM_GRACE_S


@needs_rclone
def test_config_password_by_environment(tmp_path):
    (tmp_path / "dst").mkdir()
    password = os.urandom(18).hex()
    _encrypted_alias(tmp_path, password)
    ok = rclone.run(["listremotes"], config=tmp_path / "c.conf", password_command=None, config_password=password)
    assert ok.returncode == 0 and "gd:" in ok.stdout
    assert password not in " ".join(ok.args)
    bad = rclone.run(["listremotes"], config=tmp_path / "c.conf", password_command=None, config_password="wrong")
    assert bad.returncode != 0


@needs_rclone
def test_a_command_past_its_timeout_comes_back_failed(tmp_path):
    enc = tmp_path / "enc.conf"
    enc.write_text("")
    r = raw("config", "encryption", "set", "--config", str(enc), "--password-command", "/bin/echo " + os.urandom(8).hex())
    assert r.returncode == 0
    t0 = time.monotonic()
    slow = rclone.run(["listremotes"], config=enc, password_command="/bin/sleep 1.5", timeout=0.3)
    assert slow.returncode == 124 and "timed out" in slow.stderr and time.monotonic() - t0 < 1.2
    # the password command outlives the rclone a timeout ended, so wait for it to end too
    time.sleep(max(0.0, 2.0 - (time.monotonic() - t0)))


def test_a_command_that_cannot_start(monkeypatch):
    res = rclone.run(["version"], config=None, password_command=None, rclone="/nonexistent/rclone")
    assert res.returncode == 127
