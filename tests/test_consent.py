"""Google's consent, run through real rclone against a stand-in Google on loopback, and every way it
can end.

rclone runs for real: the encrypted config, the remote made with its client, `config reconnect` with
its own questions, its page on 127.0.0.1:53682 and the token it saves. Google is a small server on
another loopback port (the remote's auth_url and token_url point at it), so nothing here reaches
Google. The account check's owner is handed in. The browser is the test, following the page's
redirects.
"""
from __future__ import annotations

import http.server
import json
import os
import secrets
import signal
import socket
import stat
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

import pytest

from conftest import needs_rclone, raw
from billspc import consent as cs
from billspc._env import clean_env
from billspc.files import read_json, write_json

ACCOUNT = "owner@example.org"
CID = "test-" + secrets.token_hex(6) + ".apps.googleusercontent.com"
CSECRET = secrets.token_urlsafe(18)
TOKENS: list[str] = []


class FakeGoogle(http.server.BaseHTTPRequestHandler):
    """Google's two OAuth endpoints as rclone uses them: the consent page sends the browser back with
    a code (or an error), and the token endpoint trades the code for a token."""
    mode = "ok"

    def log_message(self, *a):
        pass

    def do_GET(self):
        q = dict(urllib.parse.parse_qsl(urllib.parse.urlparse(self.path).query))
        extra = {"ok": {"code": "c" + secrets.token_hex(6)},
                 "denied": {"error": "access_denied", "error_description": "the person said no"},
                 "policy": {"error": "admin_policy_enforced",
                            "error_description": "the app is blocked for this account"}}[FakeGoogle.mode]
        self.send_response(302)
        self.send_header("Location", q["redirect_uri"] + "?" + urllib.parse.urlencode({"state": q["state"], **extra}))
        self.end_headers()

    def do_POST(self):
        self.rfile.read(int(self.headers.get("Content-Length") or 0))
        tok = {"access_token": "a" + secrets.token_hex(12), "refresh_token": "r" + secrets.token_hex(12),
               "token_type": "Bearer", "expires_in": 3600}
        TOKENS.extend([tok["access_token"], tok["refresh_token"]])
        body = json.dumps(tok).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def port_free() -> bool:
    try:
        with socket.create_connection(("127.0.0.1", cs.PORT), timeout=0.5):
            return False
    except OSError:
        return True


@pytest.fixture(scope="module")
def google():
    if not port_free():
        pytest.skip(f"port {cs.PORT} is in use, and rclone serves every consent there")
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), FakeGoogle)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield srv.server_address[1]
    srv.shutdown()


class World:
    def __init__(self, tmp: Path, gport: int, name: str = "gd"):
        self.tmp, self.gport = tmp, gport
        self.store = cs.FileStore(tmp / "pw")
        item = f"billspc-{name}"
        self.remote = cs.Remote(name=name, config=tmp / "rclone" / f"{name}.conf",
                                password_command=self.store.command(item), state_dir=tmp / "state" / "consent",
                                account=ACCOUNT, password_item=item)
        self.client = (CID, CSECRET)

    def make(self) -> dict:
        made = cs.ensure_config(self.remote, client=self.client, store=self.store)
        self.point_at_fake()
        return made

    def point_at_fake(self):
        """The test's own step: the remote's OAuth endpoints are the stand-in, never Google."""
        r = self.remote
        out = raw("config", "update", r.name, f"auth_url=http://127.0.0.1:{self.gport}/auth",
                  f"token_url=http://127.0.0.1:{self.gport}/token", "config_refresh_token=false",
                  "--non-interactive", "--no-output", "--config", str(r.config), "--password-command",
                  r.password_command)
        assert out.returncode == 0, out.stderr

    def redacted(self) -> str:
        return cs.rc(self.remote, ["config", "redacted", self.remote.name]).stdout


@pytest.fixture
def world(tmp_path, google):
    FakeGoogle.mode = "ok"
    w = World(tmp_path, google)
    yield w
    # no consent outlives a test: rclone would hold the machine's one consent port
    cs.stop(w.remote)
    for _ in range(50):
        if port_free():
            break
        time.sleep(0.1)


def browse(page: str) -> int:
    try:
        with urllib.request.urlopen(page, timeout=20) as resp:
            return resp.status
    except urllib.error.HTTPError as e:
        return e.code
    except OSError:
        return -1


class Run:
    """supervise() in a thread, with the page's address handed back when it comes up."""

    def __init__(self, w: World, **kw):
        self.page, self.result, self.error = None, None, None
        self.ready = threading.Event()
        kw.setdefault("owner_of", lambda r: ACCOUNT)
        kw.setdefault("quiet", 0.3)

        def on_page(url):
            self.page = url
            self.ready.set()

        def go():
            try:
                self.result = cs.supervise(w.remote, on_page=on_page, client=w.client, store=w.store, **kw)
            except Exception as e:  # noqa: BLE001 - a test reads what it left
                self.error = e
            finally:
                self.ready.set()
        self.thread = threading.Thread(target=go, daemon=True)
        self.thread.start()
        self.ready.wait(30)

    def finish(self, timeout: float = 40.0):
        self.thread.join(timeout)
        assert not self.thread.is_alive()
        return self.result


# ---------------------------------------------------------------- the config

@needs_rclone
def test_config_is_made_in_order(world):
    made = cs.ensure_config(world.remote, client=world.client, store=world.store)
    raw_text = world.remote.config.read_text(errors="replace")
    assert made == {"ok": True, "steps": ["password kept in the store", "config encrypted", "remote made with its client"]}
    assert raw_text.startswith("# Encrypted rclone configuration File")
    assert CSECRET not in raw_text and CID not in raw_text
    assert "client_id = XXX" in world.redacted() and "scope = drive" in world.redacted()
    assert cs.ensure_config(world.remote, client=world.client, store=world.store) == {"ok": True, "steps": []}
    assert cs.config_ok(world.remote) and cs.has_token(world.remote) is False
    assert stat.S_IMODE(os.stat(world.remote.config.parent).st_mode) == 0o700
    assert stat.S_IMODE(os.stat(world.remote.config).st_mode) == 0o600
    other = World(world.tmp, world.gport, name="other")
    nope = cs.ensure_config(other.remote, client=None, store=other.store)
    assert not nope["ok"] and "no OAuth client" in nope["why"]
    assert "other" not in (cs.remotes_in_config(other.remote) or [])


# ---------------------------------------------------------------- the ways a consent ends

@needs_rclone
def test_consent_given(world):
    world.make()
    run = Run(world)
    assert run.page and cs.PAGE_RE.fullmatch(run.page)
    pf = cs.paths(world.remote)["page"]
    p = read_json(pf)
    assert stat.S_IMODE(pf.stat().st_mode) == 0o600 and "rclone" in p["rclone_id"] and p["supervisor_id"]
    assert cs.page(world.remote) == run.page
    assert cs.port_holder([world.remote]) == "ours"
    assert browse(run.page) == 200
    res = run.finish()
    assert res["outcome"] == "consented" and res["got_code"]
    assert res["account"] == {"outcome": "success", "account": ACCOUNT}
    assert "token = XXX" in world.redacted()
    assert not any(t in world.remote.config.read_text(errors="replace") for t in TOKENS)
    assert cs.page(world.remote) is None and not pf.exists() and port_free()
    assert read_json(cs.paths(world.remote)["result"])["outcome"] == "consented"


@needs_rclone
def test_a_probe_with_no_answer_leaves_the_token_unchecked(world):
    world.make()
    run = Run(world, owner_of=lambda r: None)
    browse(run.page)
    res = run.finish()
    assert res["outcome"] == "consented" and res["account"]["outcome"] == "unknown"
    assert "token = XXX" in world.redacted()
    assert cs.check_account(world.remote, owner_of=lambda r: ACCOUNT)["outcome"] == "success"


@needs_rclone
def test_another_accounts_token_is_discarded_even_after_an_unknown_question(world):
    world.make()
    # without the Shared Drive answer, the question after the code is one the supervisor does not know
    answers = tuple(a for a in cs.ANSWERS if a[0] != "Shared Drive")
    run = Run(world, owner_of=lambda r: "someone@example.org", answers=answers)
    browse(run.page)
    res = run.finish()
    assert res["outcome"] == "failed" and res["got_code"]
    assert res["account"]["outcome"] == "failure" and res["account"]["discarded"]
    assert "token" not in world.redacted() and "client_id = XXX" in world.redacted()


@needs_rclone
def test_declined(world):
    world.make()
    FakeGoogle.mode = "denied"
    run = Run(world)
    browse(run.page)
    res = run.finish()
    assert res["outcome"] == "declined" and "account" not in res


@needs_rclone
def test_blocked_by_google_in_rclones_error(world):
    world.make()
    FakeGoogle.mode = "policy"
    run = Run(world)
    browse(run.page)
    assert run.finish()["outcome"] == "blocked"


@needs_rclone
def test_blocked_or_rejected_on_the_page(world):
    world.make()
    assert Run(world, page_reader=lambda: "blocked", poll=1.0).finish()["outcome"] == "blocked"
    res = Run(world, page_reader=lambda: "rejected", poll=1.0).finish()
    assert res["outcome"] == "failed" and "not a block" in res["detail"]


@needs_rclone
def test_tabs_are_judged_by_a_page_watch(world):
    world.make()
    looks = []

    def tabs():
        looks.append(1)
        if len(looks) == 1:
            return []
        return [{"window": "1", "tab": "1", "title": "Access blocked",
                 "url": "https://accounts.google.com/signin/oauth/error/v2?client_id=" + CID}]
    res = Run(world, tabs=tabs, poll=1.0).finish()
    assert res["outcome"] == "blocked" and len(looks) >= 2


@needs_rclone
def test_never_given_and_no_longer_wanted(world):
    world.make()
    res = Run(world, lifetime=3.0).finish()
    assert res["outcome"] == "timed out" and "account" not in res and port_free()
    res = Run(world, still_wanted=lambda: False, task_poll=1.0).finish()
    assert res["outcome"] == "ended"


@needs_rclone
def test_a_callback_that_raises_still_ends_rclone(world):
    world.make()

    def boom():
        raise RuntimeError("planted")
    run = Run(world, still_wanted=boom, task_poll=1.0)
    run.thread.join(40)
    assert isinstance(run.error, RuntimeError)
    assert port_free() and cs.page(world.remote) is None
    assert read_json(cs.paths(world.remote)["result"])["outcome"] == "failed"


@needs_rclone
def test_on_end_and_on_stopped_replace_the_defaults(world):
    world.make()
    seen, stopped = [], []
    run = Run(world, on_end=lambda result: seen.append(result["outcome"]),
              on_stopped=lambda why: (stopped.append(why), cs.stop(world.remote)))
    browse(run.page)
    res = run.finish()
    assert seen == ["consented"] and stopped == ["the consent ended: consented"] and "account" not in res


# ---------------------------------------------------------------- the port, the page file and leftovers

@needs_rclone
def test_a_port_held_by_something_else(world):
    holder = socket.socket()
    holder.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    holder.bind(("127.0.0.1", cs.PORT))
    holder.listen(1)   # it never accepts: a full backlog still reads as held
    try:
        assert cs.port_holder([world.remote]) == "other"
        out = cs.open_page(world.remote, spawn=lambda r: pytest.fail("nothing may start"), client=world.client,
                           store=world.store)
        assert out["outcome"] == "failure" and str(cs.PORT) in out["why"]
    finally:
        holder.close()
    assert cs.port_holder([world.remote]) is None


@needs_rclone
def test_one_consent_at_a_time_and_leftovers(world):
    other = World(world.tmp, world.gport, name="backup")
    sleeper = subprocess.Popen(["/bin/sleep", "30"], env=clean_env("/bin"))
    page_off = cs.paths(other.remote)["page"]
    try:
        write_json(page_off, {"page": "http://127.0.0.1:53682/auth?state=x", "rclone": sleeper.pid,
                              "rclone_id": cs.proc_id(sleeper.pid), "supervisor": os.getpid(),
                              "supervisor_id": cs.proc_id(os.getpid()), "at": time.time()})
        q = cs.open_page(world.remote, spawn=lambda r: pytest.fail("nothing may start"), remotes=[other.remote],
                         client=world.client, store=world.store)
        assert q["outcome"] == "queued"
        # pids that now belong to other programs: nothing is signalled, and the file goes
        write_json(page_off, {"page": "x", "rclone": sleeper.pid, "rclone_id": "Thu Jan 1 00:00:00 2026 /usr/bin/rclone",
                              "supervisor": sleeper.pid, "supervisor_id": "Thu Jan 1 00:00:00 2026 /usr/bin/python3",
                              "group": True, "at": time.time() - cs.LIFETIME_S - 120})
        stale = cs.end_leftovers([other.remote])
        time.sleep(0.3)
        assert stale["stale"] == ["backup"] and sleeper.poll() is None and not page_off.exists()
        # the same process as rclone, whose supervisor is gone: ended at once
        write_json(page_off, {"page": "x", "rclone": sleeper.pid, "rclone_id": cs.proc_id(sleeper.pid),
                              "supervisor": 999_999, "supervisor_id": "Thu Jan 1 00:00:00 2026 /usr/bin/python3",
                              "at": time.time()})
        left = cs.end_leftovers([other.remote])
        sleeper.wait(timeout=10)
        assert left["ended"] == ["backup"] and sleeper.returncode is not None
    finally:
        if sleeper.poll() is None:
            sleeper.kill()
        page_off.unlink(missing_ok=True)


@needs_rclone
def test_the_cli_serves_the_page_in_its_own_process(world):
    w = world
    cfg = w.tmp / "config.toml"
    cfg.write_text(f"""
[billspc]
state_dir = "{w.tmp / 'state'}"
password_store = "files"
password_dir = "{w.tmp / 'pw'}"

[remotes.gd]
config = "{w.remote.config}"
account = "{ACCOUNT}"
""")
    w.make()
    argv = [sys.executable, "-m", "billspc", "--config", str(cfg), "consent", "gd"]
    out = cs.open_page(w.remote, spawn=lambda r: cs.spawn_command(argv, cs.paths(r)["log"], keep=("PYTHONPATH",)),
                       client=w.client, store=w.store, sleep=time.sleep)
    p = read_json(cs.paths(w.remote)["page"])
    assert out["outcome"] == "success" and cs.page(w.remote) == out["page"], out
    assert p["supervisor"] != os.getpid() and p["group"] is True
    assert cs.open_page(w.remote, spawn=lambda r: pytest.fail("one runs"))["outcome"] == "running"
    stopped = cs.stop(w.remote)
    time.sleep(1.5)
    assert set(stopped["ended"]) == {"rclone", "supervisor"}
    assert not cs.alive(p["rclone"]) and not cs.alive(p["supervisor"]) and port_free()
    assert "Open this page to give consent" in cs.paths(w.remote)["log"].read_text()


# ---------------------------------------------------------------- reading rclone and the browser

def test_classify_and_answers():
    assert cs.classify("NOTICE: Got code\n", 0) == "consented"
    assert cs.classify("x access_denied y", 1) == "declined"
    assert cs.classify("Description: admin_policy_enforced", 1) == "blocked"
    assert cs.classify("boom", 1) == "failed"
    q = cs.question_in("Use web browser to automatically authenticate rclone with remote?\n * Say Y\n\ny) Yes (default)\nn) No\n")
    assert cs.answer_for(q) == "y"
    assert cs.answer_for(cs.question_in("NOTICE: Got code\nConfigure this as a Shared Drive (Team Drive)?\n\ny) Yes\nn) No (default)\n")) == "n"
    assert cs.answer_for(cs.question_in("Token already configured - replace it?\ny) Yes (default)\nn) No\n")) == "y"
    assert cs.answer_for(cs.question_in("Delete everything?\n\ny) Yes\nn) No\n")) is None
    assert cs.question_in("still talking\n") is None


def test_page_kind():
    assert cs.blocked_page({"url": "https://accounts.google.com/signin/oauth/error/v2?authError=x", "title": ""})
    assert cs.blocked_page({"url": "https://accounts.google.com/o/oauth2/auth", "title": "Access blocked"})
    assert not cs.blocked_page({"url": "https://accounts.google.com/o/oauth2/auth", "title": "Sign in"})
    assert not cs.blocked_page({"url": "https://example.org/oauth/error", "title": ""})
    assert cs.page_kind({"url": "https://accounts.google.com/signin/rejected", "title": ""}) == "rejected"


def test_page_watch_counts_only_this_consents_tabs():
    w = cs.PageWatch("st" + secrets.token_hex(8), CID)
    old_block = {"window": "1", "tab": "11", "title": "Access blocked",
                 "url": f"https://accounts.google.com/signin/oauth/error/v2?client_id={CID}"}
    other = {"window": "2", "tab": "21", "url": "https://example.org/x", "title": "x"}
    assert w.see([old_block, other]) == ""
    assert w.see([old_block, other]) == "", "an earlier blocked attempt's window blocks nothing later"
    assert w.see(None) is None
    other_site = {"window": "2", "tab": "21", "title": "Access blocked",
                  "url": "https://accounts.google.com/signin/oauth/error/v2?client_id=x.apps"}
    assert w.see([old_block, other_site]) == ""
    ours_tab = {"window": "3", "tab": "31", "title": "Sign in",
                "url": "https://accounts.google.com/o/oauth2/auth?" + urllib.parse.urlencode({"client_id": CID, "state": w.state})}
    assert w.see([old_block, other_site, ours_tab]) == ""
    ours_blocked = {**ours_tab, "url": "https://accounts.google.com/signin/oauth/error/v2?authError=x", "title": "Access blocked"}
    assert w.see([old_block, other_site, ours_blocked]) == "blocked"
    w2 = cs.PageWatch("st" + secrets.token_hex(8), CID)
    w2.see([old_block])
    rejected = {"window": "4", "tab": "41", "url": "https://accounts.google.com/signin/rejected?rrk=46", "title": "x"}
    assert w2.see([old_block, rejected]) == "rejected"


# ---------------------------------------------------------------- clients and password stores

def test_load_client(tmp_path):
    field = cs.SECRET_FIELD
    installed = json.dumps({"installed": {"client_id": CID, field: CSECRET, "project_id": "p"}})
    assert cs.load_client(installed) == (CID, CSECRET)
    assert cs.load_client({"client_id": CID, field: CSECRET}) == (CID, CSECRET)
    f = tmp_path / "client.json"
    f.write_text(installed)
    assert cs.load_client(f) == (CID, CSECRET) and cs.load_client(str(f)) == (CID, CSECRET)
    assert cs.load_client("{not json") is None and cs.load_client({"installed": {"client_id": CID}}) is None
    assert cs.load_client(tmp_path / "missing.json") is None


def test_mac_keychain_passes_the_value_on_stdin(monkeypatch):
    calls = []

    def fake_run(argv, *a, **k):
        calls.append((list(argv), k.get("input")))
        return subprocess.CompletedProcess(argv, 0, "", "")
    monkeypatch.setattr(cs.subprocess, "run", fake_run)
    kc = cs.MacKeychain(account="someone")
    value = secrets.token_urlsafe(32)
    assert kc.add("item-1", value)
    assert all(value not in " ".join(argv) for argv, _ in calls)
    assert calls[0][0] == ["/usr/bin/security", "-i"] and value in calls[0][1]
    assert kc.command("item-1") == "/usr/bin/security find-generic-password -a someone -s item-1 -w"


def test_file_store(tmp_path):
    s = cs.FileStore(tmp_path / "pw")
    assert not s.has("x") and s.add("x", "v") and s.has("x")
    assert stat.S_IMODE((tmp_path / "pw" / "x").stat().st_mode) == 0o600
    assert subprocess.run(s.command("x").split(), capture_output=True, text=True).stdout == "v"


def test_process_identity():
    me = cs.proc_id(os.getpid())
    assert me and cs.ours(os.getpid(), me)
    assert not cs.ours(os.getpid(), None) and not cs.ours(None, me)
    assert not cs.ours(os.getpid(), "Thu Jan 1 00:00:00 2026 /usr/bin/elsewhere")
    child = subprocess.Popen(["/bin/sleep", "0.1"])
    child.wait()
    assert not cs.alive(child.pid) and cs.proc_id(child.pid) is None
    assert signal.SIGTERM  # stop() signals with TERM only
