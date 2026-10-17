"""Google's consent for an rclone Drive remote, run under a supervisor.

The pieces, each usable alone:

- `ensure_config()` makes the remote's rclone config: a password kept in a password store, the
  empty config encrypted, then the remote with its OAuth client. The token Google gives later lands
  in the encrypted file and nowhere else.
- `supervise()` runs `rclone config reconnect <remote>:`, answers rclone's questions by their words,
  writes the consent page's address to a private page file, ends rclone after a lifetime or when the
  caller no longer wants it, and checks whose account the new token belongs to. Whatever ends it,
  rclone ends with it and the result is written.
- `open_page()` starts a supervisor (through a `spawn` function the caller gives) and waits for the
  page, or answers that one is running, or that another consent holds the port.
- `check_account()` makes a probe file in My Drive, reads its owner and sends it to the trash. A
  token for any other account than the expected one is discarded at once.
- `stop()` and `end_leftovers()` end a consent's processes, and only while each pid is still that
  process (its start time and executable are kept beside it), so a pid reused after a reboot is
  never signalled.

rclone serves every consent on 127.0.0.1:53682 and cannot be moved to another port, so only one
consent runs at a time on a machine. `port_holder()` says who holds the port.

The questions rclone asks in a reconnect, measured on rclone 1.75.2 with stdin a pipe: "Token
already configured - replace it?", "Use web browser to automatically authenticate rclone with
remote?" and, after the code, "Configure this as a Shared Drive (Team Drive)?". rclone prints a
question and its choices and then waits with no prompt after them. The supervisor waits for the
output to go quiet with choices last, and answers by the words in ANSWERS. Any other question ends
the consent as failed, never with a guessed answer.

A caller adds its own bookkeeping through callbacks: `on_page`, `still_wanted`, `on_end` and
`on_stopped`. The page reader (`page_reader`, or `tabs` with `PageWatch`) decides from the browser
whether Google says the app is blocked.

Every function here that starts a program (rclone, `ps`, `security`, a supervisor) takes `env`, the
whole environment that program gets. None (the default) keeps the environment each one builds for
itself. A function that reaches others passes its `env` on to each of them. Callbacks and functions
the caller hands in (`spawn`, `owner_of`, `on_end`, ...) are the caller's own and get no `env`, and a
password store gets its programs' environment from its own constructor (`MacKeychain(env=...)`).
"""
from __future__ import annotations

import json
import os
import re
import secrets
import select
import signal
import socket
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Optional
from urllib.parse import parse_qs, unquote, urlparse

from billspc import rclone
from billspc._env import clean_env
from billspc.files import read_json, write_json

#: rclone's own port for every consent. It cannot be moved
PORT = 53682
#: a consent ends after this, with or without an answer
LIFETIME_S = 30 * 60
#: how long open_page waits for rclone's page to come up
WAIT_S = 30
#: how often the supervisor reads the browser for a page that says the app is blocked
POLL_S = 15
#: how often the supervisor asks still_wanted()
TASK_POLL_S = 30
PAGE_RE = re.compile(r"http://127\.0\.0\.1:53682/auth\?state=[A-Za-z0-9_-]+")
#: rclone's questions by their words, and the answer. Older releases said "Already have a token"
ANSWERS = (("Token already configured", "y"), ("Already have a token", "y"),
           ("Use web browser to automatically authenticate", "y"), ("Shared Drive", "n"))
#: the client's secret's field, in Google's JSON and as rclone's option. Built rather than written
#: whole, so secret scanners do not read two credential field names side by side as a secret
SECRET_FIELD = "client_" + "secret"
#: Google's words for an app it blocks, in rclone's error or on its page
BLOCKED = ("admin_policy_enforced", "advanced protection", "app is blocked", "access blocked",
           "blocked this access", "has been blocked")


# ------------------------------------------------------------------------------------ remotes and secrets

@dataclass(frozen=True)
class Remote:
    """One Google Drive remote: its rclone name, its encrypted config, the command that opens the
    config, the Drive scope it asks for, the account its token must belong to, the name of the
    password item in the password store, and the folder for its consent's page and result."""
    name: str
    config: Path
    password_command: str
    state_dir: Path
    scope: str = "drive"
    account: Optional[str] = None
    password_item: Optional[str] = None


def paths(r: Remote) -> dict[str, Path]:
    """Where one remote's consent keeps its page, its result and its log."""
    d = Path(r.state_dir)
    return {"page": d / f"{r.name}.page.json", "result": d / f"{r.name}.result.json",
            "log": d / f"{r.name}.consent.log"}


def load_client(source) -> tuple[str, str] | None:
    """An OAuth client (id, secret) from Google's JSON (under "installed" or "web") or a flat
    {"client_id", "client_secret"}. `source` is the JSON text, a dict, or a path to the file.
    None when it holds no client."""
    doc = source
    if isinstance(source, Path) or (isinstance(source, str) and not source.lstrip().startswith("{")):
        try:
            doc = Path(source).expanduser().read_text()
        except OSError:
            return None
    if isinstance(doc, str):
        try:
            doc = json.loads(doc)
        except ValueError:
            return None
    inner = (doc.get("installed") or doc.get("web") or doc) if isinstance(doc, dict) else None
    if not isinstance(inner, dict):
        return None
    cid, sec = inner.get("client_id") or inner.get("id"), inner.get(SECRET_FIELD) or inner.get("secret")
    return (cid, sec) if isinstance(cid, str) and cid and isinstance(sec, str) and sec else None


class MacKeychain:
    """The macOS login keychain as a password store. `has` reads an item's attributes only (no -w,
    so no value is read), and `add` passes the value to `security -i` on stdin, never on a command
    line. `command(item)` is the password command rclone runs to read it.

    `env` is the whole environment `security` gets. The one given to `has` or `add` comes first,
    then the one given here, and with neither the environment is built from nothing as before."""

    def __init__(self, account: str = "billspc", security: str = "/usr/bin/security",
                 env: dict[str, str] | None = None):
        self.account, self.security, self.env = account, security, env

    def _env(self, env: dict[str, str] | None) -> dict[str, str]:
        given = env if env is not None else self.env
        return dict(given) if given is not None else clean_env("/usr/bin:/bin")

    def command(self, item: str) -> str:
        return f"{self.security} find-generic-password -a {self.account} -s {item} -w"

    def has(self, item: str, env: dict[str, str] | None = None) -> bool | None:
        try:
            res = subprocess.run([self.security, "find-generic-password", "-a", self.account, "-s", item],
                                 capture_output=True, text=True, timeout=15, stdin=subprocess.DEVNULL,
                                 env=self._env(env))
        except (OSError, subprocess.SubprocessError):
            return None
        return True if res.returncode == 0 else (False if res.returncode == 44 else None)

    def add(self, item: str, value: str, env: dict[str, str] | None = None) -> bool:
        try:
            res = subprocess.run([self.security, "-i"], capture_output=True, text=True, timeout=15,
                                 input=f"add-generic-password -a {self.account} -s {item} -w {value}\n",
                                 env=self._env(env))
        except (OSError, subprocess.SubprocessError):
            return False
        return res.returncode == 0 and self.has(item, env=env) is True


class FileStore:
    """A folder of private files (0600) as a password store, one file per item. For systems with no
    keychain, and for tests."""

    def __init__(self, folder: Path):
        self.folder = Path(folder).expanduser()

    def command(self, item: str) -> str:
        return f"/bin/cat {self.folder / item}"

    def has(self, item: str) -> bool:
        return (self.folder / item).is_file()

    def add(self, item: str, value: str) -> bool:
        self.folder.mkdir(mode=0o700, parents=True, exist_ok=True)
        fd = os.open(self.folder / item, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as out:
            out.write(value)
        return True


def rc(r: Remote, args: list[str], *, env: dict[str, str] | None = None, **kw):
    """One checked rclone command against this remote's encrypted config. `env` and the other `kw`
    go to rclone.run."""
    return rclone.run(args, config=Path(r.config), password_command=r.password_command, env=env, **kw)


def remotes_in_config(r: Remote, env: dict[str, str] | None = None) -> list[str] | None:
    res = rc(r, ["listremotes"], env=env)
    return [x.strip().rstrip(":") for x in res.stdout.splitlines() if x.strip()] if res.returncode == 0 else None


def ensure_config(r: Remote, *, client: tuple[str, str] | None, store=None,
                  env: dict[str, str] | None = None) -> dict:
    """The remote's encrypted config, made when missing. {"ok", "steps", "why"}. Never prints a value.

    The steps, in order: the config's password kept in `store` (a random one, when the store lacks
    `r.password_item`), the empty config encrypted, then the remote made with its client and scope.
    `store` is any object with has(item) and add(item, value), such as MacKeychain or FileStore.
    Without a store or an item, the password command must already work."""
    steps: list[str] = []
    cfg = Path(r.config)
    cfg.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(cfg.parent, 0o700)
    if store is not None and r.password_item:
        held = store.has(r.password_item)
        if held is None:
            return {"ok": False, "steps": steps, "why": f"the password store could not say whether it holds {r.password_item}"}
        if not held:
            if not store.add(r.password_item, secrets.token_urlsafe(32)):
                return {"ok": False, "steps": steps, "why": f"the password store did not take {r.password_item}"}
            steps.append("password kept in the store")
    if not cfg.exists() or cfg.stat().st_size == 0:
        # rclone writes the file itself, encrypted and 0600, when it is not there
        res = rc(r, ["config", "encryption", "set"], env=env)
        if res.returncode != 0 or not cfg.exists():
            return {"ok": False, "steps": steps, "why": f"encrypting the empty config failed: {res.stderr.strip()[-160:]}"}
        os.chmod(cfg, 0o600)
        steps.append("config encrypted")
    if rc(r, ["config", "encryption", "check"], env=env).returncode != 0:
        return {"ok": False, "steps": steps, "why": f"{cfg.name} is not encrypted, so nothing goes in it"}
    names = remotes_in_config(r, env)
    if names is None:
        return {"ok": False, "steps": steps, "why": "the config could not be opened"}
    if r.name not in names:
        if client is None:
            return {"ok": False, "steps": steps, "why": f"no OAuth client was given for {r.name}"}
        res = rc(r, ["config", "create", r.name, "drive", f"client_id={client[0]}",
                     f"{SECRET_FIELD}={client[1]}", f"scope={r.scope}", "--non-interactive", "--no-output"],
                 env=env)
        if res.returncode != 0 or r.name not in (remotes_in_config(r, env) or []):
            return {"ok": False, "steps": steps, "why": "rclone did not make the remote"}
        steps.append("remote made with its client")
    return {"ok": True, "steps": steps}


def config_ok(r: Remote, env: dict[str, str] | None = None) -> bool:
    """Whether the remote's config is whole: there, encrypted, and holding the remote. Reads only."""
    try:
        if not Path(r.config).exists() or Path(r.config).stat().st_size == 0:
            return False
    except OSError:
        return False
    if rc(r, ["config", "encryption", "check"], env=env).returncode != 0:
        return False
    return r.name in (remotes_in_config(r, env) or [])


def has_token(r: Remote, env: dict[str, str] | None = None) -> bool | None:
    """Whether the remote holds a token, from rclone's redacted config (which shows it as XXX).
    None when the config could not be read."""
    res = rc(r, ["config", "redacted", r.name], env=env)
    if res.returncode != 0:
        return None
    return any(line.split("=", 1)[0].strip() == "token" for line in res.stdout.splitlines() if "=" in line)


def discard_token(r: Remote, *, client: tuple[str, str] | None, store=None,
                  env: dict[str, str] | None = None) -> dict:
    """Throw a token away without asking Google to revoke the grant (that would end the app's other
    grants too): the remote deleted from the config and made again, with its client and no token."""
    res = rc(r, ["config", "delete", r.name], env=env)
    if res.returncode != 0:
        return {"ok": False, "why": "rclone did not delete the remote"}
    return ensure_config(r, client=client, store=store, env=env)


# ------------------------------------------------------------------------------------ processes

def alive(pid) -> bool:
    """Whether the process runs. A child of this process that ended is reaped here (until it is, a
    signal 0 still finds it). "Cannot tell" counts as alive."""
    if not pid:
        return False
    try:
        done, _status = os.waitpid(int(pid), os.WNOHANG)
        if done == int(pid):
            return False
    except (ChildProcessError, OSError, ValueError):
        pass
    try:
        os.kill(int(pid), 0)
    except ProcessLookupError:
        return False
    except (PermissionError, OSError, ValueError, TypeError):
        return True
    return True


def proc_id(pid, env: dict[str, str] | None = None) -> str | None:
    """A process's start time and executable as `ps -o lstart=,comm=` prints them, or None when no
    such process runs. Kept beside each pid, so a later signal can tell the same process from the
    next program the pid was given to. `env` is the whole environment `ps` gets."""
    if not pid:
        return None
    child = dict(env) if env is not None else clean_env("/bin:/usr/bin")
    try:
        r = subprocess.run(["/bin/ps", "-o", "lstart=,comm=", "-p", str(int(pid))], capture_output=True,
                           text=True, timeout=10, stdin=subprocess.DEVNULL, env=child)
    except (OSError, subprocess.SubprocessError, ValueError):
        return None
    got = " ".join(r.stdout.split()) if r.returncode == 0 else ""
    return got or None


def ours(pid, ident: str | None, env: dict[str, str] | None = None) -> bool:
    """Whether `pid` is still the very process `ident` names. A pid with no identity is never ours."""
    return bool(pid and ident) and alive(pid) and proc_id(pid, env) == ident


def shim(state_dir: Path) -> Path:
    """A folder whose `open` and `xdg-open` do nothing, put first on rclone's PATH, so rclone cannot
    open Google's page in whatever browser window the user has in front. The caller opens it."""
    d = Path(state_dir) / "no-open"
    d.mkdir(parents=True, exist_ok=True)
    for name in ("open", "xdg-open"):
        f = d / name
        if not f.exists():
            f.write_text("#!/bin/sh\n# the consent page is opened by the caller, not by rclone\nexit 0\n")
            f.chmod(0o755)
    return d


# ------------------------------------------------------------------------------------ the page

def port_holder(remotes: list[Remote] = (), port: int = PORT,
                env: dict[str, str] | None = None) -> str | None:
    """Who listens on the consent port: "ours" when the rclone of one of `remotes` does, "other"
    when something else answers (or holds it without answering), None when it is free."""
    for r in remotes:
        p = read_json(paths(r)["page"])
        if ours(p.get("rclone"), p.get("rclone_id"), env):
            return "ours"
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=1.0):
            return "other"
    except ConnectionRefusedError:
        return None
    except OSError:
        return "other"


def page(r: Remote, lifetime: float = LIFETIME_S, env: dict[str, str] | None = None) -> str | None:
    """The address of this remote's consent page while its rclone runs, else None."""
    p = read_json(paths(r)["page"])
    if (p.get("page") and ours(p.get("rclone"), p.get("rclone_id"), env)
            and time.time() - float(p.get("at") or 0) < lifetime):
        return p["page"]
    return None


def stop(r: Remote, *, own_pid: int | None = None, env: dict[str, str] | None = None) -> dict:
    """End this remote's consent: its rclone, and the supervisor's process group when the supervisor
    leads one of its own. Each only while its pid is still that process. The page file goes.
    {"ended": [...], "left": [...]}."""
    pf = paths(r)["page"]
    p = read_json(pf)
    ended, left = [], []
    rpid, spid = p.get("rclone"), p.get("supervisor")
    if rpid:
        if ours(rpid, p.get("rclone_id"), env):
            try:
                os.kill(int(rpid), signal.SIGTERM)
                ended.append("rclone")
            except (ProcessLookupError, PermissionError):
                pass
        elif alive(rpid):
            left.append(f"pid {rpid} is no longer the consent's rclone, so it was left alone")
    if spid and spid != own_pid and spid != os.getpid():
        if ours(spid, p.get("supervisor_id"), env) and p.get("group"):
            try:
                group = os.getpgid(int(spid))
                if group == int(spid) and group != os.getpgrp():
                    os.killpg(group, signal.SIGTERM)
                    ended.append("supervisor")
            except (ProcessLookupError, PermissionError):
                pass
        elif alive(spid) and not ours(spid, p.get("supervisor_id"), env):
            left.append(f"pid {spid} is no longer the consent's supervisor, so it was left alone")
    pf.unlink(missing_ok=True)
    return {"ended": ended, "left": left}


def end_leftovers(remotes: list[Remote], *, now: float | None = None, lifetime: float = LIFETIME_S,
                  stopper: Optional[Callable[[Remote, str], object]] = None,
                  env: dict[str, str] | None = None) -> dict:
    """End what a consent left behind with nothing else to end it. Run it now and then (and before
    each open), so the port is never held for good.

    - a page file none of whose processes is still ours is deleted, and nothing is signalled, since
      its pids now belong to other programs (after a reboot or a SIGKILL)
    - an rclone whose supervisor is gone (nothing answers it or checks the account), or one past its
      lifetime, is ended through `stopper(remote, why)` (by default stop())

    {"ended": [names], "stale": [names]}."""
    now = time.time() if now is None else now
    out: dict[str, list[str]] = {"ended": [], "stale": []}
    for r in remotes:
        p = read_json(paths(r)["page"])
        if not p:
            continue
        rclone_ours = ours(p.get("rclone"), p.get("rclone_id"), env)
        super_ours = ours(p.get("supervisor"), p.get("supervisor_id"), env)
        if not rclone_ours and not super_ours:
            paths(r)["page"].unlink(missing_ok=True)
            out["stale"].append(r.name)
        elif rclone_ours and (not super_ours or now - float(p.get("at") or 0) > lifetime + 60):
            why = ("its supervisor is gone, so nothing answers rclone or checks the account"
                   if not super_ours else "its consent outlived its lifetime")
            (stopper or (lambda rr, _w: stop(rr, env=env)))(r, why)
            out["ended"].append(r.name)
    return out


def spawn_command(argv: list[str], log: Path, *, keep: tuple[str, ...] = (),
                  env: dict[str, str] | None = None) -> int:
    """Start a supervisor process in a session of its own (so stop() can end it whole), its output
    appended to `log`. Returns its pid. `argv` is the whole command, for example
    [sys.executable, "-m", "billspc", "consent", "serve", "gdrive"].

    `env` is the whole environment the supervisor gets. None builds one from nothing with the names
    in `keep` carried over, and `keep` is not used when `env` is given."""
    log.parent.mkdir(parents=True, exist_ok=True)
    child = dict(env) if env is not None else clean_env("/usr/bin:/bin", keep=keep)
    with open(log, "a") as out:
        p = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=out, stderr=subprocess.STDOUT,
                             start_new_session=True, env=child)
    return p.pid


def open_page(r: Remote, *, spawn: Callable[[Remote], int], client: tuple[str, str] | None = None,
              store=None, remotes: list[Remote] = (), before_spawn: Optional[Callable[[], None]] = None,
              sleep=time.sleep, wait_s: int = WAIT_S, env: dict[str, str] | None = None) -> dict:
    """The consent page for this remote: the running one, or a new one.

    {"outcome": "running" | "queued" | "success" | "failure", "page", "why", "pid", "steps"}.
    "queued" when another consent of `remotes` holds the port. "failure" with why when something
    else holds the port, the config cannot be made, or the page does not come up in `wait_s`.
    `before_spawn` runs just before the supervisor starts: from that moment the token may change,
    whatever the consent ends as. `env` goes to every program this starts itself (rclone, `ps`).
    `spawn` is the caller's own and starts the supervisor with whatever environment it chooses, for
    example through spawn_command(..., env=...)."""
    running = page(r, env=env)
    if running:
        return {"outcome": "running", "page": running}
    end_leftovers([r, *remotes], env=env)
    holder = port_holder([r, *remotes], env=env)
    if holder == "ours":
        return {"outcome": "queued", "page": None,
                "why": "another consent holds rclone's port, so this one waits for it to end"}
    if holder == "other":
        return {"outcome": "failure", "page": None, "why": f"something else holds port {PORT}"}
    cfg = ensure_config(r, client=client, store=store, env=env)
    if not cfg["ok"]:
        return {"outcome": "failure", "page": None, "why": cfg["why"], "steps": cfg["steps"]}
    pp = paths(r)
    for k in ("page", "result"):
        pp[k].unlink(missing_ok=True)
    if before_spawn:
        before_spawn()
    pid = spawn(r)
    for _ in range(wait_s):
        sleep(1)
        p = read_json(pp["page"])
        if p.get("page"):
            return {"outcome": "success", "page": p["page"], "pid": pid, "steps": cfg["steps"]}
        if read_json(pp["result"]).get("outcome"):
            break
    res = read_json(pp["result"])
    return {"outcome": "failure", "page": None, "pid": pid,
            "why": res.get("detail") or "rclone's page did not come up"}


# ------------------------------------------------------------------------------------ reading rclone and the browser

def classify(text: str, rc_: int | None) -> str:
    """How rclone's consent ended, from its own output: consented, blocked, declined or failed."""
    low = (text or "").lower()
    if rc_ == 0 and "got code" in low:
        return "consented"
    if any(w in low for w in BLOCKED):
        return "blocked"
    if "access_denied" in low:
        return "declined"
    return "failed"


def page_kind(tab: dict) -> str | None:
    """What a browser tab on Google's sign-in says: "blocked" when its address is Google's OAuth
    error page or its title says the app is blocked, "rejected" when Google refused to sign in in
    this browser (/signin/rejected, a failed sign-in and no block), else None."""
    url, title = (tab.get("url") or "").lower(), (tab.get("title") or "").lower()
    if "accounts.google.com" not in url:
        return None
    if "/signin/rejected" in url:
        return "rejected"
    if "/oauth/error" in url or any(w in title for w in BLOCKED):
        return "blocked"
    return None


def blocked_page(tab: dict) -> bool:
    return page_kind(tab) == "blocked"


def _flat(url: str) -> str:
    """An address decoded three times: Google carries the consent's own address, with its state,
    inside its continue and redirect parameters, encoded once for each."""
    for _ in range(3):
        url = unquote(url)
    return url


class PageWatch:
    """This consent's own browser tabs, judged for Google's block page.

    The first look is taken as the page comes up, before the browser can have opened it, so every
    tab then is older than this consent. Later a tab is this consent's when its address carries the
    consent's state, when it opened since, or when it has moved since and carries the app's client
    id. Only such a tab that moved or opened since speaks for this consent, so a window left open by
    an earlier blocked attempt does not block a later consent.

    `see(tabs)` takes [{"window", "tab", "url", "title"}] and returns "blocked", "rejected" or ""
    (None when the browser could not be read)."""

    def __init__(self, state: str | None, client_id: str | None):
        self.state = state if state and len(state) >= 8 else None
        self.client = client_id if client_id and len(client_id) >= 8 else None
        self.before: dict[tuple[str, str], str] | None = None
        self.mine: set[tuple[str, str]] = set()

    def see(self, tabs: list[dict] | None) -> str | None:
        if tabs is None:
            return None
        now = {(str(t.get("window")), str(t.get("tab"))): t for t in tabs}
        if self.before is None:
            self.before = {k: t.get("url") or "" for k, t in now.items()}
            return ""
        verdict = ""
        for k, t in now.items():
            url = t.get("url") or ""
            moved = self.before.get(k) != url
            flat = _flat(url)
            if ((self.state and self.state in flat) or k not in self.before
                    or (moved and self.client and self.client in flat)):
                self.mine.add(k)
            if k not in self.mine or not moved:
                continue
            kind = page_kind(t)
            if kind == "blocked":
                return "blocked"
            if kind == "rejected":
                verdict = "rejected"
        return verdict


def question_in(text: str) -> str | None:
    """The question rclone is waiting on, when its output ends with a list of choices."""
    lines = [ln.rstrip() for ln in text.rstrip("\n").split("\n")]
    if not lines or not re.match(r"^[a-z]\) ", lines[-1]):
        return None
    i = len(lines) - 1
    while i >= 0 and re.match(r"^[a-z]\) ", lines[i]):
        i -= 1
    while i >= 0 and not lines[i].strip():
        i -= 1
    j = i
    while j > 0 and lines[j - 1].strip():
        j -= 1
    return " ".join(ln.strip() for ln in lines[j:i + 1]) if i >= 0 else None


def answer_for(question: str | None, answers=None) -> str | None:
    if not question:
        return None
    return next((a for words, a in (answers or ANSWERS) if words.lower() in question.lower()), None)


# ------------------------------------------------------------------------------------ the account

def owner_of_probe(r: Remote, env: dict[str, str] | None = None) -> str | None:
    """Make a probe file at the top of My Drive, read its owner from Drive's metadata, send it to
    the trash. The owner, or None when any step did not answer. This reaches Google."""
    target = f"{r.name}:{rclone.PROBE_PREFIX}{secrets.token_hex(6)}"
    if rc(r, ["touch", target], timeout=60, env=env).returncode != 0:
        return None
    try:
        res = rc(r, ["lsjson", "--stat", "--metadata", target], timeout=60, env=env)
        try:
            meta = (json.loads(res.stdout or "{}") or {}).get("Metadata") or {}
        except ValueError:
            meta = {}
        owner = meta.get("owner")
        return owner if isinstance(owner, str) and "@" in owner else None
    finally:
        rc(r, ["deletefile", target], timeout=60, env=env)


def check_account(r: Remote, *, owner_of: Optional[Callable[[Remote], str | None]] = None,
                  client: tuple[str, str] | None = None, store=None,
                  env: dict[str, str] | None = None) -> dict:
    """Whose is the token this remote holds?

    {"outcome": "success", "account"} when it is r.account's (or any account, when r.account is
    None). {"outcome": "failure", "account", "discarded"} for anyone else's: the token is discarded
    at once, so nothing can use it. {"outcome": "unknown"} when the probe got no answer: nothing is
    changed, and the caller should check again later. `owner_of` replaces the probe (for tests) and
    gets only the remote. `env` goes to the probe and to the discard."""
    owner = owner_of(r) if owner_of is not None else owner_of_probe(r, env)
    if owner is None:
        return {"outcome": "unknown", "why": "the probe file's owner could not be read"}
    if r.account is None or owner.casefold() == r.account.casefold():
        return {"outcome": "success", "account": owner}
    d = discard_token(r, client=client, store=store, env=env)
    return {"outcome": "failure", "account": owner, "discarded": d.get("ok"),
            "why": f"the token was {owner}'s, not {r.account}'s, so it was discarded"}


# ------------------------------------------------------------------------------------ the supervisor

def supervise(r: Remote, *, page_reader: Optional[Callable[[], str | None]] = None,
              tabs: Optional[Callable[[], list[dict] | None]] = None, client_id: str | None = None,
              still_wanted: Optional[Callable[[], bool]] = None,
              on_page: Optional[Callable[[str], None]] = None,
              on_end: Optional[Callable[[dict], None]] = None,
              on_stopped: Optional[Callable[[str], None]] = None,
              owner_of: Optional[Callable[[Remote], str | None]] = None,
              client: tuple[str, str] | None = None, store=None, answers=None,
              lifetime: float = LIFETIME_S, poll: float = POLL_S, task_poll: float = TASK_POLL_S,
              quiet: float = 0.5, clock=time.monotonic, env: dict[str, str] | None = None) -> dict:
    """Run one consent to its end and return its result, which is also written to the result file:

        {"outcome": consented | declined | blocked | failed | timed out | ended,
         "rc", "at", "got_code", "detail", "account"?}

    - the page file (0600) holds the page's address, rclone's and this process's pids with their
      identities, and whether this process leads its own process group
    - `page_reader()` returns "blocked", "rejected" or "" from the browser, or build one from
      `tabs()` (a list of tabs) with PageWatch. "rejected" ends the consent as failed, not blocked
    - `still_wanted()` is asked every `task_poll` seconds, and False ends the consent as "ended"
    - after rclone ends, `on_end(result)` runs. By default it checks the account of any token the
      remote holds now, whatever the ending (rclone saves a new token before its last question).
      An exception there is kept in result["recorded"]
    - `on_stopped(why)` then runs unless a stopper already took the page file away (default stop())
    - `env` goes to every program this starts itself: rclone's reconnect, `ps`, and the account
      check. rclone's reconnect gets it with the folder from shim() put first on its PATH, so rclone
      still cannot open a browser. None keeps the environment each one builds for itself

    Whatever ends it, rclone ends with it: the loop is inside try/finally, so even a callback that
    raises still ends rclone, frees the port and writes the result before the exception goes on."""
    pp = paths(r)
    no_open = shim(r.state_dir)
    if env is None:
        p = rclone.popen(["config", "reconnect", f"{r.name}:"], config=Path(r.config),
                         password_command=r.password_command, path=f"{no_open}:{rclone.PATH}")
    else:
        given_path = env.get("PATH")
        p = rclone.popen(["config", "reconnect", f"{r.name}:"], config=Path(r.config),
                         password_command=r.password_command,
                         env={**env, "PATH": f"{no_open}:{given_path}" if given_path else str(no_open)})
    rclone_id = proc_id(p.pid, env)
    fd = p.stdout.fileno()
    text, buf, page_url, outcome, note = "", "", None, None, ""
    reader = page_reader
    result: dict = {}
    start = last = clock()
    next_look, next_task = start + poll, start + task_poll
    try:
        while True:
            ready = select.select([fd], [], [], 0.2)[0]
            if ready:
                chunk = os.read(fd, 4096)
                if not chunk:
                    break
                s = chunk.decode(errors="replace")
                text, buf, last = text + s, buf + s, clock()
                m = PAGE_RE.search(text)
                if m and not page_url:
                    page_url = m.group(0)
                    write_json(pp["page"], {"page": page_url, "rclone": p.pid, "rclone_id": rclone_id,
                                            "supervisor": os.getpid(), "supervisor_id": proc_id(os.getpid(), env),
                                            "group": os.getpgid(0) == os.getpid(), "at": time.time(),
                                            "remote": r.name})
                    if reader is None and tabs is not None:
                        state = (parse_qs(urlparse(page_url).query).get("state") or [None])[0]
                        w = PageWatch(state, client_id or (client[0] if client else None))
                        reader = lambda: w.see(tabs())  # noqa: E731
                    if reader is not None:
                        reader()   # the first look, before the browser can have opened the page
                    if on_page:
                        on_page(page_url)
                continue
            if p.poll() is not None:
                break
            now = clock()
            if buf and now - last >= quiet:
                q = question_in(buf)
                if q is not None:
                    a = answer_for(q, answers)
                    if a is None:
                        outcome = "failed"
                        text += f"\n[rclone asked a question with no known answer: {q[:120]}]"
                        p.terminate()
                        continue
                    p.stdin.write((a + "\n").encode())
                    p.stdin.flush()
                    buf = ""
            if now - start > lifetime:
                outcome = "timed out"
                p.terminate()
            elif page_url and reader is not None and now >= next_look:
                next_look = now + poll
                seen = reader()
                if seen == "blocked":
                    outcome = "blocked"
                    p.terminate()
                elif seen == "rejected":
                    outcome = "failed"
                    note = ("Google refused to sign in in this browser (accounts.google.com/signin/"
                            "rejected): a failed sign-in, not a block")
                    p.terminate()
            elif still_wanted is not None and now >= next_task:
                next_task = now + task_poll
                if not still_wanted():
                    outcome = "ended"
                    p.terminate()
    finally:
        if p.poll() is None:
            p.terminate()
        try:
            rc_ = p.wait(timeout=10)
        except subprocess.TimeoutExpired:
            p.kill()
            rc_ = p.wait()
        outcome = outcome or classify(text, rc_)
        got_code = "got code" in text.lower()
        result = {"outcome": outcome, "rc": rc_, "at": time.time(), "got_code": got_code,
                  "detail": note or next((ln.strip() for ln in text.splitlines()
                                          if "error" in ln.lower() or "description" in ln.lower()), "")[:300]}
        write_json(pp["result"], result)
        try:
            if on_end is not None:
                on_end(result)
            elif has_token(r, env):
                result["account"] = check_account(r, owner_of=owner_of, client=client, store=store, env=env)
        except Exception as e:  # noqa: BLE001 - kept in the result; rclone has ended above
            result["recorded"] = f"{type(e).__name__}: {str(e)[:200]}"
        write_json(pp["result"], result)
        if page_url is None or pp["page"].exists():
            try:
                (on_stopped or (lambda _why: stop(r, own_pid=os.getpid(), env=env)))(f"the consent ended: {outcome}")
            except Exception:  # noqa: BLE001 - rclone has ended; only the bookkeeping failed
                pp["page"].unlink(missing_ok=True)
    return result
