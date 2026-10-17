"""Run rclone with every command line checked against an allowlist first.

rclone can empty a whole Drive in one command (`sync` against an empty folder, `purge`,
`--delete-excluded`). So nothing here types an rclone command line freely. Each command is checked
by `check()`, and anything outside the allowlist raises `Refused` before it runs.

What is allowed:

- reading: `version`, `about`, `lsjson`, `check`, `listremotes`, `config redacted` (which prints
  secrets as XXX)
- uploading: `copy` of a listed set (`--files-from`), from an absolute local folder to a remote
- the consent's own config steps: `config create`, `config delete`, `config reconnect`,
  `config encryption set` and `config encryption check`
- `dedupe` in the two modes that never choose between two different files (`list`, `skip`)
- the account check's probe file: `touch` and `deletefile` of that one file, by its exact name

Everything else is refused because it is not listed (`sync`, `bisync`, `move`, `delete`, `purge`,
`rmdirs`, `cleanup`, `mount`, `serve`, `config show`, `config dump`, `config disconnect`, ...).

Each command also carries only the flags listed for it in FLAGS. A refused-by-name list misses the
next flag rclone adds, and some read commands write files through a flag (`check --combined <file>`
writes over the file it names, `--log-file` appends to any file). The tests try every flag that
`rclone help flags` lists on each command.

The command line is read the way rclone reads it. The subcommand is the literal first words, so a
flag's value is never taken for the subcommand. Short flags combine as Go's pflag combines them
(`-Lv` is -L and -v). Booleans are read as Go's strconv.ParseBool reads them.

The config is always encrypted. rclone opens it through `--password-command`, or through
RCLONE_CONFIG_PASS set for that one process when the caller hands the password in. The password is
never on the command line. The environment is built from nothing (no RCLONE_* variable the caller
exported reaches rclone), so nothing outside the command line can point a remote elsewhere.

One secret does cross a command line once. `config create` takes the OAuth client's secret as an
argument (rclone saves option values only from arguments). Google treats a desktop client's secret
as not confidential, since it ships inside every installed app. The token, the real key, never
appears on a command line or in the environment. And every result's `args` has key=value secrets
replaced by XXX.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from pathlib import Path
from typing import Callable, Union

from billspc._env import clean_env

#: the rclone release the tests were measured against
VERSION = "1.75.2"
#: where rclone is looked for when BINARY is not set
CANDIDATES = ("/opt/homebrew/bin/rclone", "/usr/local/bin/rclone", "/usr/bin/rclone")
#: the rclone binary to run. None means: find it on the PATH, then in CANDIDATES
BINARY: str | None = None
#: what rclone and its password command may find
PATH = "/usr/bin:/bin"
#: the probe file the account check writes and removes, as a prefix. A probe is this prefix
#: followed by 12 lowercase hexadecimal characters, at the top of the remote
PROBE_PREFIX = ".billspc-account-check-"
#: the only folder a check's report (--combined) may be written into. A path, or a function that
#: returns one at the moment of asking. None refuses every --combined
REPORT_DIR: Union[Path, Callable[[], Path], None] = None

#: the subcommands rclone may be run with, as the words a command line starts with
ALLOWED = {"version", "about", "lsjson", "check", "listremotes", "copy", "touch", "deletefile", "dedupe",
           "config create", "config delete", "config reconnect", "config redacted",
           "config encryption set", "config encryption check"}
#: flags refused wherever they appear, as `--flag` or `--flag=value`
NEVER_FLAGS = ("--delete-before", "--delete-during", "--delete-after", "--delete-excluded",
               "--max-delete", "--max-delete-size", "--backup-dir", "--suffix", "--inplace",
               "--links", "--copy-links", "--fix-case", "--no-unicode-normalization", "--resync",
               "--force", "--dump", "--dump-headers", "--dump-bodies", "--dump-auth",
               "--drive-client-id", "--drive-client-secret", "--drive-token",
               "--drive-root-folder-id", "--drive-service-account-file",
               "--drive-service-account-credentials", "--drive-impersonate", "--drive-auth-url",
               "--drive-token-url", "--rc", "--rc-addr", "--ask-password")
#: short flags refused in any group (-L follows links, -l copies them)
NEVER_SHORT = ("L", "l")
#: what --log-level may say. DEBUG prints requests and their tokens
LOG_LEVELS = ("INFO", "NOTICE", "ERROR")
#: the spellings Go's strconv.ParseBool reads as true. Any other value of a guarding boolean is
#: refused rather than left to rclone
TRUE = ("1", "t", "T", "TRUE", "true", "True")
#: keys `config create` may never set: each points the remote at another client, token or folder.
#: Matched case and all, as rclone matches them (a key in another case is saved and read by no backend)
NEVER_KEYS = ("token", "auth_url", "token_url", "root_folder_id", "service_account_file",
              "service_account_credentials", "impersonate", "team_drive")
#: values shown as XXX in a result's `args`
SECRET_KEYS = ("client_secret", "client_id", "token")
#: the only long flags a copy may carry: its list, the two flags that keep it off newer content on
#: the remote, its log, the trash on, and how fast it goes
COPY_FLAGS = ("--files-from", "--files-from-raw", "--no-traverse", "--ignore-existing", "--update",
              "--dry-run", "--immutable", "--check-first", "--drive-skip-gdocs",
              "--drive-skip-shortcuts", "--drive-use-trash", "--use-json-log", "--verbose",
              "--log-level", "--stats", "--stats-one-line", "--progress", "--retries",
              "--low-level-retries", "--transfers", "--checkers", "--tpslimit", "--tpslimit-burst",
              "--bwlimit", "--drive-pacer-min-sleep", "--drive-pacer-burst", "--drive-chunk-size",
              "--drive-upload-cutoff", "--max-duration")
#: and the only short ones: -v, -u (--update), -n (--dry-run), -P (--progress)
COPY_SHORT = ("v", "u", "n", "P")
#: the copy flags that take a value. pflag reads it from the next word when no `=` gives it.
#: Every other copy flag is a boolean, except --verbose, which counts
COPY_VALUED = ("--files-from", "--files-from-raw", "--log-level", "--stats", "--retries",
               "--low-level-retries", "--transfers", "--checkers", "--tpslimit", "--tpslimit-burst",
               "--bwlimit", "--drive-pacer-min-sleep", "--drive-pacer-burst", "--drive-chunk-size",
               "--drive-upload-cutoff", "--max-duration")
#: the long flags each command may carry
FLAGS = {
    "version": (), "listremotes": (), "touch": (), "deletefile": (),
    "about": ("--json",),
    "lsjson": ("--files-only", "--recursive", "--files-from-raw", "--no-traverse", "--stat",
               "--metadata", "--drive-skip-gdocs", "--drive-skip-shortcuts"),
    "check": ("--files-from-raw", "--one-way", "--combined", "--drive-skip-gdocs",
              "--drive-skip-shortcuts", "--use-json-log"),
    "copy": COPY_FLAGS,
    "dedupe": ("--dedupe-mode", "--dry-run", "--drive-use-trash", "--use-json-log", "--log-level",
               "--verbose", "--max-depth"),
    "config create": ("--non-interactive", "--no-output"),
    "config delete": (), "config reconnect": (), "config redacted": (),
    "config encryption set": (), "config encryption check": (),
}
#: and the short ones: a listing's -R (--recursive), and a copy's own
SHORT = {"lsjson": ("R",), "copy": COPY_SHORT}
#: dedupe modes that never delete one of two different files. `list` changes nothing. `skip` merges
#: folders of one name and sends an exact duplicate (same path, same content) to the trash
DEDUPE_MODES = ("list", "skip")
#: a remote named plainly: a word before the colon, so neither a connection string
#: (`name,key=value:`, which overrides the config) nor an on-the-fly backend (`:local:`, which needs
#: no config at all)
REMOTE_NAME = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.-]*$")
#: how long rclone gets to end by itself after a timeout's TERM. It writes the end of its log then
#: and removes a partial upload. Only past this is it killed
TERM_GRACE_S = 10.0


class Refused(ValueError):
    """A command line outside the allowlist. Raised before anything runs."""


def binary() -> str:
    """The rclone to run: BINARY when set, else the first found on the PATH or in CANDIDATES."""
    if BINARY:
        return BINARY
    found = shutil.which("rclone")
    if found:
        return found
    return next((c for c in CANDIDATES if os.path.exists(c)), "rclone")


def probe_re() -> re.Pattern:
    """The exact shape of the account check's probe file, as `remote:<PROBE_PREFIX><12 hex>`."""
    return re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.-]*:" + re.escape(PROBE_PREFIX) + r"[0-9a-f]{12}$")


def _short_letters(a: str) -> str:
    """The letters of a short flag group as pflag reads it (`-Lv` is L and v). A group with a value
    (`-v=2`) gives its letters before the `=`. '' for anything that is not a short flag."""
    if not a.startswith("-") or a.startswith("--") or len(a) < 2:
        return ""
    return a[1:].split("=", 1)[0]


def _positionals(rest: list[str]) -> list[str]:
    """A copy's positional words as pflag reads them. A flag of COPY_VALUED given without `=` takes
    the next word as its value. Everything after `--` is positional."""
    out, take = [], False
    for i, a in enumerate(rest):
        if take:
            take = False
            continue
        if a == "--":
            out += rest[i + 1:]
            break
        if a.startswith("--"):
            take = "=" not in a and a in COPY_VALUED
            continue
        if a.startswith("-") and len(a) > 1:
            continue
        out.append(a)
    return out


def _report_dir() -> Path | None:
    d = REPORT_DIR() if callable(REPORT_DIR) else REPORT_DIR
    return Path(d) if d else None


def _in_reports(target: str) -> bool:
    """Whether a path a flag writes lies inside REPORT_DIR, the one place a check's report goes."""
    d = _report_dir()
    if d is None or not target.startswith("/"):
        return False
    p, state = Path(os.path.normpath(target)), Path(os.path.normpath(str(d)))
    return p != state and p.is_relative_to(state)


def _remote_word(w: str) -> str | None:
    """The remote a word names as rclone reads it: the text before its first colon when no slash
    comes before that colon ('' for an on-the-fly backend), or None for a local path (/x/a:b and
    x/a:b are folders, a:b is the remote a)."""
    name, colon, _ = w.partition(":")
    return None if not colon or "/" in name else name


def check(args: list[str]) -> None:
    """Raise Refused for a command line (the arguments after `rclone`) the allowlist does not hold."""
    args = list(args)
    head = next((p for p in sorted(ALLOWED, key=lambda s: len(s.split()), reverse=True)
                 if args[:len(p.split())] == p.split()), None)
    if head is None:
        shown = " ".join(args[:2]) or "(nothing)"
        raise Refused(f"rclone {shown} is not a command this module runs (the subcommand comes first)")
    rest = args[len(head.split()):]
    words = [a for a in rest if not a.startswith("-")]
    verbose = 0
    for i, a in enumerate(rest):
        flag = a.split("=", 1)[0]
        if flag in NEVER_FLAGS or flag.startswith("--dump"):
            raise Refused(f"rclone flag {flag} is refused: it can lose data or print a secret")
        letters = _short_letters(a)
        if head == "copy" and a.startswith("-") and (
                (a.startswith("--") and flag not in COPY_FLAGS)
                or any(ch not in COPY_SHORT for ch in letters)):
            raise Refused(f"rclone copy runs only with the flags listed in COPY_FLAGS, and {flag} is not "
                          "one: it can change what a copy writes over or where it writes")
        if a.startswith("-") and ((a.startswith("--") and flag not in FLAGS[head])
                                  or any(ch not in SHORT.get(head, ()) for ch in letters)):
            raise Refused(f"rclone {head} runs only with the flags listed for it, and {flag} is not "
                          "one: a flag can make a read write a local file")
        if flag == "--combined":
            target = a.split("=", 1)[1] if "=" in a else (rest[i + 1] if i + 1 < len(rest) else "")
            if not _in_reports(target):
                raise Refused(f"rclone check writes its report only inside REPORT_DIR, never at "
                              f"{target[:60] or 'no path'}: --combined writes over the file it names")
        if head == "copy" and "=" in a and a.split("=", 1)[1] not in TRUE and (
                (a.startswith("--") and flag not in COPY_VALUED and flag != "--verbose")
                or (not a.startswith("--") and letters)):
            raise Refused(f"rclone copy {a} turns off a flag a copy carries to stay safe (--update and "
                          "--ignore-existing keep it off newer content on the remote), refused")
        if head == "copy" and "=" in a and letters and len(letters) != 1:
            raise Refused(f"rclone copy {a} gives a value to a group of short flags, refused")
        if any(ch in NEVER_SHORT for ch in letters):
            raise Refused(f"rclone flag {a} is refused: it can lose data or print a secret")
        if "=" in a and "v" in letters:
            raise Refused(f"rclone flag {a} is refused: a verbosity above -v prints requests")
        verbose += letters.count("v")
        if flag == "--verbose":
            if "=" in a:
                raise Refused(f"rclone flag {a} is refused: a verbosity above -v prints requests")
            verbose += 1
        if flag == "--drive-use-trash":
            if "=" in a and a.split("=", 1)[1] not in TRUE:
                raise Refused(f"rclone {a} deletes past Drive's trash, refused")
            nxt = rest[i + 1] if i + 1 < len(rest) else ""
            if "=" not in a and nxt and not nxt.startswith("-") and nxt not in TRUE:
                raise Refused(f"rclone --drive-use-trash {nxt} reads as a value that is not true, refused")
        if flag == "--log-level":
            level = a.split("=", 1)[1] if "=" in a else (rest[i + 1] if i + 1 < len(rest) else "")
            if level.upper() not in LOG_LEVELS:
                raise Refused(f"rclone --log-level {level} is refused: DEBUG prints requests")
    if verbose > 1:
        raise Refused("rclone -v given more than once is DEBUG, which prints requests, refused")
    for w in words:
        name = _remote_word(w)
        if name is not None and not REMOTE_NAME.match(name):
            raise Refused(f"rclone {w[:60]} does not name a remote plainly: a connection string "
                          "overrides the remote's own config, and an on-the-fly backend needs none")
    if head == "copy":
        pos = _positionals(rest)
        if len(pos) != 2 or not pos[0].startswith("/") or _remote_word(pos[1]) is None:
            raise Refused("rclone copy goes from a local folder to a remote, never back and never "
                          f"between remotes: {' '.join(pos)[:80] or 'no source and destination'}")
    if head in ("deletefile", "touch"):
        if len(words) != 1 or not probe_re().match(words[0]):
            raise Refused(f"rclone {head} may touch only the account check's own probe file")
    if head == "touch" and any(a.split("=", 1)[0] == "--recursive" or "R" in _short_letters(a) for a in rest):
        raise Refused("rclone touch -R rewrites the time of every file under a path, refused")
    if head == "dedupe":
        modes = [a.split("=", 1)[1] if "=" in a else None for a in rest if a.split("=", 1)[0] == "--dedupe-mode"]
        if len(modes) != 1 or modes[0] not in DEDUPE_MODES:
            raise Refused("rclone dedupe runs with one --dedupe-mode=list or --dedupe-mode=skip, written "
                          "with its `=`: every other mode deletes one of two different files")
        if any(a.startswith("--") and "=" not in a and a in ("--log-level", "--drive-use-trash", "--max-depth")
               for a in rest):
            raise Refused("rclone dedupe takes each value with its `=`, so no value reads as a path or a mode")
        if len(words) != 1 or _remote_word(words[0]) is None:
            raise Refused("rclone dedupe works on one remote path, and a mode is never a bare word: "
                          f"{' '.join(words)[:80] or 'no path'}")
        if modes[0] == "skip" and not any(a.split("=", 1)[0] == "--drive-use-trash" and a.split("=", 1)[-1] in TRUE
                                          for a in rest):
            raise Refused("rclone dedupe --dedupe-mode=skip runs only with --drive-use-trash=true: an exact "
                          "duplicate goes to Drive's trash, never past it")
    if head == "config create":
        for w in words[2:]:
            key, _, value = w.partition("=")
            if key in NEVER_KEYS or (key == "use_trash" and value not in TRUE):
                raise Refused(f"rclone config create may not set {key}: it points the remote "
                              "elsewhere or deletes past Drive's trash")
    if head == "copy" and not any(a.startswith("--files-from") for a in rest):
        raise Refused("rclone copy runs only with --files-from, so it copies a listed set")


def redacted(cmd: list[str]) -> list[str]:
    """The command with every secret key=value shown as key=XXX."""
    out = []
    for a in cmd:
        key, sep, _ = a.partition("=")
        out.append(f"{key}=XXX" if sep and key in SECRET_KEYS else a)
    return out


def argv(args: list[str], *, config: Path | None, password_command: str | None,
         config_password: str | None = None, rclone: str | None = None) -> list[str]:
    """The whole command line: rclone, the checked arguments, and the encrypted config with the
    command that opens it. Refuses before returning anything."""
    check(args)
    out = [rclone or binary(), *args]
    if config is not None:
        if not password_command and not config_password:
            raise Refused("an rclone config is always encrypted, so it needs a password command or a "
                          "password handed in")
        out += ["--config", str(config)]
        if password_command:
            out += ["--password-command", password_command]
        out.append("--ask-password=false")
    return out


def env(path: str = PATH, config_password: str | None = None) -> dict[str, str]:
    """rclone's environment, built from nothing: HOME for its cache, a PATH, and no RCLONE_*
    variable except the config's password when the caller hands one in."""
    return clean_env(path, add={"RCLONE_CONFIG_PASS": config_password} if config_password else None)


def run(args: list[str], *, config: Path | None, password_command: str | None,
        timeout: float = 120, stdin_text: str | None = None, path: str = PATH,
        config_password: str | None = None, rclone: str | None = None) -> subprocess.CompletedProcess:
    """Run one checked rclone command and wait for it.

    A command that cannot start or runs past its timeout comes back as a failed CompletedProcess
    (127 or 124), never as an exception. A command past its timeout keeps what it said: it is sent
    TERM (rclone then removes a partial upload and ends), its output is read to the end, and the
    note "timed out after N s" is added to stderr. KILL follows only past TERM_GRACE_S. So a copy cut
    by its timeout still reports each file it wrote."""
    cmd = argv(args, config=config, password_command=password_command,
               config_password=config_password, rclone=rclone)
    shown = redacted(cmd)
    try:
        proc = subprocess.Popen(cmd, stdin=subprocess.PIPE if stdin_text is not None else subprocess.DEVNULL,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                                env=env(path, config_password))
    except OSError as e:
        return subprocess.CompletedProcess(shown, 127, "", str(e))
    try:
        out, err = proc.communicate(input=stdin_text, timeout=timeout)
        return subprocess.CompletedProcess(shown, proc.returncode, out, err)
    except subprocess.TimeoutExpired:
        proc.terminate()
        try:
            out, err = proc.communicate(timeout=TERM_GRACE_S)
        except subprocess.TimeoutExpired:
            proc.kill()
            out, err = proc.communicate()
        note = f"timed out after {timeout:.0f} s"
        return subprocess.CompletedProcess(shown, 124, out or "",
                                           f"{err.rstrip()}\n{note}" if (err or "").strip() else note)


def popen(args: list[str], *, config: Path | None, password_command: str | None,
          path: str = PATH, config_password: str | None = None, rclone: str | None = None,
          **kw) -> subprocess.Popen:
    """Start one checked rclone command that keeps running (the consent's reconnect), with stdin and
    stdout pipes for the caller to answer its questions on. stderr goes to stdout."""
    cmd = argv(args, config=config, password_command=password_command,
               config_password=config_password, rclone=rclone)
    return subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, env=env(path, config_password), **kw)


# ------------------------------------------------------------------------------------ the version

def installed_version(rclone: str | None = None) -> str | None:
    """The installed rclone's version as "1.75.2", or None when it does not run."""
    try:
        r = subprocess.run([rclone or binary(), "version"], capture_output=True, text=True, timeout=30,
                           stdin=subprocess.DEVNULL, env=env())
    except (OSError, subprocess.SubprocessError):
        return None
    m = re.search(r"rclone v(\d+(?:\.\d+)*)", r.stdout or "")
    return m.group(1) if r.returncode == 0 and m else None


def _parts(v: str) -> tuple[int, ...]:
    return tuple(int(x) for x in re.findall(r"\d+", v))


def version_ok(minimum: str = VERSION, rclone: str | None = None) -> tuple[bool, str | None]:
    """(whether the installed rclone is at least `minimum`, its version). An rclone that does not run
    is never ok. The allowlist and the plan checks were measured on VERSION, so a newer one is
    accepted and an older one is not."""
    got = installed_version(rclone)
    return (got is not None and _parts(got) >= _parts(minimum)), got


# ------------------------------------------------------------------------------------ reading output

def json_log(text: str) -> list[dict]:
    """The lines of rclone's --use-json-log output that are JSON objects, in order."""
    out = []
    for line in (text or "").splitlines():
        line = line.strip()
        if line.startswith("{"):
            try:
                obj = json.loads(line)
            except ValueError:
                continue
            if isinstance(obj, dict):
                out.append(obj)
    return out


#: what a dry run may plan: copies, and setting a time on what it copied
PLANNED_OK = ("copy", "set modification time", "set directory modification time",
              "update modification time")


def plan_problems(lines: list[dict], copies: set[str] | None = None) -> list[str]:
    """What a --dry-run --use-json-log plan would do beyond copying, from its own words. [] is a
    plan of copies only.

    rclone logs {"skipped": "copy"} for a file that replaces one on the remote exactly as for a new
    file. So a caller can name the paths it decided may be written (`copies`), and any other planned
    copy is then a problem too."""
    bad = []
    for o in lines:
        step = o.get("skipped")
        if step and step not in PLANNED_OK:
            bad.append(f"{step} {o.get('object', '')}".strip())
        elif step == "copy" and copies is not None and o.get("object") not in copies:
            bad.append(f"copy {o.get('object', '')}: a path the plan did not decide to write")
        stats = o.get("stats")
        if isinstance(stats, dict):
            for k in ("deletes", "deletedDirs", "renames", "serverSideMoves"):
                if stats.get(k):
                    bad.append(f"{k} {stats[k]}")
    return bad


#: rclone's words for a file a copy wrote ("Copied (new)", "Copied (replaced existing)", the
#: server-side and multi-thread forms). With --use-json-log -v each is one line with the path in
#: "object" and the bytes in "size". A file the copy skipped or failed has none
COPIED = re.compile(r"^(?:Multi-thread )?Copied \(")


def copied(lines: list[dict]) -> dict[str, int | None]:
    """The files a real copy wrote, from its own --use-json-log -v lines: {path: bytes}."""
    out: dict[str, int | None] = {}
    for o in lines:
        msg, obj = o.get("msg"), o.get("object")
        if isinstance(msg, str) and isinstance(obj, str) and COPIED.match(msg):
            size = o.get("size")
            out[obj] = size if isinstance(size, int) and not isinstance(size, bool) else None
    return out


def combined(text: str) -> dict[str, str]:
    """The per-file verdicts of `rclone check --combined <file>`: {path: mark}. "=" is the same on
    both sides, "*" differs, "+" is missing on the destination and "!" could not be read. A listed
    file rclone skipped (one that vanished, a folder) has no line, so it is never read as checked."""
    out = {}
    for line in (text or "").splitlines():
        if len(line) > 2 and line[1] == " " and line[0] in "=*+-!":
            out[line[2:]] = line[0]
    return out
