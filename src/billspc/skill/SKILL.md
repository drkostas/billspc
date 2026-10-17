---
name: billspc
description: Use when a Mac's files should reach Google Drive through rclone with the billspc package. Covers running rclone behind an allowlist so no command can delete a Drive, writing filter files for rclone copy and bisync from built-in rules, ignore patterns and included folders, running Google's OAuth consent for an rclone remote under a supervisor and checking whose account the token belongs to, reading an Insync setup to move its ignore rules to rclone, and listing the files changed under a folder since a moment. Also use it when an rclone command is refused, when a consent page does not come up or port 53682 is busy, when a token belongs to the wrong account, or when rclone and a filter disagree about a file.
---

# billspc

billspc runs rclone for Google Drive sync and backup on a Mac. It has five modules, and each one works alone.

| Module | What it does |
|---|---|
| `billspc.rclone` | runs rclone, with every command line checked against an allowlist first |
| `billspc.filters` | says what a sync never copies, as a Python matcher and as rclone filter lines |
| `billspc.consent` | runs Google's consent for a remote under a supervisor and checks the token's account |
| `billspc.insync` | reads an Insync setup (its schema, its ignore rules) without reading a secret |
| `billspc.scan` | lists the files changed under a folder since a moment |

Install it with `pip install billspc`. It needs rclone 1.75.2 or newer (`billspc rclone-version` checks).

## Rules that keep a Drive safe

1. Never type an rclone command line yourself for real data. Call `billspc.rclone.run(args, config=..., password_command=...)`. It raises `Refused` before anything runs when the command is outside the allowlist.
2. The allowlist has no `sync`, `bisync`, `move`, `delete`, `purge`, `cleanup` or `config show`. A refusal is the design, not a bug. Do not widen `ALLOWED` or `FLAGS` to get a command through. If a new command is truly needed, add it with a test that tries every flag `rclone help flags` lists on it (see `tests/test_rclone.py`).
3. A copy needs `--files-from` or `--files-from-raw`, goes from an absolute local folder to a remote, and carries only `COPY_FLAGS`. Add `--ignore-existing` or `--update` so a copy never writes over newer content on the remote.
4. Plan first. Run the copy with `--dry-run --use-json-log -v`, read the plan with `rclone.plan_problems(rclone.json_log(out), copies=set_of_paths)`, and run for real only when it returns `[]`. A plan of "copy" steps can still replace files on the remote, which is why `copies` names the paths you decided to write.
5. After a real copy, `rclone.copied(json_log)` says which files rclone wrote. A copy cut by its timeout still reports them (exit code 124).
6. A config is always encrypted. Give `password_command`, or `config_password` (it reaches rclone as RCLONE_CONFIG_PASS for that one process, never on the command line).
7. `check --combined <file>` may write only inside `rclone.REPORT_DIR`. Set it (a path, or a function that returns one) before you run a check with a report.
8. To choose rclone's environment, pass `env=` (a dict) to `run`, `popen`, `installed_version` or `version_ok`. It replaces the environment billspc builds from nothing, and `path` is then not used. `RCLONE_CONFIG_PASS` is still added for `config_password`. A dict with any `RCLONE_*` variable is refused before anything runs, so pass a config password as `config_password`, never in `env`. `env=None` (the default) builds the environment as before.

```python
from pathlib import Path
from billspc import rclone

kw = {"config": Path("~/.config/billspc/rclone/gdrive.conf").expanduser(),
      "password_command": "/usr/bin/security find-generic-password -a billspc -s billspc-gdrive -w"}
args = ["copy", "/path/to/Drive", "gdrive:", "--files-from-raw", "/path/to/list.txt",
        "--no-traverse", "--ignore-existing", "--use-json-log", "-v"]
plan = rclone.run([*args, "--dry-run"], **kw)
if not rclone.plan_problems(rclone.json_log(plan.stdout + plan.stderr), copies=set(paths)):
    done = rclone.run(args, **kw, timeout=3600)
    print(rclone.copied(rclone.json_log(done.stdout + done.stderr)))
```

## Filters

A `FilterSet` holds the built-in never-copied list (`DEFAULT_NEVER`, with a reason for each rule), ignore patterns (`GlobRules`) and included folders.

- `fs.excluded(rel, is_dir)` returns why a path is left out, or `None`.
- `fs.lines()` returns the same rules as rclone filter lines. Ignore patterns become regular expression blocks (`{{ }}`), two lines each.
- `write_filter_file(path, lines)` writes them atomically and returns the MD5. bisync asks for `--resync` when its filters file changes, so compare the MD5 with the last one.
- Run rclone with `--ignore-case`. The matcher is case-blind, as macOS is.
- rclone refuses `--files-from` together with other filters. For a listed copy, filter while you build the list (with `fs.excluded`), not with `--filter-from`.
- The Finder icon file is named `Icon` plus a carriage return. rclone lists it as `Icon␍`, and the filter lines spell it that way.
- Ignore patterns are read loosely on purpose (`*` crosses folders, a pattern matches any run of path parts). A path that a looser reading keeps out only stays local, while an upload cannot be undone.

When rclone and the matcher seem to disagree, run the check from `tests/test_filters.py`, which lists a planted tree with real rclone and with the matcher and compares them file for file.

## The consent

```python
from billspc import consent

store = consent.MacKeychain(account="billspc")          # or consent.FileStore(folder)
r = consent.Remote(name="gdrive", config=Path("~/.config/billspc/rclone/gdrive.conf").expanduser(),
                   password_command=store.command("billspc-gdrive"), password_item="billspc-gdrive",
                   state_dir=Path("~/.local/state/billspc/consent").expanduser(),
                   account="you@example.org")
client = consent.load_client(Path("~/.config/billspc/client.json").expanduser())
consent.ensure_config(r, client=client, store=store)
result = consent.supervise(r, client=client, store=store, on_page=print)
```

Or from the command line, `billspc consent gdrive` with a config file (see `examples/config.example.toml`).

- rclone serves the page at `http://127.0.0.1:53682/auth?state=...` while `config reconnect` runs. The port cannot be moved, so one consent runs at a time. `port_holder(remotes)` returns "ours", "other" or `None`.
- The supervisor answers rclone's questions by their words (`ANSWERS`). An unknown question ends the consent as "failed" and is never answered with a guess.
- The shim folder (`shim()`) puts a do-nothing `open` and `xdg-open` first on rclone's PATH, so rclone does not open the page in a browser window the user is working in. Open the page yourself (`on_page`).
- Outcomes are consented, declined, blocked, failed, timed out and ended. "blocked" comes from Google's words in rclone's error or from the page (`page_reader`, or `tabs` judged by `PageWatch`). Google's `/signin/rejected` page is a failed sign-in, not a block.
- After every ending, the default `on_end` checks the account of any token the remote holds, because rclone saves a new token before its last question. `check_account` makes a probe file at the top of My Drive, reads its owner and sends it to the trash. A token for another account is discarded at once (the remote deleted and made again with no token). Google is never asked to revoke the grant, since that would end the app's other grants too.
- An "unknown" account check (the probe got no answer) changes nothing. Check again later with `check_account`.
- `open_page(remote, spawn=...)` starts a supervisor in its own process and waits for the page. `spawn_command(argv, log)` starts one in a session of its own, so `stop()` can end it whole.
- Each pid in the page file is kept with its start time and executable. `stop()` and `end_leftovers()` signal a pid only while it is still that process, so a pid reused after a reboot is never signalled.
- For your own bookkeeping, pass `still_wanted`, `on_end` and `on_stopped`. A callback that raises still leaves rclone ended, the port free and the result written.
- Every function that starts a program takes `env`, the whole environment that program gets, and passes it on to each program it starts (rclone, `ps`, `security`). `env=None` keeps the environment each one builds. `supervise` keeps the shim folder first on the `PATH` you give. A function you hand in (`spawn`, `owner_of`, the callbacks) gets no `env`, so give your `spawn` its own, for example `spawn_command(argv, log, env=env)`. A password store sets its own, as `MacKeychain(env=env)`.

A Google Cloud project's OAuth client of the "Desktop app" type works. While the app is in "Testing", Google ends its refresh tokens after seven days. In "Production" a token lasts until it is revoked or unused for six months.

## Leaving Insync

1. Quit Insync first. A running Insync deletes on Drive what the Mac lacks.
2. `billspc insync schema` prints each database's tables and columns and never a row.
3. `billspc insync rules --out ~/.config/billspc/ignore.txt` writes each account's ignore rules. Any line shaped like a token refuses the rules whole, and the message never prints it.
4. Set a folder's `ignore_file` to that file, and `billspc filters <folder>` shows the rclone lines.

`insync.Reader` reads only the (table, column) pairs it is given, enforced by SQLite's authorizer, and returns any secret-shaped value as `[refused: ...]`. It opens databases read only (mode=ro), which reads an unfolded WAL and changes neither the database nor the WAL.

## What changed since a moment

```python
from billspc import scan
listing = scan.changed_since(Path("~/Drive").expanduser(), since, exclude=fs.excluded,
                             remembered=previous.get("moved"))
scan.write_json(state / "scan" / "drive.json", listing)
```

- A file counts when its mtime or its ctime is after `since` (a move keeps the mtime and changes the ctime).
- A folder moved or renamed after `since` brings every file under it, found by APFS's date added (macOS), by its ctime past its mtime, or because an earlier listing saw it (pass the old listing's `moved`).
- Past `cap` (20,000), files under moved folders are counted in `moved_unlisted` and not named.
- `uploaded={"uploaded": {path: {"size", "mtime_ns", "verified": True}}}` leaves out a file already copied and checked until it changes again.
- `scan.background()` lowers the process to nice 10 and macOS's throttled disk tier before a large walk.

## Testing

`pytest` runs everything with no network and no Google account. The consent tests run real rclone against a stand-in Google on loopback and skip when port 53682 is busy. Tests that need rclone skip when it is not installed.
