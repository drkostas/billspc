# billspc

billspc is a self-hosted cloud filesystem for a Mac, with Google Drive as the storage and rclone as the engine.

It is the part of a Drive sync that has to be careful. rclone can empty a whole Drive with one wrong command, a consent page can give a token for the wrong account, and a desktop sync client keeps rules that nothing else reads. billspc is a Python package and a command line for those parts.

- **An allowlist before every rclone command.** Reads, a copy of a listed set of files, and the consent's own config steps are allowed. `sync`, `bisync`, `move`, `delete`, `purge` and every flag not chosen for a command are refused before anything runs. The tests try every flag rclone lists on every command.
- **Filter files.** A built-in list of what never syncs (`.git`, `node_modules`, half-written files, Finder's `.DS_Store`, link files to Google documents), ignore patterns and included folders, written as rclone filter lines for `copy` and `bisync`. The tests hold real rclone to the Python matcher, file for file.
- **A supervised Google consent.** `rclone config reconnect` runs under a supervisor that answers its questions, ends it after a lifetime, and checks whose account the new token belongs to. A token for another account is discarded at once.
- **Leaving Insync.** It reads Insync's databases read only, prints their schema without a row, and writes each account's ignore rules to a file. A value shaped like a token is never returned.
- **A scan of what changed.** Every file changed under a folder since a moment, including every file under a folder moved after it, written atomically.

It runs on macOS, and everything but the keychain store and APFS's date added runs on Linux too.

## Install

```bash
pip install billspc
brew install rclone        # 1.75.2 or newer
billspc rclone-version
```

## Use

Copy `examples/config.example.toml` to `~/.config/billspc/config.toml` and complete it with your remote and folder. You need an OAuth client from a Google Cloud project (type "Desktop app") with the Drive API on, saved as the JSON file Google gives you.

```bash
billspc consent gdrive                  # prints Google's page, waits, checks the account
billspc account gdrive                  # whose account the token belongs to
billspc filters drive --out ~/.config/billspc/drive.filters
billspc scan drive --since 2026-01-31T12:00:00+00:00
```

The page `billspc consent` prints is on `127.0.0.1:53682`, where rclone serves every consent. Open it in the browser on the same machine. The token goes into the encrypted rclone config and nowhere else, and the config's password goes into the macOS keychain (or a private file, with `password_store = "files"`).

To leave Insync, quit Insync first, then

```bash
billspc insync schema                   # tables and columns, never a row
billspc insync rules --out ~/.config/billspc/ignore.txt
```

and set `ignore_file` for the folder.

## Use it from Python

`examples/catch_up.py` copies every file changed under a folder since a moment, upload only. It lists the files with `billspc.scan`, plans the copy with a dry run, refuses the plan if it does anything but copy the listed files, and then copies.

```bash
python examples/catch_up.py ~/Drive gdrive: 2026-01-31T12:00:00+00:00 \
  --config ~/.config/billspc/rclone/gdrive.conf \
  --password-command "/usr/bin/security find-generic-password -a billspc -s billspc-gdrive -w"
```

The modules are `billspc.rclone`, `billspc.filters`, `billspc.consent`, `billspc.insync` and `billspc.scan`. Each docstring says what it guards against and why.

## Claude Code

billspc ships a Claude Code skill with the rules above and the details behind them. `billspc skill` prints it, and `billspc skill --install` copies it to `~/.claude/skills/billspc`.

## Tests

```bash
pip install -e '.[test]'
pytest
```

They need no network and no Google account. The consent tests run real rclone against a stand-in Google on loopback. Tests that need rclone are skipped when it is not installed.

## Licence

MIT

Like Bill's PC, you can reach this box from any Pokémon Center.
