# Changelog

## Unreleased

- Every function that starts a program takes `env`, the whole environment that program gets. In `billspc.rclone` these are `run`, `popen`, `installed_version` and `version_ok`. In `billspc.consent` they are `MacKeychain` (its constructor, `has` and `add`), `proc_id`, `ours`, `spawn_command`, `rc` and every function that reaches them. `env=None` keeps the environment billspc builds, so existing callers see no change
- An `env` handed to rclone replaces the environment billspc builds. `RCLONE_CONFIG_PASS` is still added for `config_password`, and a dict with any `RCLONE_*` variable is refused before anything runs
- `popen` takes `env` as its own argument, so it never clashes with the keyword arguments it passes to Popen

## 0.1.0

First release.

- `billspc.rclone` runs rclone behind an allowlist of commands and of each command's flags, with an encrypted config opened by a password command or a password handed in through the environment. It reads dry-run plans, the files a copy wrote and a check's per-file verdicts
- `billspc.filters` holds the never-synced list, ignore patterns and included folders, as a Python matcher and as rclone filter lines
- `billspc.consent` runs Google's consent for an rclone remote under a supervisor, checks whose account the token belongs to and discards any other account's
- `billspc.insync` reads an Insync setup read only, its schema and its ignore rules, and never returns a secret-shaped value
- `billspc.scan` lists the files changed under a folder since a moment
- The `billspc` command and a Claude Code skill (`billspc skill`)
