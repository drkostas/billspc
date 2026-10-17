# Contributing

Issues and pull requests are welcome.

```bash
python -m venv .venv && .venv/bin/pip install -e '.[test]'
.venv/bin/pytest
```

Please add a test for every change in behaviour. Tests run real rclone where they can (install it first), with local folders and a stand-in Google on loopback in place of Drive. A change to the allowlist needs a test that tries the new command or flag the way rclone reads it.

## Writing for this repository

Everything here is public, including commit messages and pull request descriptions. Please write them for a user of the package. Do not name other projects, people or machines that use it, and keep real hostnames, IP addresses, paths, account names and credentials out of code, tests and history (examples use `example.org`, `192.0.2.x` and `/path/to`). A check on every pull request looks for terms that must not appear here.
