"""Copy every file changed under a folder since a moment to an rclone remote, upload only.

    python examples/catch_up.py <folder> <remote:path> <since> --config <rclone.conf> --password-command "<cmd>"

1. List what changed since the moment, with the built-in never-copied list (billspc.scan).
2. Plan the copy with a dry run and refuse it if it would do anything but copy (billspc.rclone).
3. Copy for real and print each file rclone says it wrote.

The copy is `rclone copy --files-from-raw <list> --ignore-existing`, so a file the remote already
holds is never written over, and nothing on the remote is ever deleted.
"""
from __future__ import annotations

import argparse
import sys
import tempfile
from datetime import datetime
from pathlib import Path

from billspc import rclone, scan


def main(argv=None) -> int:
    p = argparse.ArgumentParser()
    p.add_argument("folder")
    p.add_argument("remote")
    p.add_argument("since", help="an ISO time, such as 2026-01-31T12:00:00+00:00")
    p.add_argument("--config", required=True)
    p.add_argument("--password-command", required=True)
    a = p.parse_args(argv)

    folder = Path(a.folder).expanduser().resolve()
    since = datetime.fromisoformat(a.since)
    listing = scan.changed_since(folder, since if since.tzinfo else since.astimezone())
    paths = [f["path"] for f in listing["files"]]
    print(f"{len(paths)} file(s) changed under {folder} since {a.since}")
    if not paths:
        return 0
    with tempfile.TemporaryDirectory() as tmp:
        files = Path(tmp) / "files.txt"
        files.write_text("".join(f"{x}\n" for x in paths))
        args = ["copy", str(folder), a.remote, "--files-from-raw", str(files), "--no-traverse",
                "--ignore-existing", "--use-json-log", "-v"]
        kw = {"config": Path(a.config), "password_command": a.password_command}
        plan = rclone.run([*args, "--dry-run"], **kw)
        problems = rclone.plan_problems(rclone.json_log(plan.stdout + "\n" + plan.stderr), copies=set(paths))
        if plan.returncode != 0 or problems:
            print(f"refused: the plan is not a copy of the listed files: {problems or plan.stderr[-300:]}")
            return 1
        res = rclone.run(args, **kw, timeout=3600)
    wrote = rclone.copied(rclone.json_log(res.stdout + "\n" + res.stderr))
    for path, size in sorted(wrote.items()):
        print(f"copied {path} ({size} bytes)")
    return 0 if res.returncode == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
