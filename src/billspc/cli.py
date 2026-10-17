"""The billspc command line."""
from __future__ import annotations

import argparse
import json
import shutil
import signal
import sys
from datetime import datetime
from pathlib import Path

from billspc import __version__, consent, filters, insync, rclone, scan

SKILL_SRC = Path(__file__).parent / "skill" / "SKILL.md"


def install_skill(target: str = "~/.claude/skills") -> Path:
    """Copy the Claude Code skill that comes with billspc into a skills folder."""
    dest = Path(target).expanduser() / "billspc"
    dest.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(SKILL_SRC, dest / "SKILL.md")
    return dest / "SKILL.md"


def _since(text: str) -> datetime:
    d = datetime.fromisoformat(text)
    return d if d.tzinfo else d.astimezone()


def cmd_version(cfg, args) -> int:
    ok, got = rclone.version_ok(args.minimum)
    print(f"rclone {got or 'not found'} ({'ok' if ok else 'needs ' + args.minimum + ' or newer'})")
    return 0 if ok else 1


def cmd_filters(cfg, args) -> int:
    fs = cfg.filters(args.folder)
    lines = fs.lines()
    if args.out:
        md5 = filters.write_filter_file(Path(args.out), lines, header=f"billspc filters for {args.folder}")
        print(f"wrote {len(lines)} lines to {args.out} (md5 {md5})")
    else:
        print("\n".join(lines))
    return 0


def cmd_scan(cfg, args) -> int:
    f = cfg.folders[args.folder]
    fs = cfg.filters(args.folder)
    out = Path(args.out) if args.out else cfg.state_dir / "scan" / f"{args.folder}.json"
    previous = scan.read_json(out)
    if args.background:
        scan.background()
    listing = scan.changed_since(f.path, _since(args.since), exclude=fs.excluded, key=args.folder,
                                 remembered=previous.get("moved") or [])
    scan.write_json(out, listing)
    if args.json:
        print(json.dumps(listing, indent=1, default=str))
    else:
        print(f"{scan.unsynced(listing)} file(s) changed under {f.path} since {args.since} "
              f"(oldest {scan.oldest_hours(listing, datetime.now().timestamp())} h), listing in {out}")
    return 0


def cmd_insync(cfg, args) -> int:
    root = Path(args.root).expanduser() if args.root else insync.DATA_DIR
    if args.what == "schema":
        picked = [Path(a) for a in args.db] or insync.databases(root)
        if not picked:
            print(f"no Insync database under {root}", file=sys.stderr)
            return 1
        return 1 if insync.show(picked, root=root) else 0
    picked = [Path(a) for a in args.db] or insync.account_databases(root)
    lines: list[str] = []
    for db in picked:
        lines += insync.ignore_rules(db)
    if args.out:
        Path(args.out).expanduser().write_text("".join(f"{l}\n" for l in lines))
        print(f"wrote {len(lines)} lines from {len(picked)} database(s) to {args.out}")
    else:
        print("\n".join(lines))
    return 0


def cmd_consent(cfg, args) -> int:
    r = cfg.remote(args.remote)
    client = cfg.client(args.remote)
    store = cfg.password_store()
    if consent.port_holder([cfg.remote(n) for n in cfg.remotes]) is not None:
        print(f"port {consent.PORT} is in use, so no consent can start now", file=sys.stderr)
        return 1
    made = consent.ensure_config(r, client=client, store=store)
    if not made["ok"]:
        print(f"the config is not ready: {made['why']}", file=sys.stderr)
        return 1
    # a TERM (from stop()) ends the supervisor through its finally, so rclone ends with it
    signal.signal(signal.SIGTERM, lambda *_a: sys.exit(143))
    result = consent.supervise(
        r, client=client, store=store, lifetime=args.lifetime,
        on_page=lambda url: print(f"Open this page to give consent: {url}", flush=True))
    print(json.dumps(result, default=str))
    return 0 if (result.get("account") or {}).get("outcome") == "success" else 1


def cmd_account(cfg, args) -> int:
    r = cfg.remote(args.remote)
    if consent.has_token(r) is not True:
        print(f"{args.remote} holds no token", file=sys.stderr)
        return 1
    res = consent.check_account(r, client=cfg.client(args.remote), store=cfg.password_store())
    print(json.dumps(res))
    return 0 if res["outcome"] == "success" else 1


def cmd_stop(cfg, args) -> int:
    print(json.dumps(consent.stop(cfg.remote(args.remote))))
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="billspc", description="rclone-backed Google Drive sync and backup, run safely.")
    p.add_argument("--config", default=None, help="config file (default $BILLSPC_CONFIG or ~/.config/billspc/config.toml)")
    p.add_argument("--version", action="version", version=f"billspc {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("skill", help="print the Claude Code skill (needs no config), or install it")
    s.add_argument("--install", action="store_true", help="copy it into a skills folder")
    s.add_argument("--dir", default="~/.claude/skills")

    s = sub.add_parser("rclone-version", help="whether the installed rclone is new enough (needs no config)")
    s.add_argument("--minimum", default=rclone.VERSION)
    s.set_defaults(fn=cmd_version, no_config=True)

    s = sub.add_parser("filters", help="print or write a folder's rclone filter lines")
    s.add_argument("folder")
    s.add_argument("--out", help="write the lines to this file (for --filter-from or --filters-file)")
    s.set_defaults(fn=cmd_filters)

    s = sub.add_parser("scan", help="list what changed under a folder since a moment")
    s.add_argument("folder")
    s.add_argument("--since", required=True, help="an ISO time, such as 2026-01-31T12:00:00+00:00")
    s.add_argument("--out", help="where the listing goes (default <state_dir>/scan/<folder>.json)")
    s.add_argument("--json", action="store_true", help="print the whole listing")
    s.add_argument("--background", action="store_true", help="run the walk at background priority")
    s.set_defaults(fn=cmd_scan)

    s = sub.add_parser("insync", help="read an Insync setup: its schema, or its ignore rules (needs no config)")
    s.add_argument("what", choices=("schema", "rules"))
    s.add_argument("db", nargs="*", help="database files (default every one under the data folder)")
    s.add_argument("--root", help=f"Insync's data folder (default {insync.DATA_DIR})")
    s.add_argument("--out", help="write the rules to this file")
    s.set_defaults(fn=cmd_insync, no_config=True)

    s = sub.add_parser("consent", help="run Google's consent for a remote and check whose token it gave")
    s.add_argument("remote")
    s.add_argument("--lifetime", type=float, default=consent.LIFETIME_S)
    s.set_defaults(fn=cmd_consent)

    s = sub.add_parser("account", help="check whose account a remote's token belongs to")
    s.add_argument("remote")
    s.set_defaults(fn=cmd_account)

    s = sub.add_parser("stop", help="end a remote's running consent")
    s.add_argument("remote")
    s.set_defaults(fn=cmd_stop)

    args = p.parse_args(argv)
    if args.cmd == "skill":
        if args.install:
            print(f"installed {install_skill(args.dir)}")
        else:
            print(SKILL_SRC.read_text(), end="")
        return 0
    cfg = None
    if not getattr(args, "no_config", False):
        from billspc import config as config_mod
        path = args.config or config_mod.default_path()
        try:
            cfg = config_mod.load(path)
        except FileNotFoundError:
            print(f"no config at {path} (see examples/config.example.toml)", file=sys.stderr)
            return 2
        except ValueError as e:
            print(str(e), file=sys.stderr)
            return 2
        cfg.apply()
    try:
        return args.fn(cfg, args)
    except KeyError as e:
        print(e.args[0], file=sys.stderr)
        return 2
    except (rclone.Refused, insync.Refused) as e:
        print(f"refused: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
