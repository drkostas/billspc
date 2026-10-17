"""The configuration file: where things are, which remotes exist, and which folders sync.

Default place: $BILLSPC_CONFIG, else ~/.config/billspc/config.toml. See
examples/config.example.toml for every key.
"""
from __future__ import annotations

import os
import sys
from dataclasses import dataclass, field
from pathlib import Path

if sys.version_info >= (3, 11):
    import tomllib
else:  # pragma: no cover
    import tomli as tomllib

from billspc import rclone
from billspc.consent import FileStore, MacKeychain, Remote, load_client
from billspc.filters import DEFAULT_NEVER, FilterSet, GlobRules, Rule


def default_path() -> Path:
    return Path(os.environ.get("BILLSPC_CONFIG") or Path.home() / ".config" / "billspc" / "config.toml")


def _p(value: str | None) -> Path | None:
    return Path(os.path.expanduser(value)) if value else None


@dataclass
class RemoteConf:
    name: str
    config: Path
    scope: str = "drive"
    account: str | None = None
    client_file: Path | None = None
    password_item: str | None = None
    password_command: str | None = None


@dataclass
class FolderConf:
    key: str
    path: Path
    remote: str | None = None
    ignore_file: Path | None = None
    include: tuple[str, ...] = ()
    never_paths: tuple[str, ...] = ()


@dataclass
class Config:
    state_dir: Path
    store: str = "keychain"
    store_account: str = "billspc"
    store_dir: Path | None = None
    rclone_binary: str | None = None
    rclone_path: str = rclone.PATH
    remotes: dict[str, RemoteConf] = field(default_factory=dict)
    folders: dict[str, FolderConf] = field(default_factory=dict)

    def password_store(self):
        """The store that holds each config's password: the macOS keychain, or a folder of files."""
        if self.store == "files":
            return FileStore(self.store_dir or self.state_dir / "passwords")
        return MacKeychain(self.store_account)

    def remote(self, name: str) -> Remote:
        """The consent's view of one remote."""
        if name not in self.remotes:
            raise KeyError(f"no remote {name!r} in the config (it has {sorted(self.remotes)})")
        rc = self.remotes[name]
        item = rc.password_item or f"billspc-{name}"
        command = rc.password_command or self.password_store().command(item)
        return Remote(name=name, config=rc.config, password_command=command,
                      state_dir=self.state_dir / "consent", scope=rc.scope, account=rc.account,
                      password_item=item)

    def client(self, name: str) -> tuple[str, str] | None:
        f = self.remotes[name].client_file
        return load_client(f) if f else None

    def filters(self, key: str) -> FilterSet:
        """The filter set of one folder: the built-in list, its own never paths, its ignore file
        and its included folders."""
        f = self.folders[key]
        never = DEFAULT_NEVER + tuple(Rule("path", p.strip("/"), "named in the config", folder=key)
                                      for p in f.never_paths)
        patterns = GlobRules.from_file(f.ignore_file) if f.ignore_file else GlobRules()
        return FilterSet(never=never, patterns=patterns, include=tuple(f.include), folder=key)

    def apply(self) -> None:
        """Hand the rclone settings to the rclone module. A check's report goes in the state folder."""
        rclone.BINARY = self.rclone_binary or rclone.BINARY
        rclone.PATH = self.rclone_path
        rclone.REPORT_DIR = self.state_dir / "reports"


def load(path: Path | None = None) -> Config:
    path = Path(path) if path else default_path()
    with open(path, "rb") as f:
        data = tomllib.load(f)
    general = data.get("billspc", {})
    rcl = data.get("rclone", {})
    cfg = Config(state_dir=_p(general.get("state_dir")) or Path.home() / ".local" / "state" / "billspc",
                 store=general.get("password_store", "keychain"),
                 store_account=general.get("keychain_account", "billspc"),
                 store_dir=_p(general.get("password_dir")),
                 rclone_binary=rcl.get("binary"), rclone_path=rcl.get("path", rclone.PATH))
    if cfg.store not in ("keychain", "files"):
        raise ValueError(f"password_store must be keychain or files, not {cfg.store!r}")
    for name, r in (data.get("remotes") or {}).items():
        if "config" not in r:
            raise ValueError(f"remote {name!r} needs a config path")
        cfg.remotes[name] = RemoteConf(name=name, config=_p(r["config"]), scope=r.get("scope", "drive"),
                                       account=r.get("account"), client_file=_p(r.get("client_file")),
                                       password_item=r.get("password_item"),
                                       password_command=r.get("password_command"))
    for key, f in (data.get("folders") or {}).items():
        if "path" not in f:
            raise ValueError(f"folder {key!r} needs a path")
        if f.get("remote") and f["remote"] not in cfg.remotes:
            raise ValueError(f"folder {key!r} names remote {f['remote']!r}, which the config does not have")
        cfg.folders[key] = FolderConf(key=key, path=_p(f["path"]), remote=f.get("remote"),
                                      ignore_file=_p(f.get("ignore_file")),
                                      include=tuple(f.get("include") or ()),
                                      never_paths=tuple(f.get("never") or ()))
    return cfg
