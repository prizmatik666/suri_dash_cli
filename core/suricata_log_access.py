#!/usr/bin/env python3
"""Audited, reversible EVE log access transition for agent and dashboard users.

The public CLI operates only on the installed Suricata configuration, its
matching EVE file, and the installed logrotate rule. It never restarts services.
"""

from __future__ import annotations

import argparse
import base64
import errno
import grp
import hashlib
import json
import os
import pwd
import re
import stat
import sys
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path


@dataclass(frozen=True)
class Paths:
    suricata_yaml: Path = Path("/etc/suricata/suricata.yaml")
    logrotate: Path = Path("/etc/logrotate.d/suricata")
    state_dir: Path = Path("/var/lib/suricata-agent/log-access")


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _read_regular(path: Path) -> tuple[bytes, os.stat_result]:
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode):
        raise ValueError(f"Expected a regular file, not a symlink or device: {path}")
    return path.read_bytes(), info


def _stat_regular(path: Path) -> os.stat_result:
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode):
        raise ValueError(f"Expected a regular file, not a symlink or device: {path}")
    return info


def _require_no_acl(path: Path, *, directory: bool = False) -> None:
    if not hasattr(os, "getxattr"):
        return
    names = ("system.posix_acl_access", "system.posix_acl_default") if directory else ("system.posix_acl_access",)
    for name in names:
        try:
            os.getxattr(path, name)
        except OSError as exc:
            if exc.errno not in (errno.ENODATA, errno.ENOTSUP, errno.EOPNOTSUPP):
                raise
        else:
            raise ValueError(f"Extended ACL on {path}; inspect with getfacl and resolve it before using this mode-based transition")


def _eve_location(yaml_text: str) -> Path:
    directory = re.findall(r"(?m)^default-log-dir:[ \t]*(\S+)[ \t]*$", yaml_text)
    blocks = re.findall(r"(?ms)^  - eve-log:[ \t]*\n(.*?)(?=^  - [\w-]+:|\Z)", yaml_text)
    if len(directory) != 1 or len(blocks) != 1:
        raise ValueError("Expected one default-log-dir and one EVE logger; refusing an ambiguous Suricata config")
    names = re.findall(r"(?m)^      filename:[ \t]*(\S+)[ \t]*$", blocks[0])
    if len(names) != 1:
        raise ValueError("Expected one EVE filename; refusing an ambiguous Suricata config")
    root = Path(directory[0])
    name = Path(names[0])
    if not root.is_absolute() or name.name != names[0] or name.name in (".", ".."):
        raise ValueError("Only a simple EVE filename under an absolute default-log-dir is supported")
    location = root / name
    if root.is_symlink() or location.is_symlink():
        raise ValueError("Symlinked Suricata log paths are not supported for privileged changes")
    return location


def _render_yaml(original: bytes) -> bytes:
    text = original.decode("utf-8")
    blocks = list(re.finditer(r"(?ms)^  - eve-log:[ \t]*\n(.*?)(?=^  - [\w-]+:|\Z)", text))
    if len(blocks) != 1:
        raise ValueError("Expected exactly one EVE logger")
    block = blocks[0]
    section = block.group(0)
    existing = re.findall(r"(?m)^      filemode:[ \t]*\S+[ \t]*$", section)
    if len(existing) > 1:
        raise ValueError("Multiple EVE filemode settings found")
    if existing:
        section = section.replace(existing[0], "      filemode: 640", 1)
    else:
        section, count = re.subn(r"(?m)^(      filename:[ \t]*\S+[ \t]*\n)", r"\1      filemode: 640\n", section, count=1)
        if count != 1:
            raise ValueError("Could not locate the EVE filename to place filemode")
    return (text[:block.start()] + section + text[block.end():]).encode("utf-8")


def _validate_logrotate(original: bytes) -> bytes:
    text = original.decode("utf-8")
    create_lines = re.findall(r"(?m)^[ \t]*create(?:[ \t]+[^\n]*)?$", text)
    if len(create_lines) != 1 or create_lines[0].strip() != "create" or "copytruncate" in text or "nocreate" in text:
        raise ValueError("Logrotate must use one bare 'create' directive so EVE's protected mode/owner/group are inherited; refusing to change a shared rotation rule")
    return original


def _reader_membership(user: str, group_gid: int) -> None:
    try:
        account = pwd.getpwnam(user)
    except KeyError as exc:
        raise ValueError(f"Reader user does not exist: {user}") from exc
    if group_gid not in os.getgrouplist(user, account.pw_gid):
        raise ValueError(f"{user} is not in the trusted log group; add them and start a new login/session before applying")


def _mode_allows(info: os.stat_result, uid: int, gids: set[int], owner_bit: int, group_bit: int, other_bit: int) -> bool:
    if info.st_uid == uid:
        return bool(info.st_mode & owner_bit)
    if info.st_gid in gids:
        return bool(info.st_mode & group_bit)
    return bool(info.st_mode & other_bit)


def _sdash_settings(user: str) -> tuple[Path, dict | None]:
    account = pwd.getpwnam(user)
    home = Path(account.pw_dir)
    path = home / ".config/sdash/config.json"
    try:
        content, file_info = _read_regular(path)
    except FileNotFoundError:
        return Path("/var/log/suricata/eve.json"), None
    except PermissionError as exc:
        raise PermissionError(f"Cannot inspect sdash settings at {path}; use the config menu's sudo preview or repair the dashboard settings ownership first") from exc
    directory_info = path.parent.lstat()
    if not stat.S_ISDIR(directory_info.st_mode):
        raise ValueError(f"sdash settings directory is not a regular directory: {path.parent}")
    _require_no_acl(path)
    _require_no_acl(path.parent, directory=True)
    try:
        settings = json.loads(content)
    except json.JSONDecodeError as exc:
        raise ValueError(f"Invalid sdash config JSON at {path}: {exc}") from exc
    if not isinstance(settings, dict) or not isinstance(settings.get("log", "/var/log/suricata/eve.json"), str):
        raise ValueError(f"Invalid sdash log setting in {path}")
    before = {
        "path": str(path),
        "sha256": _digest(content),
        "file": {"uid": file_info.st_uid, "gid": file_info.st_gid, "mode": stat.S_IMODE(file_info.st_mode)},
        "directory": {"uid": directory_info.st_uid, "gid": directory_info.st_gid, "mode": stat.S_IMODE(directory_info.st_mode)},
    }
    groups = set(os.getgrouplist(user, account.pw_gid))
    before["readable_by_dashboard_user"] = (
        _mode_allows(directory_info, account.pw_uid, groups, stat.S_IXUSR, stat.S_IXGRP, stat.S_IXOTH)
        and _mode_allows(file_info, account.pw_uid, groups, stat.S_IRUSR, stat.S_IRGRP, stat.S_IROTH)
    )
    return Path(settings.get("log", "/var/log/suricata/eve.json")).expanduser(), before


def plan(group_name: str, agent_user: str, dashboard_user: str, *, expected_eve: Path | None = None, paths: Paths = Paths()) -> dict:
    yaml_bytes, yaml_info = _read_regular(paths.suricata_yaml)
    rotate_bytes, rotate_info = _read_regular(paths.logrotate)
    for config_path in (paths.suricata_yaml, paths.logrotate):
        if hasattr(os, "listxattr") and os.listxattr(config_path):
            raise ValueError(f"Extended attributes on {config_path} cannot be preserved by this transition; refusing to replace it")
    eve_path = _eve_location(yaml_bytes.decode("utf-8"))
    if expected_eve is not None and eve_path != expected_eve.expanduser():
        raise ValueError(f"Agent EVE setting {expected_eve} differs from Suricata's configured EVE path {eve_path}")
    eve_info = _stat_regular(eve_path)
    _require_no_acl(eve_path)
    directory_info = eve_path.parent.lstat()
    _require_no_acl(eve_path.parent, directory=True)
    if not stat.S_ISDIR(directory_info.st_mode) or not directory_info.st_mode & 0o100:
        raise ValueError(f"EVE parent directory must be a searchable regular directory: {eve_path.parent}")
    try:
        group = grp.getgrnam(group_name)
    except KeyError as exc:
        raise ValueError(f"Unknown trusted group: {exc}") from exc
    _reader_membership(agent_user, group.gr_gid)
    _reader_membership(dashboard_user, group.gr_gid)
    dashboard_log, dashboard_settings = _sdash_settings(dashboard_user)
    if dashboard_log != eve_path:
        raise ValueError(f"sdash for {dashboard_user} is configured for {dashboard_log}, not {eve_path}; resolve that difference before applying")
    expected = {
        "suricata_yaml": _render_yaml(yaml_bytes),
        "logrotate": _validate_logrotate(rotate_bytes),
    }
    state = {
        "eve_path": str(eve_path),
        "group": group_name,
        "group_gid": group.gr_gid,
        "agent_user": agent_user,
        "dashboard_user": dashboard_user,
        "before": {
            "eve": {"uid": eve_info.st_uid, "gid": eve_info.st_gid, "mode": stat.S_IMODE(eve_info.st_mode)},
            "log_directory": {"uid": directory_info.st_uid, "gid": directory_info.st_gid, "mode": stat.S_IMODE(directory_info.st_mode)},
            "suricata_yaml": {"sha256": _digest(yaml_bytes), "uid": yaml_info.st_uid, "gid": yaml_info.st_gid, "mode": stat.S_IMODE(yaml_info.st_mode)},
            "logrotate": {"sha256": _digest(rotate_bytes), "uid": rotate_info.st_uid, "gid": rotate_info.st_gid, "mode": stat.S_IMODE(rotate_info.st_mode)},
        },
        "after": {"eve": {"uid": eve_info.st_uid, "gid": group.gr_gid, "mode": 0o640},
                  "log_directory": {"uid": directory_info.st_uid, "gid": group.gr_gid,
                                    "mode": (stat.S_IMODE(directory_info.st_mode) & ~0o070) | 0o050 | stat.S_ISGID},
                  "suricata_yaml": _digest(expected["suricata_yaml"]), "logrotate": _digest(expected["logrotate"])},
        "original_contents": {"suricata_yaml": base64.b64encode(yaml_bytes).decode(), "logrotate": base64.b64encode(rotate_bytes).decode()},
        "new_contents": {"suricata_yaml": base64.b64encode(expected["suricata_yaml"]).decode(), "logrotate": base64.b64encode(expected["logrotate"]).decode()},
    }
    if dashboard_settings:
        account = pwd.getpwnam(dashboard_user)
        state["sdash_config"] = dashboard_settings
        state["after"]["sdash_config"] = {
            "file": {"uid": account.pw_uid, "gid": account.pw_gid, "mode": 0o600},
            "directory": {"uid": account.pw_uid, "gid": account.pw_gid, "mode": 0o700},
        }
        if not dashboard_settings["readable_by_dashboard_user"]:
            state["warnings"] = ["sdash settings are currently unreadable to the dashboard user; applying will make those saved preferences active"]
    return state


def _private_state_dir(path: Path) -> None:
    if path.is_symlink():
        raise PermissionError(f"State directory must not be a symlink: {path}")
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
        raise PermissionError(f"State directory must be owned by this user and mode 0700: {path}")


def _sync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _write_private(path: Path, data: bytes) -> None:
    descriptor, temporary = tempfile.mkstemp(prefix=".log-access-", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
        _sync_directory(path.parent)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def _replace_system_file(path: Path, data: bytes, original: dict) -> None:
    _read_regular(path)
    descriptor, temporary = tempfile.mkstemp(prefix=".suricata-access-", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.chown(temporary, original["uid"], original["gid"])
        os.chmod(temporary, original["mode"])
        os.replace(temporary, path)
        _sync_directory(path.parent)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def _audit(paths: Paths, action: str, state: dict) -> None:
    entry = {"at": datetime.now(timezone.utc).isoformat(), "action": action,
             "eve_path": state["eve_path"], "group": state["group"],
             "agent_user": state["agent_user"], "dashboard_user": state["dashboard_user"],
             "before": state["before"], "after": state["after"],
             "sdash_config_before": state.get("sdash_config")}
    audit_path = paths.state_dir / "changes.jsonl"
    descriptor = os.open(audit_path, os.O_WRONLY | os.O_CREAT | os.O_APPEND | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(descriptor, "a", encoding="utf-8") as stream:
        stream.write(json.dumps(entry, sort_keys=True) + "\n")
        stream.flush()
        os.fsync(stream.fileno())


def _apply_state(state: dict, paths: Paths, *, reverse: bool) -> None:
    observed: dict[str, bytes] = {}
    for key, path in (("suricata_yaml", paths.suricata_yaml), ("logrotate", paths.logrotate)):
        current, _ = _read_regular(path)
        observed[key] = current
        original_hash = state["before"][key]["sha256"]
        applied_hash = state["after"][key]
        allowed = (original_hash, applied_hash) if reverse else (original_hash,)
        if _digest(current) not in allowed:
            raise RuntimeError(f"{path} changed independently; refusing to overwrite it. Review the audit snapshot and restore manually.")
    eve_path = Path(state["eve_path"])
    directory = eve_path.parent
    directory_info = directory.lstat()
    if not stat.S_ISDIR(directory_info.st_mode):
        raise RuntimeError(f"EVE directory changed type: {directory}")
    current_directory = {"uid": directory_info.st_uid, "gid": directory_info.st_gid, "mode": stat.S_IMODE(directory_info.st_mode)}
    if current_directory not in (state["before"]["log_directory"], state["after"]["log_directory"]):
        raise RuntimeError(f"{directory} ownership/mode changed independently; refusing to overwrite it")
    info = _stat_regular(eve_path)
    current_eve = {"uid": info.st_uid, "gid": info.st_gid, "mode": stat.S_IMODE(info.st_mode)}
    if current_eve not in (state["before"]["eve"], state["after"]["eve"]):
        raise RuntimeError(f"{eve_path} ownership/mode changed independently; refusing to overwrite it")
    dashboard_current: dict | None = None
    if state.get("sdash_config"):
        dashboard_path = Path(state["sdash_config"]["path"])
        dashboard_content, dashboard_info = _read_regular(dashboard_path)
        dashboard_dir_info = dashboard_path.parent.lstat()
        if not stat.S_ISDIR(dashboard_dir_info.st_mode) or _digest(dashboard_content) != state["sdash_config"]["sha256"]:
            raise RuntimeError(f"sdash settings changed independently: {dashboard_path}")
        dashboard_current = {
            "file": {"uid": dashboard_info.st_uid, "gid": dashboard_info.st_gid, "mode": stat.S_IMODE(dashboard_info.st_mode)},
            "directory": {"uid": dashboard_dir_info.st_uid, "gid": dashboard_dir_info.st_gid, "mode": stat.S_IMODE(dashboard_dir_info.st_mode)},
        }
        for key in ("file", "directory"):
            if dashboard_current[key] not in (state["sdash_config"][key], state["after"]["sdash_config"][key]):
                raise RuntimeError(f"sdash {key} ownership/mode changed independently: {dashboard_path}")
    for key, path in (("suricata_yaml", paths.suricata_yaml), ("logrotate", paths.logrotate)):
        wanted = base64.b64decode(state["original_contents" if reverse else "new_contents"][key])
        if observed[key] != wanted:
            _replace_system_file(path, wanted, state["before"][key])
    wanted_directory = state["before"]["log_directory"] if reverse else state["after"]["log_directory"]
    if current_directory != wanted_directory:
        os.chown(directory, wanted_directory["uid"], wanted_directory["gid"])
        os.chmod(directory, wanted_directory["mode"])
    wanted_eve = state["before"]["eve"] if reverse else state["after"]["eve"]
    if current_eve != wanted_eve:
        os.chown(eve_path, wanted_eve["uid"], wanted_eve["gid"])
        os.chmod(eve_path, wanted_eve["mode"])
    if dashboard_current is not None:
        dashboard_path = Path(state["sdash_config"]["path"])
        wanted_dashboard = state["sdash_config"] if reverse else state["after"]["sdash_config"]
        order = ("file", "directory") if reverse else ("directory", "file")
        for key in order:
            if dashboard_current[key] == wanted_dashboard[key]:
                continue
            target = dashboard_path if key == "file" else dashboard_path.parent
            wanted = wanted_dashboard[key]
            os.chown(target, wanted["uid"], wanted["gid"])
            os.chmod(target, wanted["mode"])


def apply(group: str, agent_user: str, dashboard_user: str, *, expected_eve: Path | None = None, paths: Paths = Paths(), require_root: bool = True) -> dict:
    if require_root and os.geteuid() != 0:
        raise PermissionError("Applying system log access requires root; use the config menu's confirmed sudo action")
    state = plan(group, agent_user, dashboard_user, expected_eve=expected_eve, paths=paths)
    _private_state_dir(paths.state_dir)
    active = paths.state_dir / "active.json"
    if active.exists() or active.is_symlink():
        raise RuntimeError(f"A prior transition is active at {active}; revert it before applying another")
    state["phase"] = "pending"
    _write_private(active, json.dumps(state, sort_keys=True).encode())
    try:
        _apply_state(state, paths, reverse=False)
        _audit(paths, "apply", state)
    except Exception:
        try:
            _apply_state(state, paths, reverse=True)
            _audit(paths, "automatic_rollback", state)
            active.unlink()
            _sync_directory(paths.state_dir)
        except Exception:
            raise RuntimeError(f"Apply failed and automatic rollback was incomplete; inspect {active} and revert manually") from None
        raise
    state["phase"] = "active"
    _write_private(active, json.dumps(state, sort_keys=True).encode())
    return state


def revert(*, paths: Paths = Paths(), require_root: bool = True) -> dict:
    if require_root and os.geteuid() != 0:
        raise PermissionError("Reverting system log access requires root; use the config menu's confirmed sudo action")
    _private_state_dir(paths.state_dir)
    active = paths.state_dir / "active.json"
    raw, info = _read_regular(active)
    if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o600:
        raise PermissionError(f"Transition state must be owner-only: {active}")
    state = json.loads(raw)
    _apply_state(state, paths, reverse=True)
    _audit(paths, "revert", state)
    active.unlink()
    _sync_directory(paths.state_dir)
    return state


def history(*, paths: Paths = Paths(), require_root: bool = True) -> list[dict]:
    if require_root and os.geteuid() != 0:
        raise PermissionError("Reading the root-owned access audit requires root")
    _private_state_dir(paths.state_dir)
    audit_path = paths.state_dir / "changes.jsonl"
    if not audit_path.exists():
        return []
    data, info = _read_regular(audit_path)
    if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o600:
        raise PermissionError(f"Audit log must be owner-only: {audit_path}")
    return [json.loads(line) for line in data.splitlines() if line]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Audited Suricata EVE access transition; no service restart")
    commands = parser.add_subparsers(dest="action", required=True)
    for name in ("plan", "apply"):
        command = commands.add_parser(name)
        command.add_argument("--group", required=True)
        command.add_argument("--agent-user", required=True)
        command.add_argument("--dashboard-user", required=True)
        command.add_argument("--expected-eve", type=Path, required=True)
    commands.add_parser("revert")
    commands.add_parser("history")
    args = parser.parse_args(argv)
    try:
        if args.action == "history":
            print(json.dumps(history()[-20:], indent=2, sort_keys=True))
        elif args.action == "revert":
            state = revert()
            print(f"Reverted EVE access for {state['eve_path']}; previous owner/group/mode restored")
        else:
            details = plan(args.group, args.agent_user, args.dashboard_user, expected_eve=args.expected_eve) if args.action == "plan" else apply(args.group, args.agent_user, args.dashboard_user, expected_eve=args.expected_eve)
            public = {key: details[key] for key in ("eve_path", "group", "agent_user", "dashboard_user", "before", "after")}
            if details.get("sdash_config"):
                public["sdash_config_before"] = details["sdash_config"]
            if details.get("warnings"):
                public["warnings"] = details["warnings"]
            print(json.dumps(public, indent=2, sort_keys=True))
            if args.action == "plan":
                print("Preview only. Apply requires root and does not restart Suricata or sdash.")
            else:
                print("Applied. Existing readers should reopen EVE; verify after the next rotation/restart.")
        return 0
    except (OSError, ValueError, RuntimeError) as exc:
        parser.exit(1, f"Log access error: {exc}\n")


if __name__ == "__main__":
    raise SystemExit(main())
