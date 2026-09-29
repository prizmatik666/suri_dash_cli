"""Validated, owner-only local configuration for the Suricata agent."""

from __future__ import annotations

import json
import os
import grp
import errno
import shlex
import stat
import tempfile
from pathlib import Path
from typing import Any


CONFIG_VERSION = 1
DEFAULTS: dict[str, Any] = {
    "version": CONFIG_VERSION,
    "eve_log": "/var/log/suricata/eve.json",
    "index_path": None,
    "debug": False,
    "security": {
        "source_log_permissions": "warn",
        "trusted_log_group": None,
        "backup_directory": None,
    },
}


def default_config_path() -> Path:
    root = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config")).expanduser()
    return root / "suricata-agent" / "config.json"


def _private_directory(path: Path, *, create: bool) -> None:
    path = Path(os.path.abspath(path.expanduser()))
    for directory in reversed((path, *path.parents)):
        if directory.is_symlink():
            raise PermissionError(f"Configuration path contains a symbolic link: {directory}")
    if create:
        path.mkdir(parents=True, exist_ok=True, mode=0o700)
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise PermissionError(f"Directory must be owned by this user and mode 0700: {path}")


def _private_file(path: Path) -> None:
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise PermissionError(f"Configuration file must be a regular owner-only file: {path}")


def validate_config(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != set(DEFAULTS):
        raise ValueError(f"Configuration must contain exactly: {', '.join(DEFAULTS)}")
    if type(value["version"]) is not int or value["version"] != CONFIG_VERSION:
        raise ValueError(f"Unsupported configuration version: {value.get('version')}")
    for key in ("eve_log", "index_path"):
        field = value[key]
        if (key == "eve_log" and (not isinstance(field, str) or not field.strip())) or (key == "index_path" and field is not None and (not isinstance(field, str) or not field.strip())):
            raise ValueError(f"{key} must be a nonempty path string" + (" or null" if key == "index_path" else ""))
    if type(value["debug"]) is not bool:
        raise ValueError("debug must be true or false")
    security = value["security"]
    # Accept files written before trusted_log_group was introduced.
    if not isinstance(security, dict) or not {"source_log_permissions", "backup_directory"} <= set(security) or set(security) - set(DEFAULTS["security"]):
        raise ValueError("security must contain source_log_permissions and backup_directory; trusted_log_group is optional")
    security.setdefault("trusted_log_group", None)
    if security["source_log_permissions"] not in ("warn", "require_private", "trusted_group"):
        raise ValueError("source_log_permissions must be warn, require_private, or trusted_group")
    group = security["trusted_log_group"]
    if group is not None and (not isinstance(group, str) or not group.strip()):
        raise ValueError("trusted_log_group must be a nonempty group name or null")
    if security["source_log_permissions"] == "trusted_group" and not group:
        raise ValueError("trusted_group policy requires security.trusted_log_group")
    backup = security["backup_directory"]
    if backup is not None and (not isinstance(backup, str) or not backup.strip()):
        raise ValueError("backup_directory must be a nonempty path string or null")
    return value


def load_config(path: Path | str | None = None) -> dict[str, Any]:
    selected = Path(path).expanduser() if path is not None else default_config_path()
    if not selected.exists() and not selected.is_symlink():
        return json.loads(json.dumps(DEFAULTS))
    _private_directory(selected.parent, create=False)
    _private_file(selected)
    with selected.open("r", encoding="utf-8") as stream:
        return validate_config(json.load(stream))


def save_config(value: dict[str, Any], path: Path | str | None = None) -> Path:
    validate_config(value)
    selected = Path(path).expanduser() if path is not None else default_config_path()
    _private_directory(selected.parent, create=True)
    if selected.exists() or selected.is_symlink():
        _private_file(selected)
    descriptor, temporary = tempfile.mkstemp(prefix=".config-", dir=selected.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(value, stream, indent=2, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, selected)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    return selected


def source_access_error(path: Path, exc: OSError) -> PermissionError:
    quoted = shlex.quote(str(path))
    return PermissionError(
        f"Cannot read EVE source {path}: {exc.strerror or exc}. "
        f"Check file and parent-directory access with `namei -l {quoted}`, "
        f"`stat -c '%a %U:%G %n' {quoted}`, and `id -nG`. "
        "The agent needs file read permission and directory search (x) permission. "
        "If using a dedicated log group, make the agent user a member, keep the EVE file group-readable, "
        "set the EVE logger's `filemode: 640`, and ensure Suricata/log rotation preserve that group and mode. "
        "Then select security.source_log_permissions=trusted_group and security.trusted_log_group=<group>. "
        "Do not make the log world-readable."
    )


def check_source_log_permissions(path: Path, policy: str, trusted_group: str | None = None) -> str | None:
    """Check source mode and actual readability without changing Suricata files."""
    try:
        info = path.stat()
    except FileNotFoundError:
        return None
    except PermissionError as exc:
        raise source_access_error(path, exc) from exc
    if not stat.S_ISREG(info.st_mode):
        raise ValueError(f"EVE source is not a regular file: {path}")
    if policy in ("require_private", "trusted_group") and hasattr(os, "getxattr"):
        try:
            os.getxattr(path, "system.posix_acl_access")
        except OSError as exc:
            if exc.errno not in (errno.ENODATA, errno.ENOTSUP, errno.EOPNOTSUPP):
                raise source_access_error(path, exc) from exc
        else:
            raise PermissionError(
                f"EVE source has an extended access ACL: {path}. "
                f"This mode-based policy cannot prove its recipients; review `getfacl {shlex.quote(str(path))}` "
                "and remove extra ACL grants before using a strict policy."
            )
    mode = stat.S_IMODE(info.st_mode)
    exposure = f"EVE source log permits group/other access ({mode:04o}): {path}"
    if policy == "require_private" and mode & 0o077:
        raise PermissionError(f"{exposure}. Use owner-only access or select trusted_group with a dedicated group.")
    if policy == "trusted_group":
        if not trusted_group:
            raise ValueError("trusted_group policy requires security.trusted_log_group")
        try:
            group = grp.getgrnam(trusted_group)
        except KeyError as exc:
            raise ValueError(f"Trusted log group '{trusted_group}' does not exist; create/select it before enabling this policy") from exc
        if mode & 0o007:
            raise PermissionError(f"{exposure}. Remove all 'other' permissions before using trusted_group.")
        if mode & 0o030:
            raise PermissionError(f"EVE source group permissions are broader than read-only ({mode:04o}): {path}; use a group-read mode such as 0640.")
        if mode & 0o040:
            if info.st_gid != group.gr_gid:
                try:
                    actual = grp.getgrgid(info.st_gid).gr_name
                except KeyError:
                    actual = str(info.st_gid)
                raise PermissionError(f"EVE source group is {actual}, but trusted_log_group is {trusted_group}; align the log group and rotation settings.")
            if info.st_uid != os.geteuid() and group.gr_gid not in {*os.getgroups(), os.getegid()}:
                raise PermissionError(f"Agent user is not in trusted log group '{trusted_group}'; add the user to that group and start a new login/session, then check `id -nG`.")
        elif info.st_uid != os.geteuid():
            raise PermissionError(f"EVE source has no group read bit ({mode:04o}) and is owned by another user; allow read access for trusted group '{trusted_group}'.")
    try:
        with path.open("rb"):
            pass
    except PermissionError as exc:
        raise source_access_error(path, exc) from exc
    return exposure if policy == "warn" and mode & 0o077 else None
