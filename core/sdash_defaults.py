"""Factory defaults and safe user-config persistence for sdash."""

from __future__ import annotations

import json
import os
import pwd
import tempfile
from pathlib import Path
from typing import Any


FACTORY_DEFAULTS: dict[str, Any] = {
    "log": "/var/log/suricata/eve.json",
    "scan_threshold": 5,
    "light_threshold": 2,
    "window": 30,
    "max_events": 40,
    "full_ip": False,
    "no_follow_end": False,
    "hide_dns_events": False,
    "suppress_dns": False,
    "ignore_dns_scans": False,
    "dns_server": [],
}

CONFIG_KEYS = frozenset(FACTORY_DEFAULTS)


def default_config_path() -> Path:
    configured = os.environ.get("SDASH_CONFIG")
    if configured:
        return Path(configured).expanduser()
    config_home = Path.home()
    # Preserve the invoking user's settings when sdash is launched with sudo.
    sudo_user = os.environ.get("SUDO_USER") if os.geteuid() == 0 else None
    if sudo_user:
        try:
            config_home = Path(pwd.getpwnam(sudo_user).pw_dir)
        except KeyError:
            pass
    return config_home / ".config" / "sdash" / "config.json"


def load_user_config(path: Path | None = None) -> dict[str, Any]:
    config_path = path or default_config_path()
    try:
        data = json.loads(config_path.read_text(encoding="utf-8"))
    except (FileNotFoundError, OSError, json.JSONDecodeError):
        return {}
    if not isinstance(data, dict):
        return {}
    settings: dict[str, Any] = {}
    integer_keys = {"scan_threshold", "light_threshold", "window", "max_events"}
    boolean_keys = {"full_ip", "no_follow_end", "hide_dns_events", "suppress_dns", "ignore_dns_scans"}
    for key in CONFIG_KEYS:
        if key not in data:
            continue
        value = data[key]
        if key in integer_keys and isinstance(value, int) and not isinstance(value, bool):
            settings[key] = value
        elif key in boolean_keys and isinstance(value, bool):
            settings[key] = value
        elif key in {"log"} and isinstance(value, str):
            settings[key] = value
        elif key == "dns_server" and isinstance(value, list) and all(isinstance(item, str) for item in value):
            settings[key] = value
    return settings


def effective_config(path: Path | None = None, *, factory_only: bool = False) -> dict[str, Any]:
    settings = dict(FACTORY_DEFAULTS)
    if not factory_only:
        settings.update(load_user_config(path))
    return settings


def save_user_config(settings: dict[str, Any], path: Path | None = None) -> Path:
    config_path = path or default_config_path()
    config_path.parent.mkdir(parents=True, exist_ok=True)
    payload = {key: settings.get(key, FACTORY_DEFAULTS[key]) for key in CONFIG_KEYS}
    fd, temporary = tempfile.mkstemp(prefix=f".{config_path.name}.", dir=config_path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, config_path)
    except Exception:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise
    return config_path
