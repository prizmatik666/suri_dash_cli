#!/usr/bin/env python3
"""Manage local agent options and create explicit, consistent index backups."""

from __future__ import annotations

import argparse
import json
import os
import pwd
import sqlite3
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

from core.agent_config import DEFAULTS, _private_directory, check_source_log_permissions, default_config_path, load_config, save_config, validate_config
from core.eve_index import EveIndex, default_index_path


def backup_index(config: dict, destination: Path | None = None) -> Path:
    backup_setting = config["security"]["backup_directory"]
    if destination is None and not backup_setting:
        raise ValueError("Set security.backup_directory or provide --destination")
    directory = Path(destination or backup_setting).expanduser()
    _private_directory(directory, create=True)
    index_path = Path(config["index_path"]).expanduser() if config["index_path"] else default_index_path(Path(config["eve_log"]).expanduser())
    # Check all index files before SQLite reads them; do not create a missing source.
    if not index_path.is_file():
        raise FileNotFoundError(f"Index does not exist: {index_path}")
    EveIndex._prepare_index_path(index_path)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    target = directory / f"{index_path.stem}-{timestamp}.sqlite3"
    descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    os.close(descriptor)
    try:
        source = sqlite3.connect(f"{index_path.resolve().as_uri()}?mode=ro", uri=True, timeout=30)
        destination_db = sqlite3.connect(str(target), timeout=30)
        try:
            source.backup(destination_db)
        finally:
            destination_db.close()
            source.close()
        if target.stat().st_mode & 0o077:
            raise PermissionError(f"Backup lost owner-only permissions: {target}")
        return target
    except BaseException:
        target.unlink(missing_ok=True)
        raise


def run_interactive(config_path: Path, *, input_fn=None, output_fn=None) -> int:
    """Edit a draft locally; only Save writes options to disk."""
    read = input_fn or input
    write = output_fn or print
    current = load_config(config_path)
    saved = json.loads(json.dumps(current))
    security_helper = Path(__file__).resolve().parent / "core" / "suricata_log_access.py"

    def system_action(action: str, *extra: str) -> bool:
        command = [sys.executable, str(security_helper), action, *extra]
        if os.geteuid() != 0:
            command.insert(0, "sudo")
        try:
            result = subprocess.run(command, check=False)
        except OSError as exc:
            write(f"Could not start system-access helper: {exc}")
            return False
        if result.returncode:
            write(f"{action} did not complete (exit {result.returncode}); no agent options were changed.")
            return False
        return True

    def prompt_value(label: str, value: str | None, *, optional: bool = False) -> str | None:
        hint = " (Enter keeps current" + (", 'none' clears" if optional else "") + ")"
        entered = read(f"{label} [{value or 'default'}]{hint}: ").strip()
        if not entered:
            return value
        if optional and entered.lower() == "none":
            return None
        return entered

    while True:
        dirty = current != saved
        write("\nSuricata agent configuration" + ("  [unsaved changes]" if dirty else ""))
        write(f"File: {config_path}" + (" (not created yet)" if not config_path.exists() else ""))
        write(f"1. EVE log: {current['eve_log']}")
        write(f"2. SQLite index: {current['index_path'] or 'automatic per-log path'}")
        write(f"3. Debug logging: {'on' if current['debug'] else 'off'}")
        write(f"4. Configure source-log access: {current['security']['source_log_permissions']}")
        write("   Choices: warn / require_private / trusted_group")
        write(f"   Trusted log group: {current['security']['trusted_log_group'] or 'not configured'}")
        write(f"5. Backup directory: {current['security']['backup_directory'] or 'not configured'}")
        write("6. Check source and resolved index paths")
        write("7. Create an index backup (asks for confirmation)")
        write("8. Save changes")
        write("9. Quit")
        write("10. Preview and apply EVE access for agent + sdash (sudo)")
        write("11. Revert the previous EVE access change (sudo)")
        write("12. View EVE access change history (sudo)")
        choice = read("Choose 1-12: ").strip().lower()
        if choice in ("1", "2", "5"):
            key = {"1": "eve_log", "2": "index_path", "5": "backup_directory"}[choice]
            if choice == "5":
                existing = current["security"][key]
                updated = prompt_value("Backup directory", existing, optional=True)
                current["security"][key] = updated
            else:
                existing = current[key]
                updated = prompt_value("EVE log" if choice == "1" else "SQLite index", existing, optional=choice == "2")
                current[key] = updated
            try:
                validate_config(current)
            except ValueError as exc:
                if choice == "5":
                    current["security"][key] = existing
                else:
                    current[key] = existing
                write(f"Not changed: {exc}")
        elif choice == "3":
            current["debug"] = not current["debug"]
            write(f"Debug logging is now {'on' if current['debug'] else 'off'} in the draft.")
        elif choice == "4":
            write("1. warn — report exposed source-log permissions and continue")
            write("2. require_private — refuse to start if group/other can read the source log")
            write("3. trusted_group — allow read-only access to one named log group, never others")
            selected = read("Choose 1, 2, or 3 (Enter keeps current): ").strip()
            if selected in ("1", "2", "3"):
                old_policy = current["security"]["source_log_permissions"]
                old_group = current["security"]["trusted_log_group"]
                if selected == "3":
                    entered = read(f"Trusted log group [{old_group or 'not set'}]: ").strip()
                    if entered:
                        current["security"]["trusted_log_group"] = entered
                current["security"]["source_log_permissions"] = {"1": "warn", "2": "require_private", "3": "trusted_group"}[selected]
                try:
                    validate_config(current)
                except ValueError as exc:
                    current["security"]["source_log_permissions"] = old_policy
                    current["security"]["trusted_log_group"] = old_group
                    write(f"Not changed: {exc}")
            elif selected:
                write("Not changed: choose 1, 2, or 3.")
        elif choice == "6":
            source = Path(current["eve_log"]).expanduser()
            index = Path(current["index_path"]).expanduser() if current["index_path"] else default_index_path(source)
            write(f"EVE source: {source} ({'readable' if os.access(source, os.R_OK) else 'not readable or missing'})")
            try:
                warning = check_source_log_permissions(source, current["security"]["source_log_permissions"], current["security"]["trusted_log_group"])
                write(warning or "Source-log permission policy: passed (or source is unavailable).")
            except (PermissionError, ValueError) as exc:
                write(f"Source-log permission policy: FAILED — {exc}")
            write(f"Resolved SQLite index: {index} ({'exists' if index.is_file() else 'not created yet'})")
        elif choice == "7":
            if not current["security"]["backup_directory"]:
                write("Set a backup directory in option 5 first.")
                continue
            index = Path(current["index_path"]).expanduser() if current["index_path"] else default_index_path(Path(current["eve_log"]).expanduser())
            write(f"Back up {index} to {current['security']['backup_directory']}?")
            if read("Type YES to create the backup: ").strip() != "YES":
                write("Backup cancelled.")
                continue
            try:
                write(f"Backup created: {backup_index(current)}")
            except (OSError, ValueError, sqlite3.Error) as exc:
                write(f"Backup failed: {exc}")
        elif choice == "8":
            try:
                save_config(current, config_path)
            except (OSError, ValueError) as exc:
                write(f"Could not save: {exc}")
            else:
                saved = json.loads(json.dumps(current))
                write(f"Saved to {config_path}. Changes take effect on the next agent start.")
        elif choice == "10":
            if dirty or not config_path.exists():
                write("Save agent options first (option 8), then return here so the plan matches the saved EVE path.")
                continue
            default_user = pwd.getpwuid(os.getuid()).pw_name
            group = read(f"Trusted log group [{current['security']['trusted_log_group'] or 'required'}]: ").strip() or current["security"]["trusted_log_group"]
            if not group:
                write("Choose an existing dedicated group first; nothing changed.")
                continue
            agent_user = read(f"Agent user [{default_user}]: ").strip() or default_user
            dashboard_user = read(f"sdash user [{default_user}]: ").strip() or default_user
            options = ("--group", group, "--agent-user", agent_user, "--dashboard-user", dashboard_user,
                       "--expected-eve", str(Path(current["eve_log"]).expanduser()))
            write("Checking Suricata, logrotate, EVE, and sdash settings; sudo may prompt for your password.")
            if not system_action("plan", *options):
                continue
            write("Apply changes the live EVE and log-directory group/mode plus Suricata's EVE filemode.")
            write("The shared logrotate rule is checked but left unchanged.")
            write("A root-only snapshot and audit entry will allow a later revert. Services are not restarted.")
            if read("Type APPLY to proceed: ").strip() != "APPLY":
                write("Apply cancelled; no system files changed.")
                continue
            if system_action("apply", *options):
                current["security"]["trusted_log_group"] = group
                current["security"]["source_log_permissions"] = "trusted_group"
                try:
                    save_config(current, config_path)
                except (OSError, ValueError) as exc:
                    write(f"System change succeeded, but agent options could not be saved: {exc}. Revert with option 11 if needed.")
                else:
                    saved = json.loads(json.dumps(current))
                    write("Agent policy saved. Restart agent and sdash, then verify access and check again after log rotation.")
        elif choice == "11":
            write("Revert restores the recorded Suricata/logrotate content and previous EVE owner, group, and mode.")
            if read("Type REVERT to proceed: ").strip() != "REVERT":
                write("Revert cancelled.")
                continue
            if system_action("revert"):
                current["security"]["source_log_permissions"] = "warn"
                try:
                    save_config(current, config_path)
                except (OSError, ValueError) as exc:
                    write(f"System revert succeeded, but agent options could not be saved: {exc}")
                else:
                    saved = json.loads(json.dumps(current))
                    write("Agent policy reset to warn. Restart agent and sdash to recheck access.")
        elif choice == "12":
            system_action("history")
        elif choice in ("9", "q", "quit", "exit"):
            if dirty:
                answer = read("Unsaved changes: [s]ave, [d]iscard, or [c]ancel quit? ").strip().lower()
                if answer in ("s", "save"):
                    try:
                        save_config(current, config_path)
                    except (OSError, ValueError) as exc:
                        write(f"Could not save: {exc}")
                        continue
                    write(f"Saved to {config_path}.")
                elif answer not in ("d", "discard"):
                    continue
            write("Configuration closed.")
            return 0
        else:
            write("Choose a menu number from 1 to 12.")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Configure the Suricata agent without using the model API",
        epilog="Run without a subcommand in a terminal to open the interactive setup menu.",
    )
    parser.add_argument("--config", type=Path, default=default_config_path(), help="Owner-only JSON config path")
    commands = parser.add_subparsers(dest="command")
    commands.add_parser("init", help="Create a config file with safe defaults")
    commands.add_parser("show", help="Show the effective config without changing it")
    setter = commands.add_parser("set", help="Set one supported option")
    setter.add_argument("key", choices=("eve_log", "index_path", "debug", "security.source_log_permissions", "security.trusted_log_group", "security.backup_directory"))
    setter.add_argument("value", help="Use 'none' to clear optional paths")
    backup = commands.add_parser("backup-index", help="Create an explicit online SQLite backup in an owner-only directory")
    backup.add_argument("--destination", type=Path, help="Override security.backup_directory")
    args = parser.parse_args(argv)
    try:
        if args.command is None:
            if not sys.stdin.isatty():
                parser.error("interactive mode needs a terminal; use init, show, set, or backup-index in scripts")
            return run_interactive(args.config)
        if args.command == "init":
            if args.config.exists() or args.config.is_symlink():
                raise FileExistsError(f"Configuration already exists: {args.config}")
            save_config(json.loads(json.dumps(DEFAULTS)), args.config)
            print(f"Created {args.config}")
        elif args.command == "show":
            print(json.dumps(load_config(args.config), indent=2, sort_keys=True))
        elif args.command == "set":
            config = load_config(args.config)
            value = args.value
            if args.key in ("index_path", "security.trusted_log_group", "security.backup_directory") and value.lower() == "none":
                value = None
            elif args.key == "debug":
                if value.lower() not in ("true", "false"):
                    raise ValueError("debug must be true or false")
                value = value.lower() == "true"
            if args.key.startswith("security."):
                config["security"][args.key.split(".", 1)[1]] = value
            else:
                config[args.key] = value
            save_config(config, args.config)
            print(f"Updated {args.config}")
        else:
            print(backup_index(load_config(args.config), args.destination))
        return 0
    except (KeyboardInterrupt, EOFError):
        print("\nConfiguration closed; unsaved changes discarded.")
        return 0
    except (OSError, ValueError, sqlite3.Error) as exc:
        parser.exit(1, f"Config error: {exc}\n")


if __name__ == "__main__":
    raise SystemExit(main())
