#!/usr/bin/env python3
"""Full-screen guided settings panel for the Suricata v3.5 dashboard."""

from __future__ import annotations

import curses
import subprocess
import sys
from pathlib import Path
from typing import Any

from sdash_defaults import FACTORY_DEFAULTS, default_config_path, effective_config, save_user_config


APP_TITLE = "SURICATA LIVE DASHBOARD v3.5 - PRIZM BUILD SETUP"


def bool_text(value: bool) -> str:
    return "ON" if value else "OFF"


def settings_rows(settings: dict[str, Any]) -> list[tuple[str, str]]:
    return [
        ("EVE log path", str(settings["log"])),
        ("Scan threshold", str(settings["scan_threshold"])),
        ("Light threshold", str(settings["light_threshold"])),
        ("Heuristic window", f"{settings['window']} seconds"),
        ("Recent-event limit", str(settings["max_events"])),
        ("Suppress DNS/mDNS", bool_text(settings["suppress_dns"])),
        ("Hide DNS Recent Events", bool_text(settings["hide_dns_events"])),
        ("Ignore DNS scan heuristic", bool_text(settings["ignore_dns_scans"])),
        ("Trusted DNS servers", ", ".join(settings["dns_server"]) or "none"),
        ("Full IPv6 display", bool_text(settings["full_ip"])),
        ("Read existing log at start", bool_text(settings["no_follow_end"])),
    ]


def prompt_value(screen, label: str, current: str) -> str | None:
    curses.def_prog_mode()
    curses.endwin()
    try:
        answer = input(f"{label} [{current}]: ").strip()
    finally:
        curses.reset_prog_mode()
        screen.refresh()
    return answer or current


def edit_setting(screen, settings: dict[str, Any], index: int) -> str:
    keys = ["log", "scan_threshold", "light_threshold", "window", "max_events", "suppress_dns", "hide_dns_events", "ignore_dns_scans", "dns_server", "full_ip", "no_follow_end"]
    key = keys[index]
    if key in {"suppress_dns", "hide_dns_events", "ignore_dns_scans", "full_ip", "no_follow_end"}:
        settings[key] = not settings[key]
        return f"{key} toggled"

    current = ",".join(settings[key]) if key == "dns_server" else str(settings[key])
    answer = prompt_value(screen, settings_rows(settings)[index][0], current)
    if answer is None:
        return "unchanged"
    try:
        if key in {"scan_threshold", "light_threshold", "window", "max_events"}:
            value = int(answer)
            if value < 1 or (key == "max_events" and value < 5):
                raise ValueError
            settings[key] = value
        elif key == "dns_server":
            settings[key] = [item.strip() for item in answer.split(",") if item.strip()]
        else:
            settings[key] = answer
    except ValueError:
        return "invalid value; unchanged"
    return "updated"


def launch_interface_tool(screen) -> str:
    tool = Path(__file__).resolve().with_name("suricata_interface_tool.py")
    curses.def_prog_mode()
    curses.endwin()
    try:
        result = subprocess.run(["sudo", sys.executable, str(tool)], check=False)
        input("\nPress Enter to return to the setup panel...")
    except OSError as exc:
        print(f"Could not launch interface tool: {exc}")
        input("Press Enter to return to the setup panel...")
        result = None
    finally:
        curses.reset_prog_mode()
        screen.refresh()
    if result is None:
        return "interface tool could not start"
    return f"interface tool exited with status {result.returncode}"


def draw(screen) -> None:
    curses.curs_set(0)
    screen.keypad(True)
    screen.timeout(250)
    settings = effective_config()
    selected = 0
    status = "Factory defaults loaded; press s to save user settings."
    rows = settings_rows(settings)

    while True:
        screen.erase()
        height, width = screen.getmaxyx()
        screen.addnstr(0, 0, APP_TITLE, max(1, width - 1), curses.A_BOLD)
        screen.addnstr(1, 0, f"Config: {default_config_path()}", max(1, width - 1))
        screen.addnstr(2, 0, "Up/Down select  Enter edit/toggle  s save  f factory reset  i interface  q quit", max(1, width - 1), curses.A_DIM)
        rows = settings_rows(settings)
        for offset, (label, value) in enumerate(rows, start=4):
            marker = "> " if offset - 4 == selected else "  "
            screen.addnstr(offset, 0, f"{marker}{label:<28} {value}", max(1, width - 1), curses.A_REVERSE if offset - 4 == selected else 0)
        screen.addnstr(min(height - 2, 17), 0, "Built-in defaults are never changed; factory reset restores the shipped v3.5 baseline.", max(1, width - 1), curses.A_DIM)
        screen.addnstr(height - 1, 0, status, max(1, width - 1), curses.A_BOLD)
        screen.refresh()

        key = screen.getch()
        if key in (ord("q"), 27):
            return
        if key == curses.KEY_UP:
            selected = (selected - 1) % len(rows)
        elif key == curses.KEY_DOWN:
            selected = (selected + 1) % len(rows)
        elif key in (10, 13):
            status = edit_setting(screen, settings, selected)
        elif key == ord("s"):
            try:
                path = save_user_config(settings)
                status = f"Saved settings to {path}"
            except OSError as exc:
                status = f"Save failed: {exc.__class__.__name__}"
        elif key == ord("f"):
            settings = dict(FACTORY_DEFAULTS)
            try:
                path = save_user_config(settings)
                status = f"Factory defaults restored to {path}"
            except OSError as exc:
                status = f"Reset failed: {exc.__class__.__name__}"
        elif key == ord("i"):
            status = launch_interface_tool(screen)


def main() -> int:
    try:
        curses.wrapper(draw)
    except KeyboardInterrupt:
        return 130
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
