#!/usr/bin/env python3
"""Guided, validation-first AF_PACKET interface selector for Suricata."""

from __future__ import annotations

import argparse
import os
import re
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime
from pathlib import Path


DEFAULT_CONFIG = Path("/etc/suricata/suricata.yaml")


def run(command: list[str], *, capture: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        text=True,
        capture_output=capture,
        check=False,
    )


def interface_info() -> list[dict[str, str]]:
    result = run(["ip", "-o", "link", "show"])
    if result.returncode:
        raise RuntimeError(result.stderr.strip() or "ip could not enumerate interfaces")

    interfaces = []
    for line in result.stdout.splitlines():
        match = re.match(r"^\d+: ([^:]+):\s+<([^>]*)>.*?link/\S+\s+([^\s]+)", line)
        if not match:
            continue
        name = match.group(1).split("@", 1)[0]
        flags = match.group(2)
        mac = match.group(3)
        state_file = Path("/sys/class/net") / name / "operstate"
        state = state_file.read_text().strip() if state_file.exists() else "unknown"
        mode = "-"
        iw = run(["iw", "dev", name, "info"])
        if iw.returncode == 0:
            mode_match = re.search(r"^\s*type\s+(\S+)", iw.stdout, re.MULTILINE)
            if mode_match:
                mode = mode_match.group(1)
        interfaces.append({"name": name, "state": state, "mode": mode, "mac": mac, "flags": flags})
    return interfaces


def af_packet_block(text: str) -> tuple[list[int], list[tuple[int, str]]]:
    lines = text.splitlines(keepends=True)
    starts = [i for i, line in enumerate(lines) if re.match(r"^af-packet:\s*$", line.rstrip("\n"))]
    if len(starts) != 1:
        raise RuntimeError(f"expected exactly one top-level af-packet block; found {len(starts)}")

    start = starts[0]
    end = len(lines)
    for i in range(start + 1, len(lines)):
        if re.match(r"^[A-Za-z0-9_-]+:\s*", lines[i]):
            end = i
            break

    entries = []
    for i in range(start + 1, end):
        match = re.match(r"^(\s*)-\s*interface:\s*(\S+)\s*(#.*)?(\r?\n)?$", lines[i])
        if match:
            entries.append((i, match.group(2)))
    return lines, entries


def choose_interface(interfaces: list[dict[str, str]]) -> str | None:
    print("\nAvailable interfaces:\n")
    for number, info in enumerate(interfaces, 1):
        print(f"  {number}) {info['name']:<12} state={info['state']:<8} mode={info['mode']:<8} mac={info['mac']}")
    print("\n  q) Cancel")
    while True:
        answer = input("\nSelect the Suricata interface: ").strip().lower()
        if answer == "q":
            return None
        if answer.isdigit() and 1 <= int(answer) <= len(interfaces):
            return interfaces[int(answer) - 1]["name"]
        print("Enter one of the displayed numbers, or q.")


def write_config(config: Path, lines: list[str], line_number: int, interface: str) -> None:
    old = lines[line_number]
    replacement = re.sub(r"(-\s*interface:\s*)\S+", rf"\g<1>{interface}", old, count=1)
    lines[line_number] = replacement
    mode = config.stat().st_mode & 0o777
    uid = config.stat().st_uid
    gid = config.stat().st_gid
    fd, temporary = tempfile.mkstemp(prefix=f".{config.name}.", dir=config.parent)
    try:
        with os.fdopen(fd, "w") as handle:
            handle.writelines(lines)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, mode)
        os.chown(temporary, uid, gid)
        os.replace(temporary, config)
    except Exception:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise


def main() -> int:
    parser = argparse.ArgumentParser(description="Safely select Suricata's AF_PACKET interface.")
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    parser.add_argument("--no-restart", action="store_true", help="Validate and stop before restarting Suricata.")
    args = parser.parse_args()

    if os.geteuid() != 0:
        print("Run this tool with sudo; it must back up and edit the system Suricata configuration.", file=sys.stderr)
        return 2
    if not args.config.is_file():
        print(f"Configuration not found: {args.config}", file=sys.stderr)
        return 2

    try:
        interfaces = interface_info()
        original_text = args.config.read_text()
        lines, entries = af_packet_block(original_text)
    except (OSError, RuntimeError) as exc:
        print(f"Cannot inspect Suricata/interface state: {exc}", file=sys.stderr)
        return 1

    if len(entries) != 1:
        print(f"Refusing to guess: active af-packet block contains {len(entries)} interface entries.", file=sys.stderr)
        print("Consolidate the AF_PACKET configuration manually, then rerun this tool.", file=sys.stderr)
        return 1

    current = entries[0][1]
    print(f"Current Suricata AF_PACKET interface: {current}")
    selected = choose_interface(interfaces)
    if selected is None:
        print("Cancelled; no files changed.")
        return 0
    if selected == current:
        print(f"Already configured for {selected}; no files changed.")
        return 0

    selected_info = next(info for info in interfaces if info["name"] == selected)
    if selected_info["mode"] == "monitor":
        print("\nWARNING: this interface is in monitor mode and may deliver raw 802.11 frames.")
        print("AF_PACKET flow visibility may be limited unless the driver presents decoded Ethernet/IP frames.")
    if input(f"\nChange Suricata from {current} to {selected}? [y/N] ").strip().lower() != "y":
        print("Cancelled; no files changed.")
        return 0

    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    backup = args.config.with_name(f"{args.config.name}.bak-{stamp}")
    try:
        shutil.copy2(args.config, backup)
        write_config(args.config, lines, entries[0][0], selected)
    except OSError as exc:
        print(f"Change failed before validation: {exc}", file=sys.stderr)
        return 1
    print(f"Backup created: {backup}")

    print("\nValidating Suricata configuration...")
    validation = run(["suricata", "-T", "-c", str(args.config)], capture=False)
    if validation.returncode != 0:
        shutil.copy2(backup, args.config)
        print("Validation failed; the original configuration was restored.", file=sys.stderr)
        return validation.returncode or 1
    print("Validation passed.")

    if args.no_restart:
        print("No restart requested. The new interface is not active until Suricata is restarted/reloaded.")
        return 0
    if input("Restart Suricata now? [Y/n] ").strip().lower() not in ("", "y", "yes"):
        print("Configuration saved and validated; Suricata was not restarted.")
        return 0

    restart = run(["systemctl", "restart", "suricata"], capture=False)
    if restart.returncode:
        print("Suricata restart failed; inspect: sudo journalctl -u suricata -n 40 --no-pager", file=sys.stderr)
        return restart.returncode
    active = run(["systemctl", "is-active", "suricata"])
    print(f"Suricata service: {active.stdout.strip() or 'unknown'}")
    print(f"Configured AF_PACKET interface: {selected}")
    print("Verify new EVE records with: sudo jq -c 'select(.in_iface!=null)' /var/log/suricata/eve.json | tail")
    return 0 if active.returncode == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
