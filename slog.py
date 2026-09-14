#!/usr/bin/env python3

# ============================================================
#  suri-log-viewer
#  Suricata Log Pretty Viewer / Browser
#
#  PRIZM BUILD
#  Created by Kyle LaBelle (@prizmatikug)
#
#  GitHub:
#  Repo:
#
#  Defensive / educational home-lab utility for viewing,
#  prettifying, browsing, and exporting Suricata log data.
# ============================================================

import argparse
import gzip
import json
import os
import shutil
import sys
import textwrap
from datetime import datetime
from pathlib import Path

APP_NAME = "suri-log-viewer"
APP_VERSION = "v0.1.0"
APP_BRAND = "PRIZM BUILD"

DEFAULT_LOG_DIR = Path("/var/log/suricata")
DEFAULT_SAVE_DIR = Path.home() / "logs"
DEFAULT_LIMIT = 500
DEFAULT_PAGE_LINES = 28

USE_COLOR = True

COLORS = {
    "reset": "\033[0m",
    "bold": "\033[1m",
    "dim": "\033[2m",
    "red": "\033[31m",
    "green": "\033[32m",
    "yellow": "\033[33m",
    "blue": "\033[34m",
    "magenta": "\033[35m",
    "cyan": "\033[36m",
    "white": "\033[37m",
}


def c(text, color):
    if not USE_COLOR:
        return str(text)
    return f"{COLORS.get(color, '')}{text}{COLORS['reset']}"


def parse_args():
    parser = argparse.ArgumentParser(
        prog=APP_NAME,
        description="Suricata log browser, prettifier, and exporter."
    )

    parser.add_argument(
        "--log-dir",
        default=str(DEFAULT_LOG_DIR),
        help=f"Directory containing Suricata logs. Default: {DEFAULT_LOG_DIR}"
    )

    parser.add_argument(
        "--save-dir",
        default=str(DEFAULT_SAVE_DIR),
        help=f"Default export directory. Default: {DEFAULT_SAVE_DIR}"
    )

    parser.add_argument(
        "--file",
        help="Specific log file to open. Can be a filename inside --log-dir or a full path."
    )

    parser.add_argument(
        "--limit",
        type=int,
        default=DEFAULT_LIMIT,
        help=f"Number of events/lines to load. Use 0 for whole file. Default: {DEFAULT_LIMIT}"
    )

    parser.add_argument(
        "--tail",
        action="store_true",
        help="Read the last --limit lines instead of the first --limit lines."
    )

    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable ANSI color output."
    )

    parser.add_argument(
        "--export-only",
        action="store_true",
        help="Export prettified output without opening the interactive browser."
    )

    parser.add_argument(
        "--output",
        help="Output file path for --export-only. If only a filename is provided, saves inside --save-dir."
    )

    parser.add_argument(
        "--page-lines",
        type=int,
        default=DEFAULT_PAGE_LINES,
        help=f"Lines per page in interactive browser. Default: {DEFAULT_PAGE_LINES}"
    )

    parser.add_argument(
        "--event-type",
        help="Only include a specific eve.json event_type, such as alert, dns, http, tls, flow."
    )

    parser.add_argument(
        "--version",
        action="store_true",
        help="Show version and exit."
    )

    return parser.parse_args()


def clear():
    os.system("clear")


def pause():
    input(c("\n[ Enter ] continue...", "dim"))


def banner():
    print(c("╔════════════════════════════════════════════╗", "cyan"))
    print(c(f"║        {APP_NAME} {APP_VERSION:<18}  ║", "cyan"))
    print(c(f"║        {APP_BRAND:<28}        ║", "cyan"))
    print(c("╚════════════════════════════════════════════╝", "cyan"))


def pretty_size(num):
    for unit in ["B", "KB", "MB", "GB"]:
        if num < 1024:
            return f"{num:.1f}{unit}"
        num /= 1024
    return f"{num:.1f}TB"


def validate_args(args):
    if args.version:
        print(f"{APP_NAME} {APP_VERSION} - {APP_BRAND}")
        return False

    if args.limit < 0:
        print(c("[!] --limit must be >= 0", "red"))
        return False

    if args.page_lines < 5:
        print(c("[!] --page-lines should be >= 5", "red"))
        return False

    log_dir = Path(args.log_dir).expanduser()

    if not log_dir.exists():
        print(c(f"[!] Log directory not found: {log_dir}", "red"))
        return False

    if not log_dir.is_dir():
        print(c(f"[!] Log directory is not a directory: {log_dir}", "red"))
        return False

    return True


def resolve_log_file(args):
    log_dir = Path(args.log_dir).expanduser()

    if not args.file:
        return None

    p = Path(args.file).expanduser()

    if not p.is_absolute():
        p = log_dir / p

    return p


def validate_log_file(path):
    if not path.exists():
        print(c(f"[!] Log file not found: {path}", "red"))
        return False

    if not path.is_file():
        print(c(f"[!] Selected path is not a file: {path}", "red"))
        return False

    if not os.access(path, os.R_OK):
        print(c(f"[!] Permission denied reading: {path}", "red"))
        print(c("[*] Try running with sudo.", "yellow"))
        return False

    return True


def read_text_file(path):
    if path.suffix == ".gz":
        with gzip.open(path, "rt", errors="replace") as f:
            return f.read()

    with open(path, "r", errors="replace") as f:
        return f.read()


def list_logs(log_dir):
    files = []

    for p in sorted(log_dir.iterdir(), key=lambda x: x.stat().st_mtime, reverse=True):
        if p.is_file():
            files.append(p)

    return files


def choose_log(log_dir):
    logs = list_logs(log_dir)

    if not logs:
        print(c(f"[!] No files found in {log_dir}", "red"))
        raise SystemExit(1)

    while True:
        clear()
        banner()
        print()

        for i, p in enumerate(logs, 1):
            st = p.stat()
            stamp = datetime.fromtimestamp(st.st_mtime).strftime("%Y-%m-%d %H:%M:%S")
            print(
                f"{c(str(i).rjust(2), 'yellow')}. "
                f"{c(p.name, 'bold')}  "
                f"{c(pretty_size(st.st_size), 'green')}  "
                f"{c(stamp, 'dim')}"
            )

        print(f"\n{c('Q', 'red')}. Quit")

        choice = input(c("\nSelect log file: ", "cyan")).strip().lower()

        if choice == "q":
            raise SystemExit

        if choice.isdigit() and 1 <= int(choice) <= len(logs):
            return logs[int(choice) - 1]

        print(c("Invalid selection.", "red"))
        pause()


def limit_lines(raw, limit, tail_mode):
    lines = raw.splitlines()

    if not limit or limit == 0:
        return "\n".join(lines)

    if tail_mode:
        return "\n".join(lines[-limit:])

    return "\n".join(lines[:limit])


def format_eve_json(raw, limit=None, tail_mode=False, event_type_filter=None):
    raw = limit_lines(raw, limit, tail_mode)
    lines = raw.splitlines()
    output = []

    for line in lines:
        if not line.strip():
            continue

        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            output.append(line)
            continue

        event = obj.get("event_type", "unknown")

        if event_type_filter and event != event_type_filter:
            continue

        output.append(format_eve_event(obj))

    return "\n\n".join(output)


def format_eve_event(obj):
    ts = obj.get("timestamp", "no-time")
    event = obj.get("event_type", "unknown")
    src = obj.get("src_ip", "?")
    sport = obj.get("src_port", "")
    dst = obj.get("dest_ip", "?")
    dport = obj.get("dest_port", "")
    proto = obj.get("proto", "")

    if event == "alert":
        alert = obj.get("alert", {})
        sev = alert.get("severity", "?")
        sig = alert.get("signature", "unknown alert")
        cat = alert.get("category", "unknown category")
        sid = alert.get("signature_id", "?")

        return (
            f"{ts} | ALERT sev={sev} sid={sid} | {src}:{sport} -> {dst}:{dport} {proto}\n"
            f"    signature: {sig}\n"
            f"    category : {cat}"
        )

    if event == "dns":
        dns = obj.get("dns", {})
        query = dns.get("query", {}).get("rrname") or dns.get("rrname", "")
        rtype = dns.get("query", {}).get("rrtype") or dns.get("rrtype", "")

        return f"{ts} | DNS | {src}:{sport} -> {dst}:{dport} | {query} {rtype}"

    if event == "http":
        http = obj.get("http", {})
        host = http.get("hostname", "")
        url = http.get("url", "")
        method = http.get("http_method", "")
        status = http.get("status", "")

        return f"{ts} | HTTP | {src}:{sport} -> {dst}:{dport} | {method} {host}{url} status={status}"

    if event == "tls":
        tls = obj.get("tls", {})
        sni = tls.get("sni", "")
        version = tls.get("version", "")

        return f"{ts} | TLS | {src}:{sport} -> {dst}:{dport} | SNI={sni} version={version}"

    if event == "flow":
        app_proto = obj.get("app_proto", "")
        return f"{ts} | FLOW | {src}:{sport} -> {dst}:{dport} {proto} app={app_proto}"

    if event == "smb":
        smb = obj.get("smb", {})
        command = smb.get("command", "")
        filename = smb.get("filename", "")
        share = smb.get("share", "")

        return f"{ts} | SMB | {src}:{sport} -> {dst}:{dport} | cmd={command} share={share} file={filename}"

    if event == "stats":
        return f"{ts} | STATS | stats event"

    return f"{ts} | {event.upper()} | {src}:{sport} -> {dst}:{dport} {proto}"


def colorize_line(line):
    lower = line.lower()

    if "alert" in lower:
        return c(line, "red")
    if "smb" in lower:
        return c(line, "yellow")
    if "dns" in lower:
        return c(line, "cyan")
    if "http" in lower:
        return c(line, "green")
    if "tls" in lower:
        return c(line, "magenta")
    if "flow" in lower:
        return c(line, "blue")
    if "stats" in lower:
        return c(line, "yellow")
    if "error" in lower or "fail" in lower or "denied" in lower:
        return c(line, "red")

    return line


def browse_text(text, page_lines=DEFAULT_PAGE_LINES):
    lines = text.splitlines()
    idx = 0

    while True:
        clear()
        print(c(f"{APP_NAME} Pretty View - {APP_BRAND}", "bold"))
        print(c(f"Lines {idx + 1}-{min(idx + page_lines, len(lines))} of {len(lines)}", "dim"))
        print(c("Commands: [n]/Enter next  [p] previous  [g] top  [G] bottom  [q] quit viewer", "dim"))
        print("-" * shutil.get_terminal_size((100, 30)).columns)

        page = lines[idx:idx + page_lines]
        width = shutil.get_terminal_size((100, 30)).columns - 2

        for line in page:
            wrapped = textwrap.wrap(line, width=width) or [""]
            for w in wrapped:
                print(colorize_line(w))

        cmd = input(c("\nviewer> ", "cyan")).strip()

        if cmd in ("n", ""):
            idx = min(idx + page_lines, max(0, len(lines) - page_lines))
        elif cmd == "p":
            idx = max(0, idx - page_lines)
        elif cmd == "g":
            idx = 0
        elif cmd == "G":
            idx = max(0, len(lines) - page_lines)
        elif cmd.lower() == "q":
            break


def ask_limit(default_limit):
    print()
    print(c("Large logs can be huge.", "yellow"))
    print("Choose how much to load:")
    print(f"1. First {default_limit} events/lines")
    print("2. First 2,000 events/lines")
    print("3. Whole file")
    print(f"4. Tail last {default_limit} raw lines")

    choice = input(c("\nSelection [1]: ", "cyan")).strip() or "1"

    if choice == "2":
        return 2000, False
    if choice == "3":
        return 0, False
    if choice == "4":
        return default_limit, True

    return default_limit, False


def clean_log(path, args, interactive=True):
    raw = read_text_file(path)

    if interactive and not args.export_only and not args.file:
        limit, tail_mode = ask_limit(args.limit)
    else:
        limit, tail_mode = args.limit, args.tail

    if "eve.json" in path.name:
        return format_eve_json(
            raw,
            limit=limit,
            tail_mode=tail_mode,
            event_type_filter=args.event_type
        )

    cleaned = limit_lines(raw, limit, tail_mode)
    return cleaned


def resolve_output_path(name, save_dir, original_name):
    save_dir = Path(save_dir).expanduser()
    save_dir.mkdir(parents=True, exist_ok=True)

    if not name:
        return save_dir / f"cleaned_{original_name}.txt"

    p = Path(name).expanduser()

    if p.parent == Path("."):
        return save_dir / p.name

    return p


def save_cleaned(text, original_name, args, force=False):
    if not force:
        ans = input(c("\nSave cleaned output? [y/N]: ", "yellow")).strip().lower()
        if ans != "y":
            return None

        default_name = Path(args.save_dir).expanduser() / f"cleaned_{original_name}.txt"
        name = input(c(f"Save name/location [default: {default_name}]: ", "cyan")).strip()
    else:
        name = args.output

    out = resolve_output_path(name, args.save_dir, original_name)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(text, encoding="utf-8", errors="replace")

    print(c(f"\nSaved: {out}", "green"))

    if not force:
        pause()

    return out


def main():
    global USE_COLOR

    args = parse_args()
    USE_COLOR = not args.no_color

    if not validate_args(args):
        if args.version:
            return
        sys.exit(1)

    log_dir = Path(args.log_dir).expanduser()
    selected_log = resolve_log_file(args)

    if selected_log:
        if not validate_log_file(selected_log):
            sys.exit(1)
    else:
        selected_log = choose_log(log_dir)

    clear()
    banner()
    print(c(f"\nSelected: {selected_log}", "green"))

    try:
        cleaned = clean_log(selected_log, args, interactive=True)
    except PermissionError:
        print(c("\nPermission denied. Run with sudo.", "red"))
        sys.exit(1)
    except Exception as e:
        print(c(f"\nError reading log: {e}", "red"))
        sys.exit(1)

    if args.export_only:
        save_cleaned(cleaned, selected_log.name.replace(".gz", ""), args, force=True)
        return

    browse_text(cleaned, page_lines=args.page_lines)
    save_cleaned(cleaned, selected_log.name.replace(".gz", ""), args)

    if not args.file:
        again = input(c("\nOpen another log? [Y/n]: ", "cyan")).strip().lower()
        if again != "n":
            main()


if __name__ == "__main__":
    main()
