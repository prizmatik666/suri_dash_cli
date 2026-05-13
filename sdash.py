#!/usr/bin/env python3

import argparse
import curses
import ipaddress
import json
import os
import sys
import time
from collections import Counter, defaultdict, deque
from pathlib import Path

APP_NAME = "sdash"
APP_VERSION = "v3.2"
APP_BRAND = "PRIZM BUILD"

DEFAULT_LOG = "/var/log/suricata/eve.json"
DEFAULT_MAX_EVENTS = 40
DEFAULT_SCAN_WINDOW = 30
DEFAULT_SCAN_THRESHOLD = 5
DEFAULT_LIGHT_THRESHOLD = 2

WATCH_PORTS = {21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 3389, 5900, 8080}
SMB_PORTS = {139, 445}

SUPPRESSED_SIGNATURES = {
    "SURICATA Ethertype unknown"
}

recent_events = None
active_scan_alerts = deque(maxlen=15)

event_counts = Counter()
alert_counts = Counter()
talker_counts = Counter()
proto_counts = Counter()
port_counts = Counter()
smb_counts = Counter()

scan_tracker = defaultdict(lambda: {
    "ports": set(),
    "last_seen": 0,
    "target": None
})

ARGS = None


def parse_args():
    parser = argparse.ArgumentParser(
        prog=APP_NAME,
        description="Suricata live terminal dashboard - PRIZM BUILD"
    )

    parser.add_argument(
        "--log",
        default=DEFAULT_LOG,
        help=f"Path to Suricata eve.json log. Default: {DEFAULT_LOG}"
    )

    parser.add_argument(
        "--scan-threshold",
        type=int,
        default=DEFAULT_SCAN_THRESHOLD,
        help=f"Unique destination ports needed to trigger scan detection. Default: {DEFAULT_SCAN_THRESHOLD}"
    )

    parser.add_argument(
        "--light-threshold",
        type=int,
        default=DEFAULT_LIGHT_THRESHOLD,
        help=f"Unique watched ports needed for light probe detection. Default: {DEFAULT_LIGHT_THRESHOLD}"
    )

    parser.add_argument(
        "--window",
        type=int,
        default=DEFAULT_SCAN_WINDOW,
        help=f"Scan tracking window in seconds. Default: {DEFAULT_SCAN_WINDOW}"
    )

    parser.add_argument(
        "--max-events",
        type=int,
        default=DEFAULT_MAX_EVENTS,
        help=f"Recent events buffer size. Default: {DEFAULT_MAX_EVENTS}"
    )

    parser.add_argument(
        "--full-ip",
        action="store_true",
        help="Show full IP addresses instead of shortening IPv6 addresses."
    )

    parser.add_argument(
        "--no-follow-end",
        action="store_true",
        help="Start reading from the beginning of the log instead of tailing new events only."
    )

    return parser.parse_args()


def validate_startup(args):
    log_path = Path(args.log).expanduser()

    if not log_path.exists():
        print(f"[!] Log file not found: {log_path}")
        print("[*] Try: sudo ls -lh /var/log/suricata/")
        return False

    if not log_path.is_file():
        print(f"[!] Log path is not a file: {log_path}")
        return False

    if not os.access(log_path, os.R_OK):
        print(f"[!] Log file is not readable: {log_path}")
        print("[*] Try running with sudo:")
        print(f"    sudo {APP_NAME} --log {log_path}")
        return False

    if args.scan_threshold < 1:
        print("[!] --scan-threshold must be >= 1")
        return False

    if args.light_threshold < 1:
        print("[!] --light-threshold must be >= 1")
        return False

    if args.window < 1:
        print("[!] --window must be >= 1")
        return False

    if args.max_events < 5:
        print("[!] --max-events should be >= 5")
        return False

    return True


def follow(path, follow_end=True):
    while not os.path.exists(path):
        time.sleep(1)

    with open(path, "r", errors="ignore") as f:
        if follow_end:
            f.seek(0, os.SEEK_END)

        while True:
            line = f.readline()
            if not line:
                time.sleep(0.05)
                yield None
            else:
                yield line.strip()


def safe_addstr(stdscr, y, x, text, color=0):
    h, w = stdscr.getmaxyx()
    if y < 0 or y >= h or x < 0 or x >= w:
        return

    max_len = max(1, w - x - 1)

    try:
        stdscr.addstr(y, x, str(text)[:max_len], color)
    except curses.error:
        pass


def shorten_ip(ip):
    if not ip:
        return ""

    ip = str(ip)

    if ARGS and ARGS.full_ip:
        return ip

    if ":" not in ip:
        return ip

    try:
        addr = ipaddress.ip_address(ip)
        compressed = addr.compressed
        parts = compressed.split(":")
        tail = parts[-2:] if len(parts) >= 2 else parts
        return f"{parts[0]}::" + ":".join(tail)

    except Exception:
        parts = [p for p in ip.split(":") if p]
        if len(parts) >= 2:
            return f"{parts[0]}::{parts[-2]}:{parts[-1]}"
        return ip[:24]


def short_pair(src, dst):
    return f"{shorten_ip(src)}->{shorten_ip(dst)}"


def add_event(msg):
    recent_events.appendleft(msg)


def add_scan(msg):
    if msg not in active_scan_alerts:
        active_scan_alerts.appendleft(msg)
        add_event(f"[SCAN] {msg}")


def detect_scan(src, dst, dport):
    if not src or not dst or not dport:
        return

    try:
        dport = int(dport)
    except Exception:
        return

    now = time.time()
    key = (src, dst)
    rec = scan_tracker[key]

    if now - rec["last_seen"] > ARGS.window:
        rec["ports"] = set()

    rec["last_seen"] = now
    rec["target"] = dst
    rec["ports"].add(dport)

    unique_ports = len(rec["ports"])
    display_pair = short_pair(src, dst)

    if unique_ports >= ARGS.scan_threshold:
        add_scan(f"POSSIBLE PORT SCAN {display_pair} ({unique_ports} ports/{ARGS.window}s)")

    elif rec["ports"] == SMB_PORTS:
        add_scan(f"SMB ENUM PROBE {display_pair} ports=[139,445]")

    elif unique_ports >= ARGS.light_threshold and rec["ports"].issubset(SMB_PORTS):
        add_scan(f"LIGHT SMB PROBE {display_pair} ports={sorted(rec['ports'])}")

    elif unique_ports >= ARGS.light_threshold and rec["ports"] & WATCH_PORTS:
        add_scan(f"LIGHT SERVICE PROBE {display_pair} ports={sorted(rec['ports'])}")


def summarize(e):
    et = e.get("event_type", "?")
    ts = e.get("timestamp", "")
    ts = ts[11:19] if len(ts) > 18 else "????????"

    src = e.get("src_ip", "")
    dst = e.get("dest_ip", "")
    sp = e.get("src_port", "")
    dp = e.get("dest_port", "")
    proto = e.get("proto", "")

    ssrc = shorten_ip(src)
    sdst = shorten_ip(dst)

    if src:
        talker_counts[src] += 1

    if proto:
        proto_counts[proto] += 1

    if dp:
        port_counts[str(dp)] += 1

    if str(dp) in ("139", "445"):
        smb_counts[f"{short_pair(src, dst)}:{dp}"] += 1

    if et == "stats":
        return None

    if et == "alert":
        alert = e.get("alert", {})
        sig = alert.get("signature", "?")
        sev = alert.get("severity", "?")
        cat = alert.get("category", "?")

        if sig in SUPPRESSED_SIGNATURES:
            return None

        alert_counts[sig] += 1

        sig_l = sig.lower()
        cat_l = cat.lower()

        if "scan" in sig_l or "nmap" in sig_l or "smb" in sig_l or "scan" in cat_l:
            add_scan(f"IDS ALERT sev:{sev} {short_pair(src, dst)} {sig}")

        return f"{ts} ALERT sev:{sev} {short_pair(src, dst)} {sig}"

    if et == "dns":
        dns = e.get("dns", {})
        q = dns.get("rrname", "") or dns.get("query", {}).get("rrname", "")
        return f"{ts} DNS   {ssrc} -> {q}"

    if et == "http":
        http = e.get("http", {})
        host = http.get("hostname", "")
        url = http.get("url", "")
        return f"{ts} HTTP  {ssrc} -> {host}{url}"

    if et == "tls":
        tls = e.get("tls", {})
        sni = tls.get("sni", "")
        return f"{ts} TLS   {ssrc} -> {sni}"

    if et == "flow":
        detect_scan(src, dst, dp)

        tag = "FLOW "
        if str(dp) in ("139", "445"):
            tag = "SMB  "

        return f"{ts} {tag} {ssrc}:{sp} -> {sdst}:{dp} {proto}"

    return f"{ts} {et.upper()} {ssrc}:{sp} -> {sdst}:{dp} {proto}"


def init_colors():
    curses.start_color()
    curses.use_default_colors()
    curses.init_pair(1, curses.COLOR_RED, -1)
    curses.init_pair(2, curses.COLOR_GREEN, -1)
    curses.init_pair(3, curses.COLOR_YELLOW, -1)
    curses.init_pair(4, curses.COLOR_CYAN, -1)
    curses.init_pair(5, curses.COLOR_MAGENTA, -1)
    curses.init_pair(6, curses.COLOR_WHITE, -1)


def color_for_event(line):
    if "ALERT" in line or "SCAN" in line:
        return curses.color_pair(1) | curses.A_BOLD
    if "SMB" in line:
        return curses.color_pair(3) | curses.A_BOLD
    if "DNS" in line:
        return curses.color_pair(4)
    if "HTTP" in line:
        return curses.color_pair(2)
    if "TLS" in line:
        return curses.color_pair(5)
    if "FLOW" in line:
        return curses.color_pair(6)
    return curses.color_pair(3)


def format_item(k, v, width=28):
    if isinstance(k, str) and ":" in k and "->" not in k:
        k = shorten_ip(k)

    return f"{str(k):<{width}} {v}"


def draw_box(stdscr, y, x, title, items, color, max_items=8, width=28):
    safe_addstr(stdscr, y, x, title, curses.A_BOLD | color)
    yy = y + 1

    for k, v in items:
        safe_addstr(stdscr, yy, x + 2, format_item(k, v, width), color)
        yy += 1
        if yy >= y + max_items + 1:
            break


def draw(stdscr):
    curses.curs_set(0)
    stdscr.nodelay(True)
    init_colors()

    paused = False
    stream = follow(ARGS.log, follow_end=not ARGS.no_follow_end)

    while True:
        if not paused:
            line = next(stream)

            if line:
                try:
                    e = json.loads(line)
                    et = e.get("event_type", "unknown")
                    event_counts[et] += 1

                    msg = summarize(e)
                    if msg:
                        add_event(msg)
                except json.JSONDecodeError:
                    pass
                except Exception:
                    pass

        stdscr.erase()
        h, w = stdscr.getmaxyx()

        if h < 20 or w < 80:
            safe_addstr(stdscr, 0, 0, "TERMINAL TOO SMALL - resize pane", curses.color_pair(1) | curses.A_BOLD)
            stdscr.refresh()
            time.sleep(0.1)
            continue

        safe_addstr(
            stdscr,
            0,
            0,
            f"SURICATA LIVE DASHBOARD {APP_VERSION} - {APP_BRAND}",
            curses.A_BOLD | curses.color_pair(2)
        )

        safe_addstr(stdscr, 1, 0, f"LOG: {ARGS.log}")
        safe_addstr(
            stdscr,
            2,
            0,
            f"q=quit  p=pause/resume  window={ARGS.window}s  threshold={ARGS.scan_threshold}  light={ARGS.light_threshold}  full_ip={ARGS.full_ip}"
        )

        if paused:
            safe_addstr(stdscr, 2, 72, "PAUSED", curses.color_pair(3) | curses.A_BOLD)

        left_x = 0
        mid_x = 34
        right_x = 58 if w <= 120 else 82

        draw_box(stdscr, 4, left_x, "EVENT COUNTS", event_counts.most_common(8), curses.color_pair(4), width=18)
        draw_box(stdscr, 4, mid_x, "TOP ALERTS", alert_counts.most_common(8), curses.color_pair(1), width=34)
        draw_box(stdscr, 4, right_x, "TOP PORTS", port_counts.most_common(8), curses.color_pair(3), width=14)

        y2 = 15
        draw_box(stdscr, y2, left_x, "TOP TALKERS", talker_counts.most_common(8), curses.color_pair(5), width=24)
        draw_box(stdscr, y2, mid_x, "PROTOCOLS", proto_counts.most_common(8), curses.color_pair(3), width=14)
        draw_box(stdscr, y2, right_x, "SMB FLOWS", smb_counts.most_common(8), curses.color_pair(3), width=34)

        scan_y = min(27, h - 12)
        safe_addstr(stdscr, scan_y, 0, "SCAN / PROBE DETECTIONS", curses.A_BOLD | curses.color_pair(1))

        y = scan_y + 1
        for s in list(active_scan_alerts)[:6]:
            safe_addstr(stdscr, y, 2, s, curses.color_pair(1) | curses.A_BOLD)
            y += 1
            if y >= h - 1:
                break

        recent_y = min(scan_y + 8, h - 8)
        safe_addstr(stdscr, recent_y, 0, "RECENT EVENTS", curses.A_BOLD | curses.color_pair(2))

        y = recent_y + 1
        available = max(1, h - y - 1)

        for ev in list(recent_events)[:available]:
            safe_addstr(stdscr, y, 2, ev, color_for_event(ev))
            y += 1
            if y >= h - 1:
                break

        stdscr.refresh()

        try:
            ch = stdscr.getch()
            if ch == ord("q"):
                break
            if ch == ord("p"):
                paused = not paused
        except Exception:
            pass

        time.sleep(0.03)


def main():
    global ARGS, recent_events

    ARGS = parse_args()
    ARGS.log = str(Path(ARGS.log).expanduser())
    recent_events = deque(maxlen=ARGS.max_events)

    if not validate_startup(ARGS):
        sys.exit(1)

    curses.wrapper(draw)


if __name__ == "__main__":
    main()
