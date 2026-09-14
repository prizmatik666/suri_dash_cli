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

from sdash_defaults import FACTORY_DEFAULTS, default_config_path, effective_config

APP_NAME = "sdash"
# Public dashboard release branding shown in the terminal title.
APP_VERSION = "v3.5"
APP_BRAND = "PRIZM BUILD"

DEFAULT_LOG = FACTORY_DEFAULTS["log"]
DEFAULT_MAX_EVENTS = FACTORY_DEFAULTS["max_events"]
DEFAULT_SCAN_WINDOW = FACTORY_DEFAULTS["window"]
DEFAULT_SCAN_THRESHOLD = FACTORY_DEFAULTS["scan_threshold"]
DEFAULT_LIGHT_THRESHOLD = FACTORY_DEFAULTS["light_threshold"]

WATCH_PORTS = {21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 3389, 5900, 8080}
SMB_PORTS = {139, 445}
DNS_PORTS = {53}
DNS_EVENT_TYPES = {"dns", "mdns"}

SUPPRESSED_SIGNATURES = {
    "SURICATA Ethertype unknown"
}

recent_events = None
active_scan_alerts = deque(maxlen=15)
active_ids_alerts = deque(maxlen=15)

event_counts = Counter()
alert_counts = Counter()
talker_counts = Counter()
proto_counts = Counter()
port_counts = Counter()
smb_counts = Counter()
dns_client_counts = Counter()
dns_domain_counts = Counter()

scan_tracker = defaultdict(lambda: {
    "ports": set(),
    "last_seen": 0,
    "target": None
})

ARGS = None


def parse_args():
    parser = argparse.ArgumentParser(
        prog=APP_NAME,
        description="Portable Suricata live terminal dashboard"
    )

    parser.add_argument(
        "--log",
        default=None,
        help=f"Path to Suricata eve.json log. Default: {DEFAULT_LOG}"
    )

    parser.add_argument(
        "--scan-threshold",
        type=int,
        default=None,
        help=f"Unique destination ports needed to trigger scan detection. Default: {DEFAULT_SCAN_THRESHOLD}"
    )

    parser.add_argument(
        "--light-threshold",
        type=int,
        default=None,
        help=f"Unique watched ports needed for light probe detection. Default: {DEFAULT_LIGHT_THRESHOLD}"
    )

    parser.add_argument(
        "--window",
        type=int,
        default=None,
        help=f"Scan tracking window in seconds. Default: {DEFAULT_SCAN_WINDOW}"
    )

    parser.add_argument(
        "--max-events",
        type=int,
        default=None,
        help=f"Recent events buffer size. Default: {DEFAULT_MAX_EVENTS}"
    )

    parser.add_argument(
        "--full-ip",
        action="store_true",
        default=None,
        help="Show full IP addresses instead of shortening IPv6 addresses."
    )

    parser.add_argument(
        "--no-follow-end",
        action="store_true",
        default=None,
        help="Start reading from the beginning of the log instead of tailing new events only."
    )

    parser.add_argument(
        "--hide-dns-events",
        action="store_true",
        default=None,
        help="Hide routine DNS entries from the Recent Events stream while still counting them."
    )

    parser.add_argument(
        "--supress-dns", "--suppress-dns",
        dest="suppress_dns",
        action="store_true",
        default=None,
        help="Suppress DNS and mDNS event records from the dashboard readout and event counts."
    )

    parser.add_argument(
        "--ignore-dns-scans",
        action="store_true",
        default=None,
        help="Ignore pure DNS port 53 traffic for scan/probe detection."
    )

    parser.add_argument(
        "--dns-server",
        action="append",
        default=None,
        help="Mark an IP as trusted DNS infrastructure. Can be used multiple times. Example: --dns-server 192.0.2.53"
    )

    parser.add_argument(
        "--config",
        default=None,
        help=f"User settings JSON path. Default: {default_config_path()}"
    )
    parser.add_argument(
        "--factory-defaults",
        action="store_true",
        help="Ignore user settings and use the built-in v3.5 PRIZM defaults."
    )

    args = parser.parse_args()
    config_path = Path(args.config).expanduser() if args.config else None
    settings = effective_config(config_path, factory_only=args.factory_defaults)
    for key, value in settings.items():
        if getattr(args, key, None) is None:
            setattr(args, key, value)
    args.config_path = config_path or default_config_path()
    return args


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

    for ip in args.dns_server:
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            print(f"[!] Invalid --dns-server IP: {ip}")
            return False

    return True


def reset_counters():
    event_counts.clear()
    alert_counts.clear()
    talker_counts.clear()
    proto_counts.clear()
    port_counts.clear()
    smb_counts.clear()
    dns_client_counts.clear()
    dns_domain_counts.clear()
    scan_tracker.clear()
    active_scan_alerts.clear()
    active_ids_alerts.clear()
    recent_events.clear()
    add_event("[RESET] counters cleared")


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


def add_ids_alert(msg):
    if msg not in active_ids_alerts:
        active_ids_alerts.appendleft(msg)


def clear_native_alerts():
    """Clear only the live native-alert panel, preserving history and counters."""
    active_ids_alerts.clear()


def is_dns_infra(ip):
    return ip in set(ARGS.dns_server or [])


def detect_scan(src, dst, dport):
    if not src or not dst or not dport:
        return

    try:
        dport = int(dport)
    except Exception:
        return

    if ARGS.ignore_dns_scans and dport in DNS_PORTS:
        return

    if dport in DNS_PORTS and (is_dns_infra(src) or is_dns_infra(dst)):
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

    if ARGS.suppress_dns and et in DNS_EVENT_TYPES:
        return None

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

        sid = alert.get("signature_id", "?")
        add_ids_alert(f"{ts} [IDS ALERT] sid:{sid} sev:{sev} {short_pair(src, dst)} {sig}")

        return f"{ts} ALERT sev:{sev} {short_pair(src, dst)} {sig}"

    if et == "dns":
        dns = e.get("dns", {})
        q = dns.get("rrname", "") or dns.get("query", {}).get("rrname", "")
        q = q.rstrip(".") if q else "?"

        if src:
            dns_client_counts[src] += 1

        if q:
            dns_domain_counts[q] += 1

        if ARGS.hide_dns_events:
            return None

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
    if "RESET" in line:
        return curses.color_pair(3) | curses.A_BOLD
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


def draw_box(stdscr, y, x, title, items, color, max_items=8, width=28, panel_width=None):
    limit = panel_width if panel_width is not None else width + 2
    safe_addstr(stdscr, y, x, str(title)[:max(1, limit)], curses.A_BOLD | color)
    yy = y + 1

    for k, v in items:
        line = format_item(k, v, max(8, min(width, limit - 2)))
        safe_addstr(stdscr, yy, x + 2, line[:max(1, limit - 2)], color)
        yy += 1
        if yy >= y + max_items + 1:
            break


def draw(stdscr):
    curses.curs_set(0)
    stdscr.nodelay(True)
    init_colors()

    paused = False
    show_event_counts = False
    show_side_stats = False
    stream = follow(ARGS.log, follow_end=not ARGS.no_follow_end)

    while True:
        if not paused:
            line = next(stream)

            if line:
                try:
                    e = json.loads(line)
                    et = e.get("event_type", "unknown")
                    if ARGS.suppress_dns and et in DNS_EVENT_TYPES:
                        continue
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

        if h < 24 or w < 80:
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
        safe_addstr(stdscr, 2, 0, f"q=quit  p=pause  r=reset  c=clear-native-alerts  e=event-counts  s=side-stats  window={ARGS.window}s")
        safe_addstr(stdscr, 3, 0, f"EVENT COUNTS:[{'ON' if show_event_counts else 'off'}]  SIDE STATS:[{'ON' if show_side_stats else 'off'}]  threshold={ARGS.scan_threshold}  light={ARGS.light_threshold}", curses.color_pair(4))

        if ARGS.dns_server:
            safe_addstr(stdscr, 3, 0, f"DNS INFRA: {', '.join(ARGS.dns_server)}", curses.color_pair(4))

        if paused:
            safe_addstr(stdscr, 2, 72, "PAUSED", curses.color_pair(3) | curses.A_BOLD)

        y = 5
        panel_width = max(20, w - 2)
        draw_box(stdscr, y, 0, "TOP ALERTS", alert_counts.most_common(5), curses.color_pair(1), max_items=5, width=32, panel_width=panel_width)
        y += 7

        if show_event_counts:
            counts = " ".join(f"{k}:{v}" for k, v in event_counts.most_common(6)) or "(none yet)"
            safe_addstr(stdscr, y, 0, f"EVENT COUNTS  {counts}", curses.color_pair(4))
            y += 1

        if show_side_stats:
            ports = " ".join(f"{k}:{v}" for k, v in port_counts.most_common(4)) or "(none)"
            talkers = " ".join(f"{k}:{v}" for k, v in talker_counts.most_common(3)) or "(none)"
            protocols = " ".join(f"{k}:{v}" for k, v in proto_counts.most_common(4)) or "(none)"
            smb = " ".join(f"{k}:{v}" for k, v in smb_counts.most_common(3)) or "(none)"
            safe_addstr(stdscr, y, 0, f"TOP PORTS {ports}  |  PROTOCOLS {protocols}", curses.color_pair(3))
            y += 1
            safe_addstr(stdscr, y, 0, f"TOP TALKERS {talkers}  |  SMB FLOWS {smb}", curses.color_pair(5))
            y += 1

        safe_addstr(stdscr, y, 0, "SURICATA ALERTS (native EVE) / SCAN (heuristic)", curses.A_BOLD | curses.color_pair(1))
        y += 1
        security_lines = list(active_ids_alerts)[:4] + list(active_scan_alerts)[:max(0, 4 - min(4, len(active_ids_alerts)))]
        for s in security_lines:
            if y >= h - 2:
                break
            safe_addstr(stdscr, y, 2, s, curses.color_pair(1) | curses.A_BOLD)
            y += 1

        recent_y = y + 1
        if recent_y >= h - 1:
            recent_y = h - 2
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
            if ch == ord("r"):
                reset_counters()
            if ch == ord("c"):
                clear_native_alerts()
            if ch == ord("e"):
                show_event_counts = not show_event_counts
            if ch == ord("s"):
                show_side_stats = not show_side_stats
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
