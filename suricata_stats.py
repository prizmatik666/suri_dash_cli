#!/usr/bin/env python3
"""Summarize and display Suricata's text-format stats.log."""

from __future__ import annotations

import argparse
import curses
import json
import os
import re
import stat
import sys
import tempfile
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path


DEFAULT_STATS_LOG = Path("/var/log/suricata/stats.log")
TAIL_CHUNK_BYTES = 64 * 1024
MAX_TAIL_BYTES = 8 * 1024 * 1024
CONFIG_VERSION = 1

SUMMARY_SECTIONS = (
    ("CAPTURE AND DECODER", (
        ("capture.kernel_packets", "Kernel packets", False),
        ("capture.kernel_drops", "Kernel drops", False),
        ("decoder.pkts", "Decoded packets", False),
        ("decoder.bytes", "Decoded bytes", True),
        ("decoder.ipv4", "IPv4 packets", False),
        ("decoder.ipv6", "IPv6 packets", False),
        ("decoder.tcp", "TCP packets", False),
        ("decoder.udp", "UDP packets", False),
        ("decoder.icmpv4", "ICMPv4 packets", False),
        ("decoder.icmpv6", "ICMPv6 packets", False),
    )),
    ("FLOWS AND DETECTION", (
        ("flow.total", "Flows observed", False),
        ("flow.active", "Active flows", False),
        ("flow.tcp", "TCP flows", False),
        ("flow.udp", "UDP flows", False),
        ("flow.end.state.established", "Established flow ends", False),
        ("flow.end.state.new", "New flow ends", False),
        ("detect.alert", "IDS alerts", False),
        ("detect.alerts_suppressed", "Suppressed alerts", False),
        ("tcp.syn", "TCP SYN", False),
        ("tcp.synack", "TCP SYN/ACK", False),
        ("tcp.rst", "TCP RST", False),
        ("tcp.reassembly_gap", "TCP reassembly gaps", False),
    )),
    ("APPLICATION LAYER", (
        ("app_layer.flow.dns_udp", "DNS/UDP flows", False),
        ("app_layer.tx.dns_udp", "DNS/UDP transactions", False),
        ("app_layer.flow.dns_tcp", "DNS/TCP flows", False),
        ("app_layer.tx.dns_tcp", "DNS/TCP transactions", False),
        ("app_layer.flow.mdns", "mDNS flows", False),
        ("app_layer.tx.mdns", "mDNS transactions", False),
        ("app_layer.flow.tls", "TLS flows", False),
        ("app_layer.flow.http", "HTTP flows", False),
        ("app_layer.tx.http", "HTTP transactions", False),
        ("app_layer.flow.smb", "SMB flows", False),
        ("app_layer.tx.smb", "SMB transactions", False),
        ("app_layer.flow.ssh", "SSH flows", False),
        ("app_layer.flow.dhcp", "DHCP flows", False),
        ("app_layer.tx.dhcp", "DHCP transactions", False),
        ("app_layer.flow.ntp", "NTP flows", False),
    )),
    ("MEMORY AND CAPACITY", (
        ("flow.memuse", "Flow memory", True),
        ("defrag.memuse", "Defrag memory", True),
        ("tcp.memuse", "TCP memory", True),
        ("tcp.reassembly_memuse", "TCP reassembly memory", True),
        ("host.memuse", "Host memory", True),
        ("host.memcap", "Host memory cap", True),
        ("ippair.memuse", "IP pair memory", True),
        ("ippair.memcap", "IP pair memory cap", True),
        ("memcap.pressure", "Memory pressure events", False),
        ("memcap.pressure_max", "Maximum memory pressure", False),
    )),
)
DEFAULT_DISPLAY_COUNTERS = tuple(
    counter
    for _section, counters in SUMMARY_SECTIONS
    for counter, _label, _is_size in counters
)
RATE_COUNTERS = (
    ("capture.kernel_packets", "Packets/s", 1 / 1, " pkt/s"),
    ("decoder.bytes", "MiB/s", 1 / (1024 * 1024), " MiB/s"),
    ("detect.alert", "Alerts/s", 1, " /s"),
    ("capture.kernel_drops", "Drops/s", 1, " /s"),
    ("flow.total", "Flows/s", 1, " /s"),
)


def stats_config_path() -> Path:
    config_home = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config")).expanduser()
    return config_home / "suricata-agent" / "stats_config.json"


def default_stats_config() -> dict:
    return {"version": CONFIG_VERSION, "display_counters": list(DEFAULT_DISPLAY_COUNTERS)}


def _validate_stats_config(config) -> dict:
    if not isinstance(config, dict) or set(config) != {"version", "display_counters"}:
        raise ValueError("stats config must contain only version and display_counters")
    if type(config["version"]) is not int or config["version"] != CONFIG_VERSION:
        raise ValueError(f"Unsupported stats config version: {config.get('version')}")
    counters = config["display_counters"]
    if not isinstance(counters, list) or any(not isinstance(item, str) or not item.strip() for item in counters):
        raise ValueError("display_counters must be a list of nonempty counter names")
    if len(counters) != len(set(counters)):
        raise ValueError("display_counters cannot contain duplicate names")
    return config


def _check_private_config_path(path: Path, *, create: bool) -> None:
    directory = path.parent
    if directory.is_symlink():
        raise PermissionError(f"Stats config directory must not be a symlink: {directory}")
    if create:
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    info = directory.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o077:
        raise PermissionError(f"Stats config directory must be owned by this user and private (0700): {directory}")
    if path.exists() or path.is_symlink():
        file_info = path.lstat()
        if not stat.S_ISREG(file_info.st_mode) or file_info.st_uid != os.getuid() or stat.S_IMODE(file_info.st_mode) & 0o077:
            raise PermissionError(f"Stats config must be a private regular file owned by this user: {path}")


def load_stats_config(path: Path | None = None) -> dict:
    selected = path or stats_config_path()
    if not selected.exists() and not selected.is_symlink():
        return default_stats_config()
    _check_private_config_path(selected, create=False)
    with selected.open("r", encoding="utf-8") as stream:
        return _validate_stats_config(json.load(stream))


def save_stats_config(config: dict, path: Path | None = None) -> Path:
    selected = path or stats_config_path()
    _validate_stats_config(config)
    _check_private_config_path(selected, create=True)
    descriptor, temporary = tempfile.mkstemp(prefix=".stats-config-", dir=selected.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(config, stream, indent=2, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, selected)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    return selected


@dataclass
class StatsSample:
    timestamp_text: str
    uptime: str
    timestamp: datetime | None = None
    values: dict[str, dict[str, float]] = field(default_factory=dict)


def _parse_sample_time(text: str) -> datetime | None:
    try:
        return datetime.strptime(text, "%m/%d/%Y -- %H:%M:%S").astimezone()
    except ValueError:
        return None


def parse_stats(text: str) -> list[StatsSample]:
    """Parse Suricata's repeated Date / Counter / TM Name / Value blocks."""
    samples: list[StatsSample] = []
    current: StatsSample | None = None
    date_pattern = re.compile(r"^Date:\s*(.*?)\s+\(uptime:\s*(.*?)\)\s*$")

    for line in text.splitlines():
        date_match = date_pattern.match(line.strip())
        if date_match:
            if current is not None and current.values:
                samples.append(current)
            timestamp_text, uptime = date_match.groups()
            current = StatsSample(timestamp_text, uptime, _parse_sample_time(timestamp_text))
            continue
        if current is None or "|" not in line:
            continue

        counter, separator, remainder = line.partition("|")
        thread, separator2, raw_value = remainder.partition("|")
        if not separator or not separator2:
            continue
        counter = counter.strip()
        thread = thread.strip()
        raw_value = raw_value.strip().replace(",", "")
        if not counter or not thread:
            continue
        try:
            value = float(raw_value)
        except ValueError:
            continue
        current.values.setdefault(counter, {})[thread] = value

    if current is not None and current.values:
        samples.append(current)
    return samples


def read_recent_samples(path: Path, needed: int, *, max_bytes: int = MAX_TAIL_BYTES) -> list[StatsSample]:
    """Read a bounded tail, growing backward until enough complete samples exist."""
    chunks: list[bytes] = []
    total = 0
    with path.open("rb") as stream:
        end = stream.seek(0, os.SEEK_END)
        start = end
        while start > 0 and total < max_bytes:
            size = min(TAIL_CHUNK_BYTES, start, max_bytes - total)
            start -= size
            stream.seek(start)
            chunks.insert(0, stream.read(size))
            total += size
            data = b"".join(chunks)
            if len(re.findall(rb"(?m)^Date:", data)) >= needed + 1:
                break

    data = b"".join(chunks)
    if start > 0:
        first_header = re.search(rb"(?m)^Date:", data)
        if first_header:
            data = data[first_header.start():]
    return parse_stats(data.decode("utf-8", errors="replace"))[-(needed + 1):]


def sample_value(sample: StatsSample, counter: str) -> float | None:
    rows = sample.values.get(counter)
    if not rows:
        return None
    if "Total" in rows:
        return rows["Total"]
    return sum(rows.values())


def _delta_rate(previous: StatsSample | None, current: StatsSample, counter: str) -> float | None:
    if previous is None or previous.timestamp is None or current.timestamp is None:
        return None
    elapsed = (current.timestamp - previous.timestamp).total_seconds()
    before = sample_value(previous, counter)
    after = sample_value(current, counter)
    if elapsed <= 0 or before is None or after is None or after < before:
        return None
    return (after - before) / elapsed


def _number(value: float | None) -> str:
    if value is None:
        return "n/a"
    value = int(value) if value.is_integer() else value
    return f"{value:,}" if isinstance(value, int) else f"{value:,.2f}"


def _rate(value: float | None, unit: str = "/s") -> str:
    return "n/a" if value is None else f"{value:,.2f}{unit}"


def _size(value: float | None) -> str:
    if value is None:
        return "n/a"
    size = float(value)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if abs(size) < 1024 or unit == "TiB":
            return f"{size:,.2f} {unit}"
        size /= 1024
    return f"{size:,.2f} TiB"


def _metric(sample: StatsSample, counter: str, label: str, *, rate: float | None = None,
            rate_unit: str = "/s", size: bool = False) -> str:
    value = sample_value(sample, counter)
    rendered = _size(value) if size else _number(value)
    suffix = f"  ({_rate(rate, rate_unit)})" if rate is not None else ""
    return f"{label:<31} {rendered}{suffix}"


def render_report(samples: list[StatsSample], *, show_all: bool = False,
                  display_counters: set[str] | None = None, path: Path = DEFAULT_STATS_LOG) -> str:
    if not samples:
        return f"No complete stats snapshots found in {path}."

    selected = set(DEFAULT_DISPLAY_COUNTERS) if display_counters is None else set(display_counters)
    previous = samples[-2] if len(samples) > 1 else None
    latest = samples[-1]
    time_label = latest.timestamp_text
    if latest.uptime:
        time_label += f" (uptime {latest.uptime})"

    lines = [
        f"SURICATA STATS  |  {path}",
        f"Latest snapshot: {time_label}",
    ]

    selected_count = 0
    for section, counters in SUMMARY_SECTIONS:
        shown = [(counter, label, is_size) for counter, label, is_size in counters if counter in selected]
        include_drop_ratio = section == "CAPTURE AND DECODER" and {
            "capture.kernel_packets", "capture.kernel_drops"
        } <= selected
        if not shown and not include_drop_ratio:
            continue
        lines.extend(("", section))
        for counter, label, is_size in shown:
            rate = _delta_rate(previous, latest, counter) if counter in {
                "capture.kernel_packets", "capture.kernel_drops", "decoder.bytes",
                "flow.total", "detect.alert",
            } else None
            rate_unit = " MiB/s" if counter == "decoder.bytes" else " pkt/s" if counter == "capture.kernel_packets" else " /s"
            rate_value = rate / (1024 * 1024) if counter == "decoder.bytes" and rate is not None else rate
            lines.append(_metric(latest, counter, label, rate=rate_value,
                                 rate_unit=rate_unit, size=is_size))
            selected_count += 1
        if include_drop_ratio:
            packets = sample_value(latest, "capture.kernel_packets")
            drops = sample_value(latest, "capture.kernel_drops")
            drop_pct = 100 * drops / (packets + drops) if packets is not None and drops is not None and packets + drops else None
            lines.append(f"{'Cumulative drop ratio':<31} {drop_pct:.3f}%" if drop_pct is not None else f"{'Cumulative drop ratio':<31} n/a")

    known_counters = {counter for _section, counters in SUMMARY_SECTIONS for counter, _label, _size in counters}
    custom_counters = sorted((selected - known_counters) & set(latest.values))
    if custom_counters:
        lines.extend(("", "CUSTOM COUNTERS"))
        for counter in custom_counters:
            lines.append(f"{counter:<56} {_number(sample_value(latest, counter)):>16}")
            selected_count += 1
    if not selected_count:
        lines.extend(("", "No counters are selected for the summary. Press c in the TUI to configure counters."))

    rate_columns = [item for item in RATE_COUNTERS if item[0] in selected]
    if len(samples) > 1 and rate_columns:
        lines.extend(("", "RECENT RATES (delta between adjacent snapshots)"))
        lines.append(f"{'Time':<21}" + "".join(f"{label:>14}" for _key, label, _scale, _unit in rate_columns))
        for index, sample in enumerate(samples[1:], start=1):
            prior = samples[index - 1] if index > 0 else None
            cells = [f"{sample.timestamp_text[-8:]:<21}"]
            for counter, _label, scale, unit in rate_columns:
                value = _delta_rate(prior, sample, counter)
                cells.append(f"{_rate(value * scale if value is not None else None, unit):>14}")
            lines.append("".join(cells))

    if show_all:
        lines.extend(("", "ALL COUNTERS (Total is preferred when present; otherwise thread values are summed)"))
        for counter in sorted(latest.values):
            thread_values = latest.values[counter]
            for thread, value in sorted(thread_values.items()):
                lines.append(f"{counter:<56} {thread:<16} {_number(value):>16}")

    lines.extend(("", "Rates use adjacent cumulative snapshots; n/a means missing, reset, or invalid timestamps."))
    return "\n".join(lines)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Collate and display Suricata text-format stats.log data.")
    parser.add_argument("--log", type=Path, default=DEFAULT_STATS_LOG, help=f"stats.log path (default: {DEFAULT_STATS_LOG})")
    parser.add_argument("--samples", type=int, default=12, help="Recent snapshots to show in rate history (1-120, default: 12)")
    parser.add_argument("--all", action="store_true", help="Show every counter in the latest snapshot")
    parser.add_argument("--watch", action="store_true", help="Refresh the report periodically until Ctrl+C")
    parser.add_argument("--refresh-seconds", type=float, default=2.0, help="Watch refresh interval (default: 2)")
    parser.add_argument("--plain", action="store_true", help="Print a plain report even when running in a terminal")
    config_action = parser.add_mutually_exclusive_group()
    config_action.add_argument("--configure", action="store_true", help="Open the counter display settings menu")
    config_action.add_argument("--reset-config", action="store_true", help="Restore and save the developer's default counter selection")
    return parser.parse_args(argv)


def _load_report(path: Path, sample_count: int, show_all: bool,
                 display_counters: set[str] | None = None) -> list[str]:
    samples = read_recent_samples(path, sample_count)
    return render_report(samples, show_all=show_all, display_counters=display_counters, path=path).splitlines()


def _tui_add(screen, row: int, text: str, width: int, attr: int = 0) -> None:
    if row < 0 or width < 2:
        return
    try:
        screen.addnstr(row, 0, text, width - 1, attr)
    except curses.error:
        pass  # Terminal resize can invalidate one draw operation.


def _search_report(screen, lines: list[str], width: int, start: int) -> tuple[int | None, str]:
    height, _ = screen.getmaxyx()
    screen.move(height - 1, 0)
    screen.clrtoeol()
    _tui_add(screen, height - 1, "Find counter/text: ", width)
    screen.refresh()
    curses.echo()
    try:
        try:
            curses.curs_set(1)
        except curses.error:
            pass
        raw = screen.getstr(height - 1, 19, max(1, width - 20))
    finally:
        curses.noecho()
        try:
            curses.curs_set(0)
        except curses.error:
            pass
    query = raw.decode("utf-8", errors="replace").strip().lower()
    if not query:
        return None, "Search cleared."
    order = list(range(start + 1, len(lines))) + list(range(0, min(start + 1, len(lines))))
    for index in order:
        if query in lines[index].lower():
            return index, f"Found: {query}"
    return None, f"No match for: {query}"


def _edit_config_screen(screen, path: Path, latest: StatsSample | None) -> dict:
    saved = load_stats_config()
    saved_selection = set(saved["display_counters"])
    draft = set(saved_selection)
    available = sorted(set(latest.values if latest else ()) | saved_selection | set(DEFAULT_DISPLAY_COUNTERS))
    selected = 0
    top = 0
    query = ""
    status = f"Saved to {stats_config_path()}"
    screen.keypad(True)
    try:
        curses.curs_set(0)
    except curses.error:
        pass

    while True:
        height, width = screen.getmaxyx()
        screen.erase()
        if height < 8 or width < 32:
            _tui_add(screen, 0, "Resize terminal to at least 32 x 8; q closes settings.", width)
            screen.refresh()
            if screen.getch() in (ord("q"), ord("Q"), 27):
                return load_stats_config()
            continue
        matches = [counter for counter in available if query.lower() in counter.lower()]
        visible = max(1, height - 6)
        selected = min(selected, max(0, len(matches) - 1))
        top = min(top, max(0, len(matches) - visible))
        if selected < top:
            top = selected
        elif selected >= top + visible:
            top = selected - visible + 1

        _tui_add(screen, 0, f"Stats display settings | {path.name}", width, curses.A_BOLD)
        discovered = len(latest.values) if latest is not None else 0
        _tui_add(screen, 1, f"{len(draft)} selected | {discovered} found in latest snapshot | {len(matches)} listed", width, curses.A_DIM)
        _tui_add(screen, 2, "↑/↓ move | PgUp/PgDn scroll | Space/Enter toggle | / filter | c clear", width)
        _tui_add(screen, 3, "a all | d defaults draft | s save | r restore defaults now | q close", width)
        for row, counter in enumerate(matches[top:top + visible], start=4):
            index = top + row - 4
            checked = "[x]" if counter in draft else "[ ]"
            default_mark = " default" if counter in DEFAULT_DISPLAY_COUNTERS else ""
            value = _number(sample_value(latest, counter)) if latest is not None else "n/a"
            text = f"{checked} {counter:<48} {value:>14}{default_mark}"
            _tui_add(screen, row, text, width, curses.A_REVERSE if index == selected else 0)
        _tui_add(screen, height - 2, f"{status}{'  [unsaved]' if draft != saved_selection else ''}", width, curses.A_DIM)
        _tui_add(screen, height - 1, f"Showing {top + 1 if matches else 0}-{min(top + visible, len(matches))} of {len(matches)}", width, curses.A_BOLD)
        screen.refresh()

        key = screen.getch()
        if key in (ord("q"), ord("Q"), 27):
            return load_stats_config()  # Discard unsaved draft changes.
        if key in (curses.KEY_UP, ord("k")):
            selected = max(0, selected - 1)
        elif key in (curses.KEY_DOWN, ord("j")):
            selected = min(max(0, len(matches) - 1), selected + 1)
        elif key == curses.KEY_PPAGE:
            selected = max(0, selected - visible)
        elif key == curses.KEY_NPAGE:
            selected = min(max(0, len(matches) - 1), selected + visible)
        elif key == curses.KEY_HOME:
            selected = 0
        elif key == curses.KEY_END:
            selected = max(0, len(matches) - 1)
        elif key in (ord(" "), 10, 13, curses.KEY_ENTER) and matches:
            counter = matches[selected]
            if counter in draft:
                draft.remove(counter)
            else:
                draft.add(counter)
        elif key == ord("/"):
            screen.move(height - 1, 0)
            screen.clrtoeol()
            _tui_add(screen, height - 1, "Filter counter: ", width)
            screen.refresh()
            curses.echo()
            try:
                try:
                    curses.curs_set(1)
                except curses.error:
                    pass
                raw = screen.getstr(height - 1, 16, max(1, width - 17))
            finally:
                curses.noecho()
                try:
                    curses.curs_set(0)
                except curses.error:
                    pass
            query = raw.decode("utf-8", errors="replace").strip()
            status = f"Filter: {query}" if query else "Counter filter cleared."
            selected = top = 0
        elif key == ord("c"):
            query = ""
            selected = top = 0
        elif key == ord("a"):
            draft = set(available)
            status = "All discovered counters selected in draft. Press s to save."
        elif key == ord("d"):
            draft = set(DEFAULT_DISPLAY_COUNTERS)
            status = "Developer defaults loaded in draft. Press s to save, or r to save immediately."
        elif key == ord("s"):
            saved_path = save_stats_config({"version": CONFIG_VERSION, "display_counters": sorted(draft)})
            saved_selection = set(draft)
            status = f"Saved settings to {saved_path}"
        elif key == ord("r"):
            defaults = default_stats_config()
            saved_path = save_stats_config(defaults)
            saved_selection = set(defaults["display_counters"])
            draft = set(saved_selection)
            status = f"Restored developer defaults: {saved_path}"


def run_tui(path: Path, sample_count: int, show_all: bool, refresh_seconds: float | None,
            display_counters: set[str]) -> int:
    def draw(screen):
        try:
            curses.curs_set(0)
        except curses.error:
            pass
        screen.keypad(True)
        screen.timeout(max(1, int(refresh_seconds * 1000)) if refresh_seconds is not None else -1)
        selected_counters = set(display_counters)
        lines = _load_report(path, sample_count, show_all, selected_counters)
        offset = 0
        status = ""

        while True:
            height, width = screen.getmaxyx()
            screen.erase()
            if height < 6 or width < 24:
                _tui_add(screen, 0, "Resize terminal to at least 24 x 6; q quits.", width)
                screen.refresh()
                key = screen.getch()
                if key in (ord("q"), ord("Q"), 27):
                    return 0
                continue

            body_height = height - 5
            max_offset = max(0, len(lines) - body_height)
            offset = min(max(0, offset), max_offset)
            latest = lines[1] if len(lines) > 1 else ""
            _tui_add(screen, 0, f"Suricata stats | {path}", width, curses.A_BOLD)
            _tui_add(screen, 1, latest, width, curses.A_DIM)
            _tui_add(screen, 2, f"Rows {offset + 1 if lines else 0}-{min(offset + body_height, len(lines))} of {len(lines)}", width, curses.A_DIM)
            for row, line in enumerate(lines[offset:offset + body_height], start=3):
                _tui_add(screen, row, line, width)

            controls = "↑/↓ scroll  PgUp/PgDn page  Home/End  / find  c settings  r refresh  q quit"
            if width < 64:
                controls = "Arrows/Pg scroll | /find | c config | r reload | q quit"
            _tui_add(screen, height - 2, controls, width, curses.A_BOLD)
            _tui_add(screen, height - 1, status, width, curses.A_DIM)
            screen.refresh()

            key = screen.getch()
            if key == -1:
                if refresh_seconds is not None:
                    lines = _load_report(path, sample_count, show_all, selected_counters)
                    status = f"Updated {datetime.now().astimezone().strftime('%H:%M:%S')}"
                continue
            if key in (ord("q"), ord("Q"), 27):
                return 0
            if key in (curses.KEY_UP, ord("k")):
                offset -= 1
            elif key in (curses.KEY_DOWN, ord("j")):
                offset += 1
            elif key == curses.KEY_PPAGE:
                offset -= body_height
            elif key == curses.KEY_NPAGE:
                offset += body_height
            elif key == curses.KEY_HOME:
                offset = 0
            elif key == curses.KEY_END:
                offset = len(lines)
            elif key == ord("r"):
                lines = _load_report(path, sample_count, show_all, selected_counters)
                status = f"Updated {datetime.now().astimezone().strftime('%H:%M:%S')}"
            elif key == ord("c"):
                latest_samples = read_recent_samples(path, 1)
                latest = latest_samples[-1] if latest_samples else None
                config = _edit_config_screen(screen, path, latest)
                selected_counters = set(config["display_counters"])
                lines = _load_report(path, sample_count, show_all, selected_counters)
                status = f"Display settings loaded from {stats_config_path()}"
            elif key == ord("/"):
                match, status = _search_report(screen, lines, width, offset)
                if match is not None:
                    offset = match

    return curses.wrapper(draw)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    if not 1 <= args.samples <= 120:
        print("--samples must be between 1 and 120", file=sys.stderr)
        return 2
    if args.refresh_seconds <= 0:
        print("--refresh-seconds must be greater than zero", file=sys.stderr)
        return 2
    path = args.log.expanduser()
    if args.reset_config:
        try:
            saved_path = save_stats_config(default_stats_config())
        except (OSError, ValueError) as exc:
            print(f"Could not restore stats defaults: {exc}", file=sys.stderr)
            return 1
        print(f"Restored developer default stats display settings: {saved_path}")
        return 0
    if not path.is_file():
        print(f"Stats log not found: {path}", file=sys.stderr)
        return 1

    try:
        config = load_stats_config()
        if args.configure:
            if not sys.stdin.isatty() or not sys.stdout.isatty():
                print("The stats configuration menu needs an interactive terminal.", file=sys.stderr)
                return 2
            samples = read_recent_samples(path, 1)
            curses.wrapper(_edit_config_screen, path, samples[-1] if samples else None)
            return 0
        if not args.plain and sys.stdin.isatty() and sys.stdout.isatty():
            return run_tui(path, args.samples, args.all,
                           args.refresh_seconds if args.watch else None,
                           set(config["display_counters"]))
        while True:
            samples = read_recent_samples(path, args.samples)
            if args.watch and sys.stdout.isatty():
                print("\033[2J\033[H", end="")
            print(render_report(samples, show_all=args.all,
                                display_counters=set(config["display_counters"]), path=path), flush=True)
            if not args.watch:
                return 0
            if not sys.stdout.isatty():
                print(f"\nRefreshing every {args.refresh_seconds:g}s; press Ctrl+C to stop.", flush=True)
            time.sleep(args.refresh_seconds)
    except KeyboardInterrupt:
        print("\nStopped stats view.")
        return 130
    except PermissionError as exc:
        print(f"Permission denied: {exc}. Check stats-log and config file permissions, parent-directory search access, and group membership.", file=sys.stderr)
        return 1
    except OSError as exc:
        print(f"Could not read stats log {path}: {exc}", file=sys.stderr)
        return 1
    except ValueError as exc:
        print(f"Stats configuration error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
