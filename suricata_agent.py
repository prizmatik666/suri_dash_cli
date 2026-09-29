#!/usr/bin/env python3
"""Central CLI/TUI entry point for the local Suricata investigation agent."""

from __future__ import annotations

import argparse
import curses
import json
import os
import stat
import sys
import threading
import textwrap
import time
from datetime import datetime
from pathlib import Path

from core.agent_runtime import AgentCancelled, AgentError, SuricataAgent
from core.agent_config import check_source_log_permissions, default_config_path, load_config, source_access_error
from core.eve_index import default_index_path
from core.suricata_tools import SuricataTools


UI_COMMANDS = ["/help", "/clear", "/context", "/history", "/status", "/quit"]
BACKGROUND_VERIFY_GRACE_SECONDS = 10.0


def _human_bytes(value: int) -> str:
    amount = float(max(0, value))
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if amount < 1024 or unit == "TiB":
            return f"{amount:.0f} {unit}" if unit == "B" else f"{amount:.1f} {unit}"
        amount /= 1024
    return f"{amount:.1f} TiB"


class StartupProgress:
    """Bounded, line-oriented startup feedback suitable for terminals and logs."""

    def __init__(self):
        self._last_percent: dict[str, int] = {}
        self._last_printed_at: dict[str, float] = {}

    @staticmethod
    def message(message: str, label: str = "startup") -> None:
        print(f"[{label}] {message}", file=sys.stderr, flush=True)

    def __call__(self, event: dict) -> None:
        stage = event.get("stage")
        if stage == "source_check":
            self.message(f"Checking EVE source identity and index checkpoint: {event.get('source_path')}", "index")
        elif stage == "source_error":
            self.message(f"EVE source check failed: {event.get('error')}", "index")
        elif stage == "source_ready":
            size = int(event.get("source_size", 0))
            offset = int(event.get("indexed_offset", 0))
            state = "existing" if event.get("existing_index") else "new"
            self.message(
                f"{state.capitalize()} index state; generation={event.get('generation', 1)}, "
                f"source={_human_bytes(size)}, pending={_human_bytes(max(0, size - offset))}",
                "index",
            )
        elif stage == "rotation_detected":
            detail = f"; completing {event['rotated_path']}" if event.get("rotated_path") else ""
            self.message(f"EVE rotation detected{detail}", "index")
        elif stage == "source_reset_detected":
            self.message("EVE copy-truncate/content replacement detected; starting a new source generation", "index")
        elif stage == "ingest_progress":
            size = int(event.get("source_size", 0))
            offset = int(event.get("indexed_offset", 0))
            percent = 100 if not size else min(100, int(offset * 100 / size))
            key = f"{event.get('source_kind')}:{event.get('source_path')}"
            now = time.monotonic()
            last_percent = self._last_percent.get(key, -10)
            last_time = self._last_printed_at.get(key, 0.0)
            if event.get("complete") or percent >= last_percent + 10 or now - last_time >= 2:
                self._last_percent[key] = percent
                self._last_printed_at[key] = now
                self.message(
                    f"Ingesting {event.get('source_kind', 'current')} EVE data: {percent}% "
                    f"({_human_bytes(offset)}/{_human_bytes(size)}), "
                    f"{event.get('records_inserted', 0)} records added",
                    "index",
                )
        elif stage == "sync_complete":
            self.message(
                f"Sync committed: {event.get('inserted', 0)} records added, "
                f"generation={event.get('generation')}, malformed lines={event.get('malformed_lines', 0)}",
                "index",
            )
        elif stage == "verify_start":
            reasons = "; ".join(event.get("reasons") or [])
            suffix = f" ({reasons})" if reasons else ""
            self.message(f"Running database-wide SQLite quick_check{suffix}...", "verify")
        elif stage == "verify_fast_complete":
            age = event.get("verification_age_hours")
            age_text = "unknown" if age is None else f"{float(age):.1f} hours"
            suffix = "; background database-wide check scheduled" if event.get("background_due") else ""
            self.message(
                f"Fast checks passed; last full check={event.get('index_integrity')} "
                f"({age_text} ago), records={event.get('record_count', 0)}{suffix}",
                "verify",
            )
        elif stage == "verify_complete":
            self.message(
                f"integrity={event.get('index_integrity')}, schema={event.get('schema_version')}, "
                f"records={event.get('record_count', 0)}, lag={_human_bytes(int(event.get('index_lag_bytes', 0)))}, "
                f"malformed={event.get('malformed_lines', 0)}",
                "verify",
            )
        elif stage == "statistics_start":
            self.message("Collecting complete event-type and timestamp statistics...", "verify")
        elif stage == "statistics_complete":
            self.message(
                f"Statistics complete: records={event.get('record_count', 0)}, "
                f"event types={event.get('event_type_count', 0)}",
                "verify",
            )


class Interface:
    def __init__(self, agent: SuricataAgent, startup_sync: dict | None = None):
        self.agent = agent
        self.lines: list[str] = []
        self.pending_tool_lines: list[str] = []
        self._lock = threading.Lock()
        self._refresh_lock = threading.Lock()
        self._refresh_thread: threading.Thread | None = None
        self._refresh_error: str | None = None
        self._refresh_result: dict | None = None
        self._refresh_error_reported = True
        self._refresh_result_reported = True
        self._refresh_requested = False
        self._request_lock = threading.Lock()
        self._request_thread: threading.Thread | None = None
        self._request_active = threading.Event()
        self._shutdown_requested = threading.Event()
        self._quit_requested = threading.Event()
        self._verification_lock = threading.Lock()
        self._verification_thread: threading.Thread | None = None
        self._verification_result: dict | None = None
        self._verification_error: str | None = None
        self._verification_reported = True
        self._request_status = "Preparing request"
        agent.on_tool = self.on_tool
        agent.on_status = self.on_status
        if startup_sync:
            if startup_sync.get("error"):
                self.lines.append(f"INDEX WARNING: {startup_sync['error']}")
            else:
                self.lines.append(
                    "INDEX READY: "
                    f"{startup_sync.get('inserted', 0)} new EVE records indexed "
                    f"({startup_sync.get('bytes_indexed_this_sync', 0)} bytes)."
                )

    def on_tool(self, name, arguments, result):
        count = None
        if isinstance(result, dict):
            count = result.get("total_count", result.get("total_events", result.get("count")))
        line = f"TOOL {name} {json.dumps(arguments, sort_keys=True)} -> {count if count is not None else 'result'}"
        with self._lock:
            self.pending_tool_lines.append(line)
            self.lines.append(line)

    def on_status(self, phase: str, detail: str) -> None:
        with self._lock:
            self._request_status = detail
            if phase == "context_compressed":
                self.lines.append(f"NOTICE: {detail}")
            elif phase in {"usage", "usage_detail"}:
                self.lines.append(f"USAGE: {detail}")

    def _start_index_refresh(self) -> bool:
        """Refresh appended EVE records while the user reads the last answer."""
        if self._shutdown_requested.is_set():
            return False
        with self._refresh_lock:
            if self._refresh_thread and self._refresh_thread.is_alive():
                self._refresh_requested = True
                return True
            self._refresh_error = None
            self._refresh_result = None
            self._refresh_error_reported = True
            self._refresh_result_reported = False
            self._refresh_requested = False

            def refresh_worker():
                combined: dict | None = None
                try:
                    while True:
                        result = self.agent.tools.sync_index_independently()
                        if combined is None:
                            combined = dict(result)
                        elif not result.get("deferred"):
                            inserted_total = int(combined.get("inserted", 0)) + int(result.get("inserted", 0))
                            bytes_total = int(combined.get("bytes_indexed_this_sync", 0)) + int(result.get("bytes_indexed_this_sync", 0))
                            combined.update(result)
                            combined["inserted"] = inserted_total
                            combined["bytes_indexed_this_sync"] = bytes_total
                        with self._refresh_lock:
                            repeat = self._refresh_requested and not self._shutdown_requested.is_set()
                            self._refresh_requested = False
                        if not repeat:
                            break
                    with self._refresh_lock:
                        self._refresh_result = combined
                except Exception as exc:
                    with self._refresh_lock:
                        self._refresh_error = f"{exc.__class__.__name__}: {exc}"
                        self._refresh_error_reported = False

            self._refresh_thread = threading.Thread(
                target=refresh_worker,
                name="suricata-eve-index-refresh",
                daemon=True,
            )
            self._refresh_thread.start()
            return True

    def _report_index_refresh_error(self) -> None:
        with self._refresh_lock:
            thread = self._refresh_thread
            if thread and thread.is_alive():
                return
            error = self._refresh_error
            result = self._refresh_result
            if error and not self._refresh_error_reported:
                self._refresh_error_reported = True
                message = f"INDEX WARNING: Background refresh failed ({error})"
            elif result is not None and not self._refresh_result_reported:
                self._refresh_result_reported = True
                if result.get("deferred"):
                    message = "INDEX REFRESH: Another synchronization was already active; the next refresh will retry."
                else:
                    message = (
                        "INDEX REFRESHED: "
                        f"{result.get('inserted', 0)} new records committed "
                        f"({result.get('bytes_indexed_this_sync', 0)} bytes)."
                    )
            else:
                return
        with self._lock:
            self.lines.append(message)

    def index_refreshing(self) -> bool:
        with self._refresh_lock:
            return bool(self._refresh_thread and self._refresh_thread.is_alive())

    def start_background_verification(self) -> bool:
        if self._shutdown_requested.is_set():
            return False
        with self._verification_lock:
            if self._verification_thread and self._verification_thread.is_alive():
                return False
            self._verification_result = None
            self._verification_error = None
            self._verification_reported = False

            def verification_worker():
                try:
                    if self._shutdown_requested.wait(BACKGROUND_VERIFY_GRACE_SECONDS):
                        return
                    while self._request_active.is_set() and not self._shutdown_requested.wait(0.1):
                        pass
                    if self._shutdown_requested.is_set():
                        return
                    result = self.agent.tools.verify_index_independently()
                    with self._verification_lock:
                        self._verification_result = result
                except Exception as exc:
                    with self._verification_lock:
                        self._verification_error = f"{exc.__class__.__name__}: {exc}"

            self._verification_thread = threading.Thread(
                target=verification_worker,
                name="suricata-index-integrity-check",
                daemon=True,
            )
            self._verification_thread.start()
        with self._lock:
            self.lines.append("INDEX VERIFY: Database-wide SQLite quick_check scheduled in the background after a brief idle period.")
        return True

    def index_verifying(self) -> bool:
        with self._verification_lock:
            return bool(self._verification_thread and self._verification_thread.is_alive())

    def _report_background_verification(self) -> None:
        with self._verification_lock:
            thread = self._verification_thread
            if not thread or thread.is_alive() or self._verification_reported:
                return
            self._verification_reported = True
            result = self._verification_result
            error = self._verification_error
        with self._lock:
            if error:
                self.lines.append(f"INDEX WARNING: Background integrity check failed ({error}); indexed searches are disabled.")
            elif result and result.get("index_integrity") == "ok":
                self.lines.append(
                    "INDEX VERIFIED: Full background integrity check passed "
                    f"at record {result.get('verified_record_id', 0)}."
                )
            else:
                self.lines.append("INDEX WARNING: Background integrity check returned an unhealthy result; indexed searches are disabled.")

    def shutdown(self, timeout: float | None = None, progress=None) -> dict[str, bool]:
        """Cooperatively stop workers and report whether SQLite may be closed."""
        self._shutdown_requested.set()
        self.agent.request_stop()
        with self._request_lock:
            request_thread = self._request_thread
        with self._refresh_lock:
            refresh_thread = self._refresh_thread
        with self._verification_lock:
            verification_thread = self._verification_thread
        workers = [
            ("active investigation", request_thread),
            ("background index refresh", refresh_thread),
            ("background integrity check", verification_thread),
        ]
        alive = [(name, thread) for name, thread in workers if thread and thread.is_alive() and thread is not threading.current_thread()]
        if progress:
            progress("Cancellation requested for the active investigation")
            if alive:
                progress("Waiting for " + " and ".join(name for name, _ in alive))
            else:
                progress("No active worker threads remain")

        if timeout is None:
            for _, thread in alive:
                thread.join()
        else:
            deadline = time.monotonic() + max(0.0, timeout)
            while any(thread.is_alive() for _, thread in alive) and time.monotonic() < deadline:
                for _, thread in alive:
                    if thread.is_alive():
                        thread.join(timeout=min(0.1, max(0.0, deadline - time.monotonic())))

        request_stopped = not request_thread or not request_thread.is_alive()
        refresh_stopped = not refresh_thread or not refresh_thread.is_alive()
        verification_stopped = not verification_thread or not verification_thread.is_alive()
        return {
            "request_stopped": request_stopped,
            "refresh_stopped": refresh_stopped,
            "verification_stopped": verification_stopped,
            "safe_to_close": request_stopped and refresh_stopped and verification_stopped,
        }

    def close(self) -> bool:
        return self.shutdown(timeout=None)["safe_to_close"]

    def quit_requested(self) -> bool:
        return self._quit_requested.is_set()

    def ask(self, question: str, refresh_after: bool = False) -> str:
        if self._shutdown_requested.is_set():
            raise AgentCancelled("Shutdown is already in progress")
        if self.index_refreshing():
            with self._lock:
                self.lines.append("INDEX SNAPSHOT: Answering from the last committed snapshot while refresh continues.")
        if self._shutdown_requested.is_set():
            raise AgentCancelled("Shutdown is already in progress")
        self._request_active.set()
        try:
            self.agent.prepare_request()
            if self._shutdown_requested.is_set():
                self.agent.request_stop()
                raise AgentCancelled("Shutdown is already in progress")
            with self._lock:
                self.pending_tool_lines.clear()
                self._request_status = "Preparing request"
            answer = self.agent.ask(question)
        finally:
            self._request_active.clear()
        with self._lock:
            self.lines.append("ASSISTANT")
            self.lines.extend(answer.splitlines() or [answer])
        if refresh_after and not self._shutdown_requested.is_set():
            self._start_index_refresh()
        return answer

    def run_cli(self, question: str) -> int:
        try:
            answer = self.ask(question)
        except AgentError as exc:
            print(f"Agent error: {exc}")
            return 1
        for line in self.lines:
            if line.startswith(("NOTICE:", "USAGE:")):
                print(line)
        for line in self.pending_tool_lines:
            print(line)
        print(answer)
        return 0

    def run_tui(self):
        curses.wrapper(self._draw)

    def save_context(self) -> Path:
        """Save the current conversation as a readable, owner-only text file."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        context_dir = Path(__file__).resolve().parent / "context"
        context_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        path = context_dir / f"context_{timestamp}.txt"
        with self._lock:
            history = list(self.agent.history())

        output = [
            "SURICATA AGENT CONTEXT",
            f"Saved: {datetime.now().astimezone().isoformat()}",
            f"Model: {self.agent.model}",
            "",
        ]
        metrics = getattr(self.agent, "last_metrics", None)
        if metrics:
            output.extend(["--- LAST INVESTIGATION METRICS ---", json.dumps(metrics, indent=2, sort_keys=True), ""])
        for index, message in enumerate(history, start=1):
            output.append(f"--- MESSAGE {index} | {message.get('role', 'unknown').upper()} ---")
            content = message.get("content")
            if content is not None:
                output.append(str(content))
            tool_calls = message.get("tool_calls")
            if tool_calls:
                output.append("TOOL_CALLS:")
                output.append(json.dumps(tool_calls, indent=2, sort_keys=True))
            output.append("")

        path.write_text("\n".join(output), encoding="utf-8")
        path.chmod(0o600)
        return path

    def _draw(self, screen):
        try:
            curses.curs_set(1)
        except curses.error:
            pass
        screen.keypad(True)
        screen.timeout(100)
        question = ""
        cursor = 0
        command_index = 0
        scroll_offset = 0
        worker: threading.Thread | None = None
        worker_error: str | None = None
        busy = False
        spinner = 0

        def command_matches():
            if not question.startswith("/"):
                return []
            return [command for command in UI_COMMANDS if command.startswith(question)]

        def finish_request():
            nonlocal worker, worker_error, busy, scroll_offset
            if worker is None or worker.is_alive():
                return
            worker.join()
            worker = None
            busy = False
            if worker_error:
                with self._lock:
                    self.lines.append(f"ERROR: {worker_error}")
                worker_error = None
            scroll_offset = 0

        def start_request(command: str):
            nonlocal worker, worker_error, busy, scroll_offset
            with self._lock:
                self.lines.append(f"USER: {command}")
                self.pending_tool_lines.clear()
            worker_error = None
            busy = True
            scroll_offset = 0

            def request_worker():
                nonlocal worker_error
                try:
                    self.ask(command, refresh_after=True)
                except AgentCancelled:
                    pass
                except AgentError as exc:
                    worker_error = str(exc)

            worker = threading.Thread(target=request_worker, daemon=True)
            with self._request_lock:
                self._request_thread = worker
            worker.start()

        while True:
            finish_request()
            self._report_index_refresh_error()
            self._report_background_verification()
            screen.erase()
            height, width = screen.getmaxyx()
            if height < 5 or width < 20:
                screen.addnstr(0, 0, "Terminal window too small; resize it.", max(1, width - 1))
                screen.refresh()
                try:
                    key = screen.get_wch()
                except curses.error:
                    continue
                if key == curses.KEY_RESIZE:
                    continue
                continue

            with self._lock:
                display_lines = list(self.lines)
            wrapped = []
            for line in display_lines:
                parts = textwrap.wrap(line, width=max(1, width - 1), replace_whitespace=False,
                                      drop_whitespace=False) or [""]
                wrapped.extend(parts)
            usable = max(1, height - 3)
            max_scroll = max(0, len(wrapped) - usable)
            scroll_offset = min(scroll_offset, max_scroll)
            end = len(wrapped) - scroll_offset
            start = max(0, end - usable)
            for row, line in enumerate(wrapped[start:end], 1):
                screen.addnstr(row, 0, line, max(1, width - 1))
            if len(wrapped) > usable:
                # Keep the scrollbar out of the text column.  ASCII glyphs
                # work reliably across terminals and remote SSH sessions.
                track_height = usable
                thumb_height = max(1, (track_height * track_height) // len(wrapped))
                thumb_top = (scroll_offset * max(0, track_height - thumb_height)) // max_scroll
                for row in range(track_height):
                    glyph = "#" if thumb_top <= row < thumb_top + thumb_height else "|"
                    try:
                        screen.addch(row + 1, width - 1, glyph, curses.A_DIM)
                    except curses.error:
                        pass

            if busy:
                spinner_char = "|/-\\"[spinner % 4]
                with self._lock:
                    request_status = self._request_status
                status = f"{spinner_char} {request_status}...  (Up/PageUp scroll, Down/PageDown follow)"
                spinner += 1
            elif self.index_refreshing():
                status = "Ready (indexing newly appended EVE records in background)"
            elif self.index_verifying():
                status = "Ready (database-wide SQLite quick_check scheduled/running in background)"
            elif scroll_offset:
                status = f"Viewing older messages ({scroll_offset} lines up)  (End follows newest)"
            else:
                status = "Ready"
            screen.addnstr(height - 2, 0, status, max(1, width - 1), curses.A_DIM)

            matches = command_matches()
            if matches:
                command_index = min(command_index, len(matches) - 1)
                menu_items = matches[:6]
                menu_top = max(1, height - 3 - len(menu_items))
                try:
                    screen.addnstr(menu_top, 0, "COMMANDS", max(1, width - 1), curses.A_BOLD)
                    for offset, command in enumerate(menu_items, start=1):
                        marker = "> " if offset - 1 == command_index else "  "
                        screen.addnstr(menu_top + offset, 0, marker + command, max(1, width - 1))
                except curses.error:
                    pass

            input_width = max(1, width - 3)
            visible_start = max(0, cursor - input_width + 1)
            visible_text = question[visible_start:visible_start + input_width]
            screen.addnstr(height - 1, 0, "> " + visible_text, max(1, width - 1))
            try:
                screen.move(height - 1, min(width - 1, 2 + cursor - visible_start))
            except curses.error:
                pass
            screen.refresh()
            try:
                key = screen.get_wch()
            except curses.error:
                continue
            if key == -1:
                continue
            if key == curses.KEY_RESIZE:
                continue
            if key in (curses.KEY_UP, curses.KEY_DOWN) and command_matches():
                matches = command_matches()
                if key == curses.KEY_UP:
                    command_index = (command_index - 1) % len(matches)
                else:
                    command_index = (command_index + 1) % len(matches)
                continue
            if key == "\t" and command_matches():
                matches = command_matches()
                question = matches[min(command_index, len(matches) - 1)]
                cursor = len(question)
                command_index = 0
                continue
            if key in (curses.KEY_UP, curses.KEY_PPAGE):
                scroll_offset = min(max_scroll, scroll_offset + (1 if key == curses.KEY_UP else usable))
                continue
            if key in (curses.KEY_DOWN, curses.KEY_NPAGE):
                scroll_offset = max(0, scroll_offset - (1 if key == curses.KEY_DOWN else usable))
                continue
            if key in (curses.KEY_HOME,):
                if question:
                    cursor = 0
                else:
                    scroll_offset = max_scroll
                continue
            if key in (curses.KEY_END,):
                if question:
                    cursor = len(question)
                else:
                    scroll_offset = 0
                continue
            if key in ("\n", "\r"):
                matches = command_matches()
                selected_command = matches[min(command_index, len(matches) - 1)] if matches else ""
                if matches and question.strip() != selected_command:
                    question = selected_command
                    cursor = len(question)
                    command_index = 0
                    continue
                command = question.strip()
                question = ""
                cursor = 0
                if not command:
                    continue
                if command == "/quit":
                    self._quit_requested.set()
                    return
                if busy:
                    if command != "/context":
                        with self._lock:
                            self.lines.append("INFO: Still waiting for the previous request to finish.")
                        continue
                if command == "/help":
                    with self._lock:
                        self.lines.extend(["Commands: /help /clear /context /history /status /quit",
                                           "Arrow keys/PageUp/PageDown/Home/End scroll the conversation.",
                                           "Or enter an investigation question."])
                    scroll_offset = 0
                    continue
                if command == "/clear":
                    self.agent.clear()
                    with self._lock:
                        self.lines.clear()
                    scroll_offset = 0
                    continue
                if command == "/history":
                    with self._lock:
                        self.lines.extend(f"{m.get('role')}: {str(m.get('content'))[:width - 10]}" for m in self.agent.history())
                    scroll_offset = 0
                    continue
                if command == "/status":
                    try:
                        status_result = self.agent.tools.get_sensor_status()
                        with self._lock:
                            self.lines.extend(json.dumps(status_result, indent=2, sort_keys=True).splitlines())
                    except Exception as exc:
                        with self._lock:
                            self.lines.append(f"ERROR: Could not read sensor status ({exc.__class__.__name__})")
                    scroll_offset = 0
                    continue
                if command == "/context":
                    try:
                        path = self.save_context()
                        with self._lock:
                            self.lines.append(f"CONTEXT SAVED: {path}")
                    except OSError as exc:
                        with self._lock:
                            self.lines.append(f"ERROR: Could not save context ({exc.__class__.__name__})")
                    scroll_offset = 0
                    continue
                start_request(command)
                command_index = 0
            elif key in (curses.KEY_BACKSPACE, "\x7f", "\b"):
                if cursor:
                    question = question[:cursor - 1] + question[cursor:]
                    cursor -= 1
                command_index = 0
            elif key == curses.KEY_DC:
                if cursor < len(question):
                    question = question[:cursor] + question[cursor + 1:]
                command_index = 0
            elif key == curses.KEY_LEFT:
                cursor = max(0, cursor - 1)
            elif key == curses.KEY_RIGHT:
                cursor = min(len(question), cursor + 1)
            elif isinstance(key, str) and key.isprintable():
                question = question[:cursor] + key + question[cursor:]
                cursor += len(key)
                command_index = 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Read-only Suricata investigation agent")
    parser.add_argument("--ask", help="Run one question and exit")
    parser.add_argument("--config", type=Path, default=default_config_path(), help="Owner-only agent options file")
    parser.add_argument("--eve-log", help="Override the configured EVE source for this run")
    parser.add_argument("--index-path", help="SQLite EVE index path. Default: a per-log database under ~/.cache/suricata-agent/")
    parser.add_argument("--build-index", action="store_true", help="Incrementally update the EVE index, print health/status JSON, and exit without using the OpenAI API")
    parser.add_argument("--verify-index", action="store_true", help="Synchronize and run a blocking database-wide SQLite quick_check, print status JSON, and exit without using the OpenAI API")
    parser.add_argument("--debug", action="store_true", help="Log interpreted intent, tool queries, counts, and automatic fallbacks to stderr")
    args = parser.parse_args()
    tools = None
    interface = None
    progress = StartupProgress()
    exit_code = 0
    interrupted = False
    safe_to_close = True
    try:
        config = load_config(args.config)
        eve_log = Path(args.eve_log or config["eve_log"]).expanduser()
        configured_index = args.index_path or config["index_path"]
        index_path = Path(configured_index).expanduser() if configured_index else default_index_path(eve_log)
        progress.message(f"Agent options: {args.config} ({'loaded' if args.config.exists() else 'built-in defaults'})")
        progress.message(f"Checking EVE log: {eve_log}")
        try:
            source_info = eve_log.stat()
        except FileNotFoundError:
            source_info = None
        except PermissionError as exc:
            raise source_access_error(eve_log, exc) from exc
        if source_info and stat.S_ISREG(source_info.st_mode):
            exposure = check_source_log_permissions(
                eve_log,
                config["security"]["source_log_permissions"],
                config["security"]["trusted_log_group"],
            )
            if exposure:
                progress.message(exposure, "warning")
            progress.message(
                f"EVE log found: {_human_bytes(eve_log.stat().st_size)}, "
                "readable=yes"
            )
        elif source_info:
            raise ValueError(f"EVE source is not a regular file: {eve_log}")
        else:
            progress.message("EVE log is not currently available; the agent will report this as a telemetry warning", "warning")
        progress.message(f"Opening {'existing' if index_path.is_file() else 'new'} SQLite index: {index_path}")
        tools = SuricataTools(eve_log, index_path=index_path)
        progress.message("SQLite schema opened successfully")
        if args.build_index or args.verify_index:
            progress.message("Synchronizing EVE records and checking index fidelity")
            status = tools.suricata_status(progress=progress, full_verify=True)
            if status.get("index_integrity") == "ok":
                progress.message("Index build/check complete; emitting JSON status", "ready")
            else:
                progress.message(f"Index fidelity check returned: {status.get('index_integrity', 'unavailable')}", "warning")
            print(json.dumps(status, indent=2, sort_keys=True))
            exit_code = 0 if status.get("eve_log_readable") and not status.get("index_lag_bytes") else 1
        else:
            progress.message("Validating agent configuration and API credentials")
            agent = SuricataAgent(tools=tools, debug=args.debug or config["debug"] or None)
            progress.message("Agent configuration validated")
            # Validate the agent configuration first, then pre-warm the index
            # before the interactive interface can accept a question.
            progress.message("Synchronizing EVE records before accepting a prompt")
            startup_sync = tools.sync_index(progress=progress, verify="auto")
            if startup_sync.get("error"):
                progress.message(startup_sync["error"], "warning")
            else:
                fidelity = startup_sync.get("fidelity", {})
                lag = int(fidelity.get("index_lag_bytes", 0))
                suffix = "; one incomplete live EVE line is deferred" if startup_sync.get("partial_line_pending") else ""
                progress.message(
                    f"Ready for questions: integrity={fidelity.get('index_integrity')}, "
                    f"records={fidelity.get('record_count', 0)}, lag={_human_bytes(lag)}{suffix}",
                    "ready",
                )
            interface = Interface(agent, startup_sync=startup_sync)
            if not args.ask and startup_sync.get("fidelity", {}).get("background_verify_due"):
                interface.start_background_verification()
            exit_code = interface.run_cli(args.ask) if args.ask else 0
            if not args.ask:
                interface.run_tui()
    except KeyboardInterrupt:
        interrupted = True
        exit_code = 130
    except (AgentError, OSError, RuntimeError, ValueError) as exc:
        print(f"Agent error: {exc}")
        exit_code = 1
    finally:
        try:
            quit_requested = bool(interface and getattr(interface, "quit_requested", lambda: False)())
            if interrupted:
                progress.message("Ctrl+C received; beginning graceful shutdown", "shutdown")
            elif quit_requested:
                progress.message("/quit received; beginning graceful shutdown", "shutdown")
            if interface:
                if interrupted or quit_requested:
                    shutdown = interface.shutdown(
                        timeout=5.0,
                        progress=lambda message: progress.message(message, "shutdown"),
                    )
                    safe_to_close = shutdown["safe_to_close"]
                    if safe_to_close:
                        progress.message("Investigation and index workers stopped", "shutdown")
                    else:
                        progress.message(
                            "A worker did not stop within 5 seconds; SQLite close is deferred to process termination",
                            "warning",
                        )
                else:
                    safe_to_close = interface.close()
            elif interrupted:
                progress.message("No interactive worker threads were started", "shutdown")

            if tools and safe_to_close:
                if interrupted or quit_requested:
                    progress.message("Closing SQLite index", "shutdown")
                tools.close()
            if interrupted:
                progress.message("Shutdown complete (exit code 130)", "shutdown")
            elif quit_requested:
                progress.message("Shutdown complete (exit code 0)", "shutdown")
        except KeyboardInterrupt:
            interrupted = True
            exit_code = 130
            progress.message("Second interrupt received; forcing process exit without a traceback", "warning")
        except Exception as exc:
            if interrupted:
                progress.message(f"Cleanup warning: {exc.__class__.__name__}: {exc}", "warning")
            else:
                print(f"Agent shutdown error: {exc}")
                exit_code = 1
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
