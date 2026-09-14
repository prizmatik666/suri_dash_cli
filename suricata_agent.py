#!/usr/bin/env python3
"""Central CLI/TUI entry point for the local Suricata investigation agent."""

from __future__ import annotations

import argparse
import curses
import json
import threading
import textwrap
from datetime import datetime
from pathlib import Path

from agent_runtime import AgentError, SuricataAgent


UI_COMMANDS = ["/help", "/clear", "/context", "/history", "/status", "/quit"]


class Interface:
    def __init__(self, agent: SuricataAgent):
        self.agent = agent
        self.lines: list[str] = []
        self.pending_tool_lines: list[str] = []
        self._lock = threading.Lock()
        agent.on_tool = self.on_tool

    def on_tool(self, name, arguments, result):
        count = result.get("count") if isinstance(result, dict) else None
        line = f"TOOL {name} {json.dumps(arguments, sort_keys=True)} -> {count if count is not None else 'result'}"
        with self._lock:
            self.pending_tool_lines.append(line)
            self.lines.append(line)

    def ask(self, question: str) -> str:
        with self._lock:
            self.pending_tool_lines.clear()
        answer = self.agent.ask(question)
        with self._lock:
            self.lines.append("ASSISTANT")
            self.lines.extend(answer.splitlines() or [answer])
        return answer

    def run_cli(self, question: str) -> int:
        try:
            answer = self.ask(question)
        except AgentError as exc:
            print(f"Agent error: {exc}")
            return 1
        for line in self.pending_tool_lines:
            print(line)
        print(answer)
        return 0

    def run_tui(self):
        curses.wrapper(self._draw)

    def save_context(self) -> Path:
        """Save the current conversation as a readable, owner-only text file."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        path = Path(__file__).resolve().parent / f"context_{timestamp}.txt"
        with self._lock:
            history = list(self.agent.history())

        output = [
            "SURICATA AGENT CONTEXT",
            f"Saved: {datetime.now().astimezone().isoformat()}",
            f"Model: {self.agent.model}",
            "",
        ]
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
                    self.ask(command)
                except AgentError as exc:
                    worker_error = str(exc)

            worker = threading.Thread(target=request_worker, daemon=True)
            worker.start()

        while True:
            finish_request()
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
                status = f"{spinner_char} Waiting for model/tools...  (Up/PageUp scroll, Down/PageDown follow)"
                spinner += 1
            elif scroll_offset:
                status = f"Viewing older messages ({scroll_offset} lines up)  (End follows newest)"
            else:
                status = "Ready"
            screen.addnstr(height - 2, 0, status, max(1, width - 1), curses.A_DIM)

            matches = command_matches()
            if matches:
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
                question = matches[command_index]
                cursor = len(question)
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
                if matches and question.strip() != matches[command_index]:
                    question = matches[command_index]
                    cursor = len(question)
                    continue
                command = question.strip()
                question = ""
                cursor = 0
                if not command:
                    continue
                if busy:
                    if command != "/context":
                        with self._lock:
                            self.lines.append("INFO: Still waiting for the previous request to finish.")
                        continue
                if command == "/quit":
                    return
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
    parser.add_argument("--eve-log", default="/var/log/suricata/eve.json")
    args = parser.parse_args()
    try:
        agent = SuricataAgent()
        agent.tools.eve_log = Path(args.eve_log).expanduser()
        interface = Interface(agent)
    except AgentError as exc:
        print(f"Agent error: {exc}")
        return 1
    if args.ask:
        return interface.run_cli(args.ask)
    interface.run_tui()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
