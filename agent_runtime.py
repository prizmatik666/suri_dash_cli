"""OpenAI native-tool agent runtime for Suricata investigations."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Callable

import requests
from dotenv import load_dotenv

from suricata_tools import SuricataTools


PROJECT_ROOT = Path(__file__).resolve().parent
load_dotenv(PROJECT_ROOT / ".env")
OPENAI_URL = "https://api.openai.com/v1/chat/completions"
DEFAULT_MODEL = "gpt-4o-mini"
MAX_TOOL_CALLS = 8

SYSTEM_PROMPT = """You are a careful Suricata incident-investigation assistant.
Use the available read-only tools to gather evidence before concluding. Start
with alerts or sensor status as appropriate, then pivot using event IDs, flow
IDs, IPs, ports, signatures, and timestamps. Treat event_id and flow_id as
different identifiers. Alert results may contain a flow_id without an
event_id; use the flow_id for event retrieval or correlation in that case.
Never invent observations. Keep
tool queries narrow and respect result limits. In the final response, separate
Observed Evidence, Correlation, Assessment, Uncertainty, and Recommended Next
Steps. Cite event_id values and timestamps when available. Do not reveal hidden
chain-of-thought; provide a concise auditable rationale instead. For an explicit
request to search the entire retained log, set all_history=true. A zero-result
query means only that no matching events were found in the selected log window;
never describe that alone as proof that the environment is safe or stable.
When a query returns no results, explain the exact filters and time window, then
suggest a broader read-only query if appropriate."""


class AgentError(RuntimeError):
    pass


def _schema(name: str, description: str, properties: dict[str, dict], required: list[str] = []) -> dict:
    return {"type": "function", "function": {"name": name, "description": description, "parameters": {"type": "object", "properties": properties, "required": required, "additionalProperties": False}}}


def _tool_schemas() -> list[dict]:
    return [
        _schema("get_sensor_status", "Inspect local Suricata configuration and log availability.", {}),
        _schema("search_alerts", "Find Suricata alert events. The signature filter matches alert signatures and nested DNS query names, including domains.", {
            "src_ip": {"type": "string"}, "dest_ip": {"type": "string"}, "signature": {"type": "string"},
            "sid": {"type": "integer", "default": 0}, "severity": {"type": "integer", "default": 0},
            "lookback_hours": {"type": "integer", "default": 24, "minimum": 1, "maximum": 720},
            "limit": {"type": "integer", "default": 20, "minimum": 1, "maximum": 50},
            "all_history": {"type": "boolean", "default": False},
        }),
        _schema("get_event", "Retrieve one Suricata EVE event by event_id or flow_id. Provide an identifier returned by a previous tool; event_id and flow_id are different fields.", {
            "event_id": {"type": "string"},
            "flow_id": {"type": "integer", "default": 0},
        }),
        _schema("search_related_events", "Find nearby Suricata events sharing a flow or source/destination pair.", {
            "src_ip": {"type": "string"}, "dest_ip": {"type": "string"}, "flow_id": {"type": "integer", "default": 0},
            "lookback_minutes": {"type": "integer", "default": 15, "minimum": 1, "maximum": 1440},
            "limit": {"type": "integer", "default": 30, "minimum": 1, "maximum": 50},
            "all_history": {"type": "boolean", "default": False},
        }),
    ]


class SuricataAgent:
    def __init__(self, tools: SuricataTools | None = None, on_tool: Callable[[str, dict, Any], None] | None = None):
        self.tools = tools or SuricataTools()
        self.registry = self.tools.tool_registry()
        self.on_tool = on_tool
        self.model = os.getenv("OPENAI_MODEL") or DEFAULT_MODEL
        self.messages: list[dict[str, Any]] = []
        key = os.getenv("OPENAI_API_KEY")
        if not key:
            raise AgentError(f"OPENAI_API_KEY is not configured in {PROJECT_ROOT / '.env'}")
        self._api_key = key

    def clear(self) -> None:
        self.messages.clear()

    def history(self) -> list[dict[str, Any]]:
        return list(self.messages)

    def ask(self, question: str) -> str:
        self.messages.append({"role": "user", "content": question})
        for _ in range(MAX_TOOL_CALLS):
            body = {"model": self.model, "messages": [{"role": "system", "content": SYSTEM_PROMPT}, *self.messages], "tools": _tool_schemas(), "tool_choice": "auto"}
            try:
                response = requests.post(OPENAI_URL, headers={"Authorization": f"Bearer {self._api_key}", "Content-Type": "application/json"}, json=body, timeout=45)
            except requests.RequestException as exc:
                raise AgentError(f"OpenAI request failed ({exc.__class__.__name__})") from None
            if response.status_code >= 400:
                raise AgentError(f"OpenAI API returned HTTP {response.status_code}")
            try:
                assistant = response.json()["choices"][0]["message"]
            except (ValueError, KeyError, IndexError, TypeError):
                raise AgentError("OpenAI returned an unexpected response") from None
            tool_calls = assistant.get("tool_calls") or []
            if not tool_calls:
                content = assistant.get("content") or ""
                self.messages.append({"role": "assistant", "content": content})
                return content
            self.messages.append({"role": "assistant", "content": assistant.get("content"), "tool_calls": tool_calls})
            for call in tool_calls:
                function = call.get("function", {})
                name = function.get("name")
                try:
                    arguments = json.loads(function.get("arguments", "{}"))
                except (TypeError, ValueError):
                    arguments = {}
                capability = self.registry.get(name)
                result = capability(**arguments) if capability else {"error": f"Unapproved tool: {name}"}
                if self.on_tool:
                    self.on_tool(name or "unknown", arguments, result)
                self.messages.append({"role": "tool", "tool_call_id": call.get("id", name), "name": name, "content": json.dumps(result, separators=(",", ":"))})
        raise AgentError(f"Stopped after {MAX_TOOL_CALLS} tool calls without a final answer")
