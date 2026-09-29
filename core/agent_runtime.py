"""OpenAI tool-calling runtime for evidence-first Suricata investigations."""

from __future__ import annotations

import json
import os
import re
import sys
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable

import requests
from dotenv import load_dotenv

from .agent_context import MAX_LOCAL_INVESTIGATIONS, investigation_state, replay_message, tool_state
from .agent_metrics import InvestigationMetrics
from .agent_payloads import model_tool_result
from .suricata_tools import MAX_LOOKBACK_MINUTES, SuricataTools, _iso, _parse_time


PROJECT_ROOT = Path(__file__).resolve().parent.parent
load_dotenv(PROJECT_ROOT / ".env")
OPENAI_URL = "https://api.openai.com/v1/responses"
DEFAULT_MODEL = "gpt-6-sol"
MAX_TOOL_CALLS = 12
MAX_COMPRESSED_CONTEXT_CHARS = 24_000

SYSTEM_PROMPT = """You are a careful Suricata incident investigator, not a thin
query wrapper. Translate conversational requests into hosts, peers, ports,
protocols, actions, and exact time windows. Prefer gathering reasonable
evidence over asking the user to name Suricata event types.

Investigation policy:
1. For a host request, start broad enough to verify traffic exists. Use
   investigate_host or search_events with either_ip unless the user explicitly
   limits direction. A shorthand such as .3 may be passed as either_ip=.3; the
   tool reports every matching full IP so ambiguity remains visible.
   For IPv6, inspect ip_resolution. Tools normalize equivalent IPv6 text and may
   recover a uniquely active full address from an abbreviated prefix/suffix.
   State that resolution explicitly. Never merge ambiguous candidates or treat
   an exact-literal miss as proof that a similarly suffixed device was inactive.
2. Never invent an absolute date for relative time language. For "last/past N
   minutes/hours", pass lookback_minutes/lookback_hours and let the tool resolve
   it from its clock. For "N minutes ago" or "around 6 AM", use the time tools
   and the current-clock anchor supplied with this request. Explicit dates given
   by the user take precedence. Report the tool's resolved_window. Default
   time_basis=either so event timestamps and flow.start/flow.end are considered.
3. Narrow to relevant protocols only after verifying broad activity. Correlate
   interesting flow IDs, inspect connection outcomes, look immediately before
   and after, check repeat occurrences, and consider local discovery protocols.
4. No alert never means no traffic. A zero-result narrow query never proves no
   activity. The runtime may attach an automatic_fallback containing broad host
   evidence and a direct raw-EVE check; use it. A raw witness with
   count_exact=false proves existence only, not a full-window count. If diagnostics indicate records,
   direction, timestamp-basis, truncation, telemetry staleness, or a search-layer
   discrepancy, state that explicitly and continue with the relevant tool. A
   zero with ip_resolution.status=not_found or ambiguous_suffix is an unresolved
   identity result, not proof of host inactivity. Never claim "no uncertainty."
5. Check truncated and next_cursor. Aggregates describe the complete match set;
   returned records are a page, not necessarily the full dataset. If
   index_sync.deferred is true, the result is from a valid committed snapshot
   but may omit the refresh batch still being built. For a near-real-time or
   negative conclusion, validate against bounded raw EVE and disclose the lag.
6. Classify statements: Observed is directly present in EVE; Alerted matched an
   IDS signature; Correlated combines records; Inferred is a supported but
   unproven interpretation; Unknown is not established. Never call SYN-only,
   no-response, or refused attempts successful connections.
7. Keep every conclusion traceable with timestamps, flow_id/event_id or
   record_id, file_offset, tuple, event_type, signature ID, DNS name, and packet/byte counts
   when available. Raw EVE remains canonical.
8. For "top requests" or "what did it request" questions, prefer outbound
   direction and report actual DNS/mDNS or HTTP requests separately from TLS SNI
   observations and generic destination flows. SNI and flows are activity, not
   application requests.
9. Keep result unit separate from duplicate handling. Use view=endpoints only
   for distinct endpoints/domains/hosts, view=transactions for request/response
   activity, and view=events for EVE observations. Ordinary event lists may use
   duplicates=group_exact to reduce repeated identical EVE lines while retaining
   every evidence reference. Explicit raw/every-record requests must use
   duplicates=preserve and detail=raw. Never collapse records merely because
   they share a flow_id.
10. "Latest", "last", "newest", or "most recent" requires sort=desc; "first",
   "earliest", or "oldest" requires sort=asc. For a complete flow/chain, use
   correlate_flow chronologically. Its grouping is lossless and distinct DNS
   request, response, alert, TLS, HTTP, and flow records remain separate.
11. Exact duplicate records only establish that matching records occur more
   than once in canonical EVE. Never attribute them to TCP/IP behavior,
   retransmission, Suricata configuration, or another cause unless separate
   evidence directly establishes that cause. Do not call behavior normal,
   benign, unusual, or suspicious merely because it is frequent or generated
   no alert; use baseline or protocol evidence and state the basis.
12. Read tool_call_adjustment when present. An ignored time argument means the
   result is not time-filtered; do not describe it as limited to that window.
13. A correlate_flow model view may be paged even when the complete local
   chain was retrieved. Use logical_event_count/raw_record_count for totals,
   inspect truncated/next_offset, and fetch later pages or get_event for any
   required detail. Never treat a model page as the complete chain.
14. Prior investigation state may include an older_finding_catalog. It is a
   locator, not fresh evidence. If the user asks for the first record cited in
   an older finding, use first_cited_record_id rather than the first sampled
   evidence reference; then verify the chosen ID with get_event. Do not claim
   a sampled record was cited when it was not.

For vague host questions, use investigate_host first. For a pair or service use
investigate_pair/investigate_service. For human action times use events_around.
For an interesting flow use correlate_flow. Use count_raw_eve_matches whenever a
higher-level zero looks inconsistent. compare_host_baseline reports novelty only,
not maliciousness.

Final investigations should use these headings when meaningful: Observed
Evidence, Correlation, Assessment, Uncertainty, Recommended Next Steps. Say
precisely "No Suricata alert records matched" rather than "no traffic" unless a
broad search and raw-EVE sanity check both support no matching activity for a
resolved identity and healthy time window. Do not invent evidence or reveal
hidden chain-of-thought; provide concise auditable rationale."""


_DURATION_UNIT_MINUTES = {
    "s": 1 / 60, "sec": 1 / 60, "secs": 1 / 60, "second": 1 / 60, "seconds": 1 / 60,
    "m": 1, "min": 1, "mins": 1, "minute": 1, "minutes": 1,
    "h": 60, "hr": 60, "hrs": 60, "hour": 60, "hours": 60,
    "d": 1440, "day": 1440, "days": 1440,
    "w": 10080, "week": 10080, "weeks": 10080,
}
_RELATIVE_LOOKBACK_RE = re.compile(
    r"\b(?:last|past|previous|preceding)\b(?P<duration>"
    r"(?:\s*(?:and\s+)?(?:\d+(?:\.\d+)?\s*)?"
    r"(?:seconds?|secs?|s|minutes?|mins?|m|hours?|hrs?|h|days?|d|weeks?|w)\b)+)",
    re.IGNORECASE,
)
_DURATION_TOKEN_RE = re.compile(
    r"(?<![a-z])(?:(?P<amount>\d+(?:\.\d+)?)\s*)?(?P<unit>seconds?|secs?|s|minutes?|mins?|m|hours?|hrs?|h|days?|d|weeks?|w)\b",
    re.IGNORECASE,
)
_AGO_RE = re.compile(
    r"\b(?:about|around|approximately|roughly)?\s*(?P<amount>\d+(?:\.\d+)?)\s*"
    r"(?P<unit>seconds?|secs?|s|minutes?|mins?|m|hours?|hrs?|h)\s+ago\b",
    re.IGNORECASE,
)
_EXPLICIT_DATE_RE = re.compile(
    r"\b\d{4}-\d{2}-\d{2}\b|\b\d{1,2}[/-]\d{1,2}(?:[/-]\d{2,4})?\b|"
    r"\b(?:jan(?:uary)?|feb(?:ruary)?|mar(?:ch)?|apr(?:il)?|may|jun(?:e)?|"
    r"jul(?:y)?|aug(?:ust)?|sep(?:tember)?|oct(?:ober)?|nov(?:ember)?|dec(?:ember)?)\b",
    re.IGNORECASE,
)
_CLOCK_TIME_RE = re.compile(
    r"\b(?:around|about|approximately|near|at)\s+(?P<hour>\d{1,2})"
    r"(?::(?P<minute>\d{2}))?\s*(?P<ampm>a\.?m\.?|p\.?m\.?)\b",
    re.IGNORECASE,
)
_RELATIVE_WINDOW_TOOLS = frozenset({
    "search_events", "investigate_host", "investigate_pair",
    "investigate_service", "search_alerts", "count_raw_eve_matches",
})


def _relative_time_override(
    name: str,
    arguments: dict[str, Any],
    question: str,
    now: datetime | None = None,
) -> tuple[dict[str, Any], str | None]:
    """Replace model-invented dates when the user gave a relative time."""
    resolved = dict(arguments)
    if name not in _RELATIVE_WINDOW_TOOLS and name != "events_around":
        return resolved, None
    if _EXPLICIT_DATE_RE.search(question):
        return resolved, None
    now = now or datetime.now().astimezone()
    now_utc = now.astimezone(timezone.utc)

    lookback = _RELATIVE_LOOKBACK_RE.search(question)
    if lookback:
        minutes = sum(
            float(match.group("amount") or 1) * _DURATION_UNIT_MINUTES[match.group("unit").lower()]
            for match in _DURATION_TOKEN_RE.finditer(lookback.group("duration"))
        )
        if minutes > 0:
            minutes = min(MAX_LOOKBACK_MINUTES, max(1, int(round(minutes))))
            if name == "events_around":
                resolved["timestamp"] = _iso(now_utc) or ""
                resolved["seconds_before"] = minutes * 60
                resolved["seconds_after"] = 0
            else:
                resolved.pop("start_time", None)
                resolved.pop("end_time", None)
                resolved.pop("lookback_hours", None)
                resolved["lookback_minutes"] = minutes
            return resolved, f"relative lookback resolved by runtime to {minutes} minutes from current time"

    ago = _AGO_RE.search(question)
    if ago:
        amount = float(ago.group("amount"))
        delta_minutes = amount * _DURATION_UNIT_MINUTES[ago.group("unit").lower()]
        point = now_utc - timedelta(minutes=delta_minutes)
        if name == "events_around":
            resolved["timestamp"] = _iso(point) or ""
        else:
            before = max(1, int(resolved.get("seconds_before", 60)))
            after = max(1, int(resolved.get("seconds_after", 60)))
            resolved["start_time"] = _iso(point - timedelta(seconds=before)) or ""
            resolved["end_time"] = _iso(point + timedelta(seconds=after)) or ""
            resolved.pop("lookback_minutes", None)
            resolved.pop("lookback_hours", None)
        return resolved, "relative event time resolved by runtime from current time"

    clock = _CLOCK_TIME_RE.search(question)
    if clock:
        hour = int(clock.group("hour"))
        minute = int(clock.group("minute") or 0)
        ampm = clock.group("ampm").lower().replace(".", "")
        if 1 <= hour <= 12 and minute < 60:
            hour = hour % 12 + (12 if ampm == "pm" else 0)
            local_now = now.astimezone()
            day_offset = -1 if re.search(r"\byesterday\b", question, re.IGNORECASE) else 0
            target = (local_now + timedelta(days=day_offset)).replace(
                hour=hour, minute=minute, second=0, microsecond=0
            )
            target_utc = target.astimezone(timezone.utc)
            if name == "events_around":
                resolved["timestamp"] = _iso(target_utc) or ""
                resolved["seconds_before"] = max(1800, int(resolved.get("seconds_before", 0)))
                resolved["seconds_after"] = max(1800, int(resolved.get("seconds_after", 0)))
            else:
                resolved["start_time"] = _iso(target_utc - timedelta(minutes=30)) or ""
                resolved["end_time"] = _iso(target_utc + timedelta(minutes=30)) or ""
                resolved.pop("lookback_minutes", None)
                resolved.pop("lookback_hours", None)
            return resolved, "clock time anchored to the current local date by runtime"
    return resolved, None


def _requested_time_context(question: str, anchor: datetime) -> dict[str, Any]:
    """Preserve the user's relative window separately from actual tool scopes."""
    arguments, note = _relative_time_override("search_events", {}, question, anchor)
    if not note:
        return {}
    if arguments.get("lookback_minutes"):
        end = anchor.astimezone(timezone.utc)
        start = end - timedelta(minutes=int(arguments["lookback_minutes"]))
        return {"start": _iso(start), "end": _iso(end), "source": "relative user wording", "applied_to_tools": "check each tool resolved_window separately"}
    if arguments.get("start_time") and arguments.get("end_time"):
        return {"start": arguments["start_time"], "end": arguments["end_time"], "source": "runtime-anchored user wording", "applied_to_tools": "check each tool resolved_window separately"}
    return {}


class AgentError(RuntimeError):
    pass


class AgentCancelled(AgentError):
    """Raised at a safe checkpoint when graceful shutdown was requested."""


def _schema(name: str, description: str, properties: dict[str, dict], required: list[str] | None = None) -> dict:
    return {
        "type": "function",
        "function": {
            "name": name,
            "description": description,
            "parameters": {
                "type": "object",
                "properties": properties,
                "required": required or [],
                "additionalProperties": False,
            },
        },
    }


TIME_PROPERTIES = {
    "start_time": {"type": "string", "description": "Explicit ISO-8601 window start, preferably with UTC offset."},
    "end_time": {"type": "string", "description": "Explicit ISO-8601 window end, preferably with UTC offset."},
    "lookback_minutes": {"type": "integer", "minimum": 1, "maximum": 43200},
    "lookback_hours": {"type": "integer", "minimum": 1, "maximum": 720, "default": 24},
    "time_basis": {"type": "string", "enum": ["event", "flow", "either"], "default": "either", "description": "Match top-level timestamp, flow start/end, or either."},
    "all_history": {"type": "boolean", "default": False},
}

PAGE_PROPERTIES = {
    "limit": {"type": "integer", "minimum": 1, "maximum": 200, "default": 50},
    "offset": {"type": "integer", "minimum": 0, "default": 0},
}


def _tool_schemas() -> list[dict]:
    search_properties = {
        "src_ip": {"type": "string"}, "dest_ip": {"type": "string"},
        "either_ip": {"type": "string", "description": "Match source OR destination; preferred for general host questions."},
        "src_port": {"type": "integer"}, "dest_port": {"type": "integer"},
        "either_port": {"type": "integer", "description": "Match source OR destination port."},
        "proto": {"type": "string"}, "app_proto": {"type": "string"},
        "event_types": {"type": "array", "items": {"type": "string"}},
        "flow_id": {"type": "integer"}, "signature": {"type": "string"},
        "hostname": {"type": "string"}, "dns_name": {"type": "string"},
        "sni": {"type": "string"}, "http_host": {"type": "string"},
        "http_url": {"type": "string"}, "free_text": {"type": "string"},
        "sort": {"type": "string", "enum": ["asc", "desc"], "default": "asc"},
        "direction": {"type": "string", "enum": ["either", "outbound", "inbound"], "default": "either"},
        "unique_by": {"type": "string", "enum": ["none", "endpoint", "flow_id"], "default": "none", "description": "Use endpoint for distinct semantic endpoints; collapses DNS request/response duplicates by hostname."},
        "view": {"type": "string", "enum": ["events", "endpoints", "flows", "transactions"], "default": "events", "description": "Select the result unit independently from duplicate handling."},
        "duplicates": {"type": "string", "enum": ["preserve", "annotate", "group_exact"], "default": "preserve", "description": "Preserve every record, annotate exact copies, or losslessly group exact copies with all evidence references."},
        "detail": {"type": "string", "enum": ["compact", "standard", "raw"], "default": "standard"},
        "cursor": {"type": "string", "description": "Short opaque next_cursor returned by the preceding page. Reuse it verbatim during the current agent process."},
        **TIME_PROPERTIES, **PAGE_PROPERTIES,
    }
    host_properties = {
        "ip": {"type": "string", "description": "Full IP or shorthand. Equivalent IPv6 forms and one unique active abbreviated IPv6 identity are resolved explicitly."},
        "peer_ip": {"type": "string"},
        "ports": {"type": "array", "items": {"type": "integer"}},
        "focus": {"type": "string"},
        "direction": {"type": "string", "enum": ["either", "outbound", "inbound"], "default": "either"},
        **TIME_PROPERTIES,
        "limit": {"type": "integer", "minimum": 1, "maximum": 200, "default": 25},
    }
    return [
        _schema("suricata_status", "Check current global EVE and index health. Call with {}: this tool accepts no host or time filters.", {}),
        _schema("search_events", "General normalized search across all Suricata EVE event types. Result view, exact-duplicate policy, detail, ordering, and filters are independent so grouping never destroys raw evidence.", search_properties),
        _schema("investigate_host", "Broad cross-protocol host overview with explicit IP identity resolution, top requests, event counts, directions, peers, ports, DNS, TLS, HTTP, alerts, TCP outcomes, bytes/packets, and correlated sequences.", host_properties, ["ip"]),
        _schema("investigate_pair", "Investigate all traffic in both directions between two hosts.", {
            "ip1": {"type": "string"}, "ip2": {"type": "string"},
            "event_types": {"type": "array", "items": {"type": "string"}},
            **TIME_PROPERTIES, **PAGE_PROPERTIES,
        }, ["ip1", "ip2"]),
        _schema("investigate_service", "Investigate all source/destination use of a port involving one host, including TCP outcomes.", {
            "ip": {"type": "string"}, "port": {"type": "integer"},
            **TIME_PROPERTIES, "limit": PAGE_PROPERTIES["limit"],
        }, ["ip", "port"]),
        _schema("events_around", "Find events in a bounded neighborhood around a human-reported action or evidence timestamp.", {
            "timestamp": {"type": "string"}, "seconds_before": {"type": "integer", "minimum": 0, "maximum": MAX_LOOKBACK_MINUTES * 60, "default": 30},
            "seconds_after": {"type": "integer", "minimum": 0, "maximum": MAX_LOOKBACK_MINUTES * 60, "default": 30},
            "ip": {"type": "string"}, "peer": {"type": "string"},
            "event_types": {"type": "array", "items": {"type": "string"}},
            "time_basis": TIME_PROPERTIES["time_basis"], **PAGE_PROPERTIES,
        }, ["timestamp"]),
        _schema("correlate_flow", "Build a complete chronological flow chain across all indexed history. This tool accepts no time filters; use timestamps in its results or search_events for a time-limited view. Distinct records remain separate and exact copies retain every reference.", {
            "flow_id": {"type": "integer"},
            "duplicates": {"type": "string", "enum": ["preserve", "annotate", "group_exact"], "default": "group_exact"},
            "detail": {"type": "string", "enum": ["compact", "standard", "raw"], "default": "compact"},
            "limit": {"type": "integer", "minimum": 1, "maximum": 200, "default": 200},
            "offset": PAGE_PROPERTIES["offset"],
        }, ["flow_id"]),
        _schema("get_event", "Retrieve original raw EVE evidence by stable record_id, event_id, flow_id, or file_offset.", {
            "record_id": {"type": "integer", "description": "Stable SQLite evidence ID; preferred across log rotations."},
            "event_id": {"type": "string"}, "flow_id": {"type": "integer"}, "file_offset": {"type": "integer"},
        }),
        _schema("search_alerts", "Search IDS alert records only. A zero does not establish no traffic; runtime automatically checks broad host activity.", {
            "src_ip": {"type": "string"}, "dest_ip": {"type": "string"}, "either_ip": {"type": "string"},
            "signature": {"type": "string"}, "sid": {"type": "integer"}, "severity": {"type": "integer"},
            **TIME_PROPERTIES, **PAGE_PROPERTIES,
        }),
        _schema("count_raw_eve_matches", "Direct canonical-EVE sanity count for an IP and window; use to detect search-layer discrepancies.", {
            "ip": {"type": "string"}, **TIME_PROPERTIES,
        }),
        _schema("compare_host_baseline", "Compare host peers and DNS names in a current window against an explicit baseline without assigning threat scores.", {
            "ip": {"type": "string"}, "current_start": {"type": "string"}, "current_end": {"type": "string"},
            "baseline_start": {"type": "string"}, "baseline_end": {"type": "string"}, "time_basis": TIME_PROPERTIES["time_basis"],
        }, ["ip", "current_start", "current_end", "baseline_start", "baseline_end"]),
    ]


def _sanitize_tool_arguments(name: str, arguments: dict[str, Any]) -> tuple[dict[str, Any], list[str], str | None]:
    """Enforce the advertised tool contract before calling local Python code."""
    schema = next((item["function"] for item in _tool_schemas() if item["function"]["name"] == name), None)
    if schema is None:
        return arguments, [], None
    allowed = set(schema["parameters"]["properties"])
    ignored = sorted(set(arguments) - allowed)
    cleaned = {key: value for key, value in arguments.items() if key in allowed}
    missing = [key for key in schema["parameters"]["required"] if key not in cleaned]
    if missing:
        return cleaned, ignored, f"Missing required argument(s) for {name}: {', '.join(missing)}"
    return cleaned, ignored, None


def _ignored_argument_note(name: str) -> str:
    if name == "suricata_status":
        return "Current global sensor/index status; host and time filters are not applied."
    if name in {"correlate_flow", "get_flow"}:
        return "Complete flow chain across indexed history; use event timestamps or search_events for a time-limited view."
    return "Only the supported arguments shown in the tool schema were used."


def _result_count(result: Any) -> int | None:
    if not isinstance(result, dict) or result.get("error"):
        return None
    for key in ("total_count", "total_events", "count"):
        if key in result:
            try:
                return int(result[key])
            except (TypeError, ValueError):
                return None
    return None


def _intent(question: str) -> str:
    lowered = question.lower()
    if "alert" in lowered:
        return "alert_investigation"
    if re.search(r"\b(around|when|before|after|ago|morning|hour|minute)\b", lowered):
        return "temporal_host_investigation"
    if re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b|(?:^|\s)\.\d{1,3}\b", question):
        return "host_investigation"
    return "general_investigation"


def _apply_intent_defaults(name: str, arguments: dict[str, Any], question: str) -> dict[str, Any]:
    """Apply only high-confidence, lossless natural-language safeguards."""
    resolved = dict(arguments)
    lowered = question.lower()
    if name == "search_events":
        resolved.setdefault("limit", 20)
        if not resolved.get("sort"):
            if re.search(r"\b(latest|last|newest|most recent)\b", lowered):
                resolved["sort"] = "desc"
            elif re.search(r"\b(first|earliest|oldest)\b", lowered):
                resolved["sort"] = "asc"

        explicit_raw = bool(re.search(r"\b(raw|unaltered|every (?:eve )?record|every (?:eve )?line)\b", lowered))
        if explicit_raw:
            resolved.setdefault("view", "events")
            resolved["duplicates"] = "preserve"
            resolved["detail"] = "raw"
        else:
            if not resolved.get("view") and not resolved.get("unique_by"):
                if re.search(r"\b(?:unique|distinct|different)\s+(?:endpoint|endpoints|domain|domains|host|hosts|name|names|destination|destinations)\b", lowered):
                    resolved["view"] = "endpoints"
                elif re.search(r"\b(?:transaction|transactions|request(?:s)?\s*(?:and|/)\s*response(?:s)?)\b", lowered):
                    resolved["view"] = "transactions"
                else:
                    resolved["view"] = "events"
            # For normal human-facing event lists, group only canonical exact
            # copies. This never groups distinct records sharing a flow ID.
            if resolved.get("view", "events") == "events" and not resolved.get("unique_by"):
                if re.search(r"\b(event|events|recent|latest|last|newest)\b", lowered):
                    resolved.setdefault("duplicates", "group_exact")
            resolved.setdefault("detail", "compact")
    elif name in {"investigate_host", "investigate_pair", "investigate_service", "events_around"}:
        resolved.setdefault("limit", 20)
    elif name in {"correlate_flow", "get_flow"}:
        explicit_raw = bool(re.search(r"\b(raw|unaltered|every (?:eve )?record|every (?:eve )?line)\b", lowered))
        resolved.setdefault("duplicates", "preserve" if explicit_raw else "group_exact")
        resolved.setdefault("detail", "raw" if explicit_raw else "compact")
    return resolved


def _responses_tools() -> list[dict[str, Any]]:
    """Translate the internal function schemas into Responses API tools."""
    return [
        {"type": "function", **tool["function"]}
        for tool in _tool_schemas()
    ]


def _responses_input_from_messages(messages: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Replay the app's compact chat history as Responses input items."""
    items: list[dict[str, Any]] = []
    for message in messages:
        role = message.get("role")
        if role in {"user", "assistant", "system", "developer"}:
            content = message.get("content")
            if isinstance(content, str) and content:
                items.append({"role": "developer" if role == "system" else role, "content": content})
            for call in message.get("tool_calls") or []:
                function = call.get("function") or {}
                items.append({
                    "type": "function_call",
                    "call_id": call.get("id") or call.get("call_id") or "",
                    "name": function.get("name") or "unknown",
                    "arguments": function.get("arguments") or "{}",
                })
        elif role == "tool":
            items.append({
                "type": "function_call_output",
                "call_id": message.get("tool_call_id") or "",
                "output": str(message.get("content") or ""),
            })
    return items


def _responses_output_text(output: Any) -> str:
    chunks: list[str] = []
    if not isinstance(output, list):
        return ""
    for item in output:
        if not isinstance(item, dict):
            continue
        content = item.get("content")
        if not isinstance(content, list):
            continue
        for part in content:
            if isinstance(part, dict) and part.get("type") in {"output_text", "refusal"}:
                if part.get("text"):
                    chunks.append(str(part["text"]))
    return "\n".join(chunks).strip()


def _responses_function_calls(output: Any) -> list[dict[str, Any]]:
    calls: list[dict[str, Any]] = []
    if not isinstance(output, list):
        return calls
    for item in output:
        if not isinstance(item, dict) or item.get("type") != "function_call":
            continue
        calls.append({
            "id": item.get("call_id") or item.get("id") or "",
            "type": "function",
            "function": {"name": item.get("name") or "unknown", "arguments": item.get("arguments") or "{}"},
        })
    return calls


def _has_unsupported_duplicate_cause(content: str) -> bool:
    return bool(re.search(
        r"\b(?:duplicate|duplicates|duplicated)\b.{0,160}\b(?:due to|caused by|owing to|because of)\b.{0,160}\b(?:tcp|retransmi|network behavior|nature of (?:the )?quer)",
        content,
        re.IGNORECASE | re.DOTALL,
    ))


def _api_error_details(response: Any) -> tuple[str, str, str]:
    """Extract safe OpenAI error fields without assuming a valid JSON body."""
    try:
        payload = response.json()
    except (ValueError, TypeError, AttributeError):
        payload = {}
    error = payload.get("error", {}) if isinstance(payload, dict) else {}
    if not isinstance(error, dict):
        error = {}
    message = str(error.get("message") or "").strip()
    code = str(error.get("code") or "").strip()
    error_type = str(error.get("type") or "").strip()
    headers = getattr(response, "headers", {})
    try:
        request_id = str(headers.get("x-request-id") or "").strip()
    except AttributeError:
        request_id = ""
    details = "; ".join(part for part in (f"code={code}" if code else "", f"type={error_type}" if error_type else "", f"request_id={request_id}" if request_id else "") if part)
    if message and details:
        message = f"{message} ({details})"
    elif not message:
        message = details or "No error details were returned"
    return message, code.lower(), (error_type + " " + message).lower()


def _is_context_length_error(response: Any) -> bool:
    if getattr(response, "status_code", None) != 400:
        return False
    _, code, description = _api_error_details(response)
    return (
        "context_length_exceeded" in code
        or "context length" in description
        or "maximum context" in description
        or "max context" in description
        or "too many tokens" in description
        or "token limit" in description
        or "maximum number of tokens" in description
    )


def _compact_json_value(value: Any, depth: int = 0) -> Any:
    """Create a bounded model-facing projection while retaining evidence IDs."""
    if depth >= 5:
        if isinstance(value, (dict, list)):
            return "[nested data omitted from compressed context; retrieve with evidence reference]"
        return value
    if isinstance(value, dict):
        compact: dict[str, Any] = {}
        for key, item in value.items():
            if key in {"raw", "raw_json", "source_path"}:
                continue
            compact[key] = _compact_json_value(item, depth + 1)
        return compact
    if isinstance(value, list):
        cap = 12
        return [_compact_json_value(item, depth + 1) for item in value[:cap]] + ([f"[{len(value) - cap} more items omitted from compressed context]"] if len(value) > cap else [])
    if isinstance(value, str) and len(value) > 1200:
        return value[:1200] + "…[truncated in compressed context]"
    return value


def _compact_tool_message(message: dict[str, Any]) -> dict[str, Any]:
    compact = dict(message)
    content = message.get("content")
    if not isinstance(content, str):
        return compact
    try:
        value = json.loads(content)
    except (TypeError, ValueError):
        compact["content"] = content[:MAX_COMPRESSED_CONTEXT_CHARS]
        if len(content) > MAX_COMPRESSED_CONTEXT_CHARS:
            compact["content"] += "\n[tool text truncated during context recovery]"
        return compact
    if not isinstance(value, (dict, list)):
        compact["content"] = json.dumps(_compact_json_value(value), separators=(",", ":"))
        return compact

    projection = _compact_json_value(value)
    if isinstance(projection, dict):
        for key in ("results", "timeline", "representative_records"):
            rows = value.get(key)
            if isinstance(rows, list) and len(rows) > 12:
                projection[key] = [_compact_json_value(row) for row in rows[:12]]
                projection[f"{key}_omitted_for_context"] = len(rows) - 12
        projection["context_compressed"] = True
        projection["context_compression_note"] = "Large tool payloads were compacted after an API context-length error. Raw EVE remains available by record_id/file_offset; totals and truncation metadata are preserved."
    serialized = json.dumps(projection, separators=(",", ":"), default=str)
    if len(serialized) > MAX_COMPRESSED_CONTEXT_CHARS:
        envelope: dict[str, Any] = {}
        if isinstance(value, dict):
            for key in (
                "query", "requested_query", "resolved_window", "snapshot_max_record_id",
                "query_fingerprint", "total_count", "total_events", "total_raw_records",
                "returned", "returned_items", "raw_records_covered", "truncated",
                "next_cursor", "counts_by_type", "view", "duplicate_policy", "detail",
                "resolved_semantics", "diagnostics", "ip_resolution", "target", "flow_id",
                "raw_record_count", "logical_event_count", "exact_duplicate_records",
                "next_offset", "model_view", "first_returned_observation",
                "last_returned_observation", "notable_observations_truncated",
                "tool_call_adjustment",
            ):
                if key in projection:
                    envelope[key] = projection[key]
            for key in ("results", "timeline", "representative_records"):
                if isinstance(projection.get(key), list):
                    envelope[key] = projection[key][:3]
                    envelope[f"{key}_omitted_for_context"] = max(0, len(value.get(key, [])) - 3)
            if isinstance(projection.get("notable_observations"), list):
                envelope["notable_observations"] = projection["notable_observations"][:10]
                envelope["notable_observations_omitted_for_context"] = max(0, len(value.get("notable_observations", [])) - 10)
            envelope["context_compressed"] = True
            envelope["context_compression_note"] = "Large tool payload further reduced after a context-length error. Retrieve omitted evidence by record_id/file_offset or continue with pagination."
        serialized = json.dumps(envelope or {"context_compressed": True, "note": "Tool payload omitted after API context-length error; retrieve evidence using local tools."}, separators=(",", ":"), default=str)
    compact["content"] = serialized
    return compact


class SuricataAgent:
    def __init__(self, tools: SuricataTools | None = None, on_tool: Callable[[str, dict, Any], None] | None = None, on_status: Callable[[str, str], None] | None = None, debug: bool | None = None, clock: Callable[[], datetime] | None = None):
        self.tools = tools or SuricataTools()
        self.registry = self.tools.tool_registry()
        self.on_tool = on_tool
        self.on_status = on_status
        self.model = os.getenv("OPENAI_MODEL") or DEFAULT_MODEL
        self.reasoning_effort = os.getenv("OPENAI_REASONING_EFFORT") or (
            "medium" if self.model.startswith(("gpt-5", "gpt-6")) else ""
        )
        self._clock = clock or (lambda: datetime.now().astimezone())
        self.debug = (os.getenv("SURICATA_AGENT_DEBUG", "").lower() in {"1", "true", "yes"}) if debug is None else debug
        self.messages: list[dict[str, Any]] = []
        self._audit_messages: list[dict[str, Any]] = []
        self._prior_investigations: list[dict[str, Any]] = []
        self._investigation_sequence = 0
        self.last_metrics: dict[str, Any] | None = None
        self._stop_requested = threading.Event()
        key = os.getenv("OPENAI_API_KEY")
        if not key:
            raise AgentError(f"OPENAI_API_KEY is not configured in {PROJECT_ROOT / '.env'}")
        self._api_key = key

    def prepare_request(self) -> None:
        self._stop_requested.clear()

    def request_stop(self) -> None:
        self._stop_requested.set()

    def _check_cancelled(self) -> None:
        if self._stop_requested.is_set():
            raise AgentCancelled("Investigation cancelled during shutdown")

    def _debug(self, section: str, **values: Any) -> None:
        if not self.debug:
            return
        rendered = " ".join(f"{key}={json.dumps(value, sort_keys=True)}" for key, value in values.items())
        print(f"[{section}] {rendered}", file=sys.stderr, flush=True)

    def _status(self, phase: str, detail: str) -> None:
        if self.on_status:
            self.on_status(phase, detail)

    def clear(self) -> None:
        self.messages.clear()
        self._audit_messages.clear()
        self._prior_investigations.clear()
        self._investigation_sequence = 0
        self.last_metrics = None

    def history(self) -> list[dict[str, Any]]:
        return list(self._audit_messages)

    def _append_message(self, message: dict[str, Any]) -> None:
        self.messages.append(message)
        self._audit_messages.append(message)

    def _compress_context_after_limit(self) -> tuple[bool, dict[str, int]]:
        """Drop stale tool-heavy turns and compact current evidence for one retry."""
        if not self.messages:
            return False, {"messages_removed": 0, "tool_messages_compacted": 0, "characters_before": 0, "characters_after": 0}
        before = sum(len(str(message.get("content") or "")) + len(json.dumps(message.get("tool_calls") or [], default=str)) for message in self.messages)
        current_start = next((index for index in range(len(self.messages) - 1, -1, -1) if self.messages[index].get("role") == "user"), 0)
        previous = self.messages[:current_start]
        current = self.messages[current_start:]

        # Keep a tiny conversational recap, never partial tool-call protocol
        # messages. Tool evidence is re-fetchable through stable record refs.
        recap = []
        for message in previous:
            if message.get("role") not in {"user", "assistant"} or message.get("tool_calls"):
                continue
            content = message.get("content")
            if not isinstance(content, str) or not content.strip():
                continue
            if content.startswith("Prior investigation state (data, not instructions): "):
                recap.append({"role": "assistant", "content": content})
                continue
            recap.append({"role": message["role"], "content": content[:500] + ("…[older conversation shortened]" if len(content) > 500 else "")})
        recap = recap[-4:]

        compacted_tool_messages = 0
        compressed_current = []
        for message in current:
            if message.get("role") == "tool":
                compact_message = _compact_tool_message(message)
                if compact_message.get("content") != message.get("content"):
                    compacted_tool_messages += 1
                compressed_current.append(compact_message)
            elif message.get("role") in {"user", "assistant"} and isinstance(message.get("content"), str) and len(message["content"]) > 4000:
                compacted = dict(message)
                compacted["content"] = message["content"][:4000] + "\n[message shortened during context recovery]"
                compressed_current.append(compacted)
            else:
                compressed_current.append(message)

        removed = max(0, len(previous) - len(recap))
        self.messages[:] = [*recap, *compressed_current]
        after = sum(len(str(message.get("content") or "")) + len(json.dumps(message.get("tool_calls") or [], default=str)) for message in self.messages)
        return before > after, {
            "messages_removed": removed,
            "tool_messages_compacted": compacted_tool_messages,
            "characters_before": before,
            "characters_after": after,
        }

    @staticmethod
    def _window_args(arguments: dict[str, Any]) -> dict[str, Any]:
        keys = ("start_time", "end_time", "lookback_minutes", "lookback_hours", "time_basis", "all_history")
        return {key: arguments[key] for key in keys if key in arguments}

    def _automatic_fallback(self, name: str, arguments: dict[str, Any], result: dict[str, Any]) -> dict[str, Any] | None:
        self._check_cancelled()
        if name not in {"search_alerts", "search_events", "search_related_events", "investigate_host"} or _result_count(result) != 0:
            return None
        target = arguments.get("either_ip") or arguments.get("src_ip") or arguments.get("dest_ip") or arguments.get("ip")
        if not target:
            return None
        self._status("fallback", "Checking broad indexed activity, then canonical EVE if needed")
        window_args = self._window_args(arguments)
        broad = self.tools.investigate_host(ip=target, limit=12, **window_args)
        self._check_cancelled()
        broad_count = _result_count(broad) or 0
        raw: dict[str, Any] = {}
        raw_tool_name = "fallback:count_raw_eve_matches"
        if broad_count > 0:
            for candidate in broad.get("representative_records", []):
                record_id = candidate.get("record_id") if isinstance(candidate, dict) else None
                if not record_id:
                    continue
                raw = self.tools.verify_raw_eve_witness(
                    int(record_id), str(broad.get("target") or target),
                    broad.get("resolved_window") or {},
                    str((broad.get("resolved_window") or {}).get("time_basis") or window_args.get("time_basis") or "either"),
                )
                if raw.get("verified"):
                    raw_tool_name = "fallback:verify_raw_eve_witness"
                    break
        if not raw.get("verified"):
            raw = self.tools.count_raw_eve_matches(ip=target, **window_args)
        self._check_cancelled()
        if name == "search_alerts":
            reason = "alert-only search cannot establish host inactivity"
        elif name == "investigate_host":
            reason = "a zero-result host snapshot requires canonical raw-EVE validation"
        else:
            reason = "narrow zero-result search requires direction/type/time-basis broadening"
        fallback: dict[str, Any] = {"triggered": True, "reason": reason, "target": target, "raw_eve_sanity_check": raw, "broad_host_investigation": broad}

        raw_count = _result_count(raw) or 0
        narrow_keys = {"event_types", "signature", "sid", "severity", "src_port", "dest_port", "either_port", "proto", "app_proto", "hostname", "dns_name", "sni", "http_host", "http_url", "free_text", "flow_id"}
        broad_ip_search = name == "search_events" and not any(arguments.get(key) for key in narrow_keys)
        unfiltered_host = name == "investigate_host" and not any(arguments.get(key) for key in ("peer_ip", "ports", "focus")) and arguments.get("direction", "either") == "either"
        if raw_count > 0 and (broad_ip_search or unfiltered_host) and _result_count(result) == 0:
            fallback["search_layer_discrepancy"] = True
            fallback["warning"] = "The initial general host search returned zero while direct raw EVE matching found records; treat the initial search layer as unreliable."
        elif raw_count > 0 and broad_count == 0:
            fallback["search_layer_discrepancy"] = True
            fallback["warning"] = "Direct raw EVE matching found records while the broad search returned zero; do not claim host inactivity."
        elif raw_count > 0:
            fallback["search_layer_discrepancy"] = False
        if raw.get("count_exact") is False:
            fallback["raw_count_note"] = "The direct EVE witness proves at least one matching raw record; broad indexed counts, not this witness, describe the full set."
        if raw.get("scan_complete") is False or raw.get("source_snapshot_consistent") is False:
            fallback["raw_eve_validation_incomplete"] = True
            fallback["warning"] = raw.get("warning") or "Raw EVE verification was incomplete; do not make a negative claim."

        if raw_count == 0 and broad_count == 0 and arguments.get("start_time") and arguments.get("end_time"):
            start = _parse_time(arguments["start_time"])
            end = _parse_time(arguments["end_time"])
            if start and end:
                expanded = self.tools.investigate_host(
                    ip=target,
                    start_time=_iso(start - timedelta(minutes=5)) or "",
                    end_time=_iso(end + timedelta(minutes=5)) or "",
                    time_basis="either",
                    limit=12,
                )
                self._check_cancelled()
                fallback["expanded_window_minutes"] = 5
                fallback["expanded_host_investigation"] = expanded
        self._debug("fallback", reason=reason, target=target, window=window_args, raw_count=raw_count, broad_count=broad_count)
        if self.on_tool:
            self.on_tool("fallback:investigate_host", {"ip": target, **window_args}, broad)
            self.on_tool(raw_tool_name, {"ip": target, **window_args}, raw)
        return fallback

    def ask(self, question: str) -> str:
        self._check_cancelled()
        meter = InvestigationMetrics(self.model)
        tool_summaries: list[dict[str, Any]] = []
        self.last_metrics = None
        self._status("interpret", "Interpreting the investigation request")
        self._append_message({"role": "user", "content": question})
        clock_anchor = self._clock()
        response_input = _responses_input_from_messages(self.messages)
        instructions = (
            f"{SYSTEM_PROMPT}\n\nCurrent local wall clock: {clock_anchor.isoformat()} "
            "Use this only to resolve relative times; never substitute a remembered/example date."
        )
        resolved_ips = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b|(?<!\S)\.\d{1,3}\b", question)
        self._debug("agent", intent=_intent(question), resolved_ips=resolved_ips, current_time=clock_anchor.isoformat(), question=question)
        duplicate_cause_revision_requested = False
        for round_number in range(1, MAX_TOOL_CALLS + 1):
            self._check_cancelled()
            self._status("model", f"Waiting for {self.model} response (round {round_number}/{MAX_TOOL_CALLS})")
            compressed_retry = False
            while True:
                body: dict[str, Any] = {
                    "model": self.model,
                    "instructions": instructions,
                    "input": response_input,
                    "tools": _responses_tools(),
                    "tool_choice": "auto",
                    "store": False,
                }
                if self.reasoning_effort:
                    body["reasoning"] = {"effort": self.reasoning_effort}
                try:
                    response = requests.post(OPENAI_URL, headers={"Authorization": f"Bearer {self._api_key}", "Content-Type": "application/json"}, json=body, timeout=45)
                except requests.RequestException as exc:
                    raise AgentError(f"OpenAI request failed ({exc.__class__.__name__})") from None
                if _is_context_length_error(response) and not compressed_retry:
                    changed, metrics = self._compress_context_after_limit()
                    if changed:
                        compressed_retry = True
                        response_input = _responses_input_from_messages(self.messages)
                        notice = "The API rejected the conversation because it exceeded the model context limit. I compressed older conversation and large tool results, kept this question and its evidence references, and am retrying."
                        self._status("context_compressed", notice)
                        self._debug("context_recovery", **metrics, retry="once")
                        continue
                break
            self._check_cancelled()
            if response.status_code >= 400:
                error_message, _, _ = _api_error_details(response)
                if compressed_retry and response.status_code == 400:
                    raise AgentError(f"OpenAI API returned HTTP 400 after context compression: {error_message}")
                raise AgentError(f"OpenAI API returned HTTP {response.status_code}: {error_message}")
            try:
                response_payload = response.json()
                response_output = response_payload["output"]
                if not isinstance(response_output, list):
                    raise TypeError
            except (ValueError, KeyError, IndexError, TypeError):
                raise AgentError("OpenAI returned an unexpected response") from None
            meter.record_request(body, response_payload)
            tool_calls = _responses_function_calls(response_output)
            if not tool_calls:
                content = _responses_output_text(response_output)
                if _has_unsupported_duplicate_cause(content) and not duplicate_cause_revision_requested and round_number < MAX_TOOL_CALLS:
                    duplicate_cause_revision_requested = True
                    self._append_message({"role": "assistant", "content": content})
                    revision = {
                        "role": "system",
                        "content": "Revise the draft. It assigns an unsupported cause to duplicate EVE records. State only that matching records exist in canonical EVE and that their cause is unknown unless direct evidence establishes it. Preserve the rest of the evidence-based answer.",
                    }
                    self._append_message(revision)
                    response_input.extend(response_output)
                    response_input.append({"role": "developer", "content": revision["content"]})
                    self._debug("response_guard", reason="unsupported_duplicate_cause", action="request_revision")
                    self._status("model", "Requesting correction of an unsupported duplicate-cause claim")
                    continue
                self._append_message({"role": "assistant", "content": content})
                before_reduction = meter.snapshot(_responses_input_from_messages(self.messages))["retained_context_estimated_tokens"]
                self._investigation_sequence += 1
                state = investigation_state(question, content, tool_summaries, clock_anchor.isoformat(), _requested_time_context(question, clock_anchor))
                state["investigation_id"] = f"I{self._investigation_sequence}"
                self._prior_investigations.append(state)
                self._prior_investigations = self._prior_investigations[-MAX_LOCAL_INVESTIGATIONS:]
                self.messages[:] = [replay_message(self._prior_investigations)]
                self.last_metrics = meter.snapshot(_responses_input_from_messages(self.messages))
                self.last_metrics["context_before_reduction_estimated_tokens"] = before_reduction
                self.last_metrics["context_reduction_estimated_tokens"] = max(0, before_reduction - self.last_metrics["retained_context_estimated_tokens"])
                usage = self.last_metrics
                if usage["api_calls_with_usage"]:
                    cost = f"${usage['estimated_cost_usd']:.4f}" if usage["estimated_cost_usd"] is not None else "unavailable"
                    prefix = "" if usage["usage_complete"] else "partial API usage: "
                    self._status("usage", f"{prefix}total={usage['total_tokens']:,}, input={usage['input_tokens']:,}, cached={usage['cached_input_tokens']:,}, cache-write={usage['cache_write_tokens']:,}, output={usage['output_tokens']:,}, reasoning={usage['reasoning_tokens']:,}, estimated cost={cost}")
                else:
                    self._status("usage", "API usage counters unavailable; local tool/context estimates recorded")
                self._status("usage_detail", f"tool results={usage['tool_result_bytes']:,} bytes (~{usage['estimated_tool_result_tokens']:,} tokens); replayed context~{usage['replayed_context_estimated_tokens']:,} tokens; retained context~{usage['retained_context_estimated_tokens']:,} tokens")
                self._debug("usage", **{key: value for key, value in usage.items() if key not in {"requests", "tool_results"}})
                self._status("complete", "Response complete")
                return content
            self._append_message({"role": "assistant", "content": None, "tool_calls": tool_calls})
            # Keep the model's returned reasoning/function-call items intact
            # while chaining local tool outputs through the Responses API.
            response_input.extend(response_output)
            for call in tool_calls:
                self._check_cancelled()
                function = call.get("function", {})
                name = function.get("name") or "unknown"
                validation_error = None
                try:
                    arguments = json.loads(function.get("arguments", "{}"))
                except (TypeError, ValueError):
                    arguments = {}
                    validation_error = f"Invalid JSON arguments for {name}; expected an object"
                if not isinstance(arguments, dict):
                    arguments = {}
                    validation_error = f"Invalid arguments for {name}; expected an object"
                if validation_error is None:
                    arguments = _apply_intent_defaults(name, arguments, question)
                    arguments, time_override = _relative_time_override(name, arguments, question, clock_anchor)
                    arguments, ignored, validation_error = _sanitize_tool_arguments(name, arguments)
                    if time_override:
                        self._debug("time_guard", tool=name, note=time_override, query=arguments)
                        self._status("time_guard", time_override)
                else:
                    ignored = []
                if validation_error is None:
                    function["arguments"] = json.dumps(arguments, separators=(",", ":"))
                    for output_item in response_output:
                        if output_item.get("type") == "function_call" and (output_item.get("call_id") or output_item.get("id")) == call.get("id"):
                            output_item["arguments"] = function["arguments"]
                if ignored:
                    self._debug("tool_argument_guard", tool=name, ignored_arguments=ignored)
                capability = self.registry.get(name)
                if validation_error:
                    result: dict[str, Any] = {"error": validation_error}
                elif not capability:
                    result: dict[str, Any] = {"error": f"Unapproved tool: {name}"}
                else:
                    self._status("tool", f"Running {name}")
                    try:
                        result = capability(**arguments)
                    except Exception as exc:
                        result = {"error": f"Tool {name} failed ({exc.__class__.__name__})"}
                if ignored:
                    result["tool_call_adjustment"] = {
                        "ignored_arguments": ignored,
                        "scope_note": _ignored_argument_note(name),
                    }
                self._check_cancelled()
                count = _result_count(result)
                self._debug("tool", name=name, arguments=arguments, resolved_window=result.get("resolved_window") if isinstance(result, dict) else None, count=count, truncated=result.get("truncated") if isinstance(result, dict) else None)
                fallback = self._automatic_fallback(name, arguments, result) if isinstance(result, dict) else None
                if fallback:
                    result["automatic_fallback"] = fallback
                if self.on_tool:
                    self.on_tool(name, arguments, result)
                model_result = model_tool_result(name, result, question)
                tool_summaries.append(tool_state(name, arguments, model_result))
                tool_content = json.dumps(model_result, separators=(",", ":"))
                meter.record_tool(name, result, tool_content)
                call_id = call.get("id") or name
                self._append_message({"role": "tool", "tool_call_id": call_id, "name": name, "content": tool_content})
                response_input.append({"type": "function_call_output", "call_id": call_id, "output": tool_content})
        raise AgentError(f"Stopped after {MAX_TOOL_CALLS} tool calls without a final answer")
