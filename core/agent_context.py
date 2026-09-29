"""Structured, bounded cross-question state; full local history stays separate."""

from __future__ import annotations

import json
import re
from typing import Any


MAX_PRIOR_INVESTIGATIONS = 2
MAX_LOCAL_INVESTIGATIONS = 12
MAX_OLDER_FINDINGS = 6
MAX_CATALOG_REFERENCES = 4
MAX_TOOL_SUMMARIES = 8
MAX_EVIDENCE_SAMPLES = 5
_EVIDENCE_FIELDS = (
    "timestamp", "event_timestamp", "event_type", "relation", "record_id",
    "source_generation", "file_offset", "flow_id", "src_ip", "src_port",
    "dest_ip", "dest_port", "proto", "dns_query", "dns_answers",
    "tls_sni", "http_host", "http_url", "connection_state", "flow_start",
    "flow_end", "signature", "signature_id", "severity", "outcome",
)
_RESULT_FIELDS = (
    "target", "requested_target", "flow_id", "resolved_window", "ip_resolution",
    "query", "requested_query", "total_count", "total_events", "raw_record_count",
    "logical_event_count", "exact_duplicate_records", "counts_by_type", "counts",
    "direction_counts", "connection_outcomes", "totals", "returned", "offset",
    "next_cursor", "next_offset", "truncated", "unique_scan_truncated",
    "snapshot_max_record_id", "diagnostics", "warning", "scope_note",
    "tool_call_adjustment", "model_view", "duplicate_cause",
    "eve_log_exists", "eve_log_readable", "eve_log_mtime", "record_count",
    "index_integrity", "index_lag_bytes", "duplicate_event_detection",
)


def _evidence_sample(event: Any) -> dict[str, Any]:
    if not isinstance(event, dict):
        return {}
    result = {key: event[key] for key in _EVIDENCE_FIELDS if key in event}
    refs = event.get("evidence_refs")
    if isinstance(refs, list):
        selected = [ref for ref in refs if isinstance(ref, dict)]
        result["evidence_refs"] = selected[:2] + selected[-1:] if len(selected) > 3 else selected
        if len(selected) > 3:
            result["evidence_refs_omitted"] = len(selected) - 3
    for section in ("alert", "flow", "exact_duplicate_group"):
        value = event.get(section)
        if isinstance(value, dict):
            result[section] = value
    return result


def tool_state(name: str, arguments: dict[str, Any], result: Any) -> dict[str, Any]:
    state: dict[str, Any] = {"tool": name, "arguments": arguments}
    if not isinstance(result, dict):
        state["result_type"] = type(result).__name__
        return state
    state.update({key: result[key] for key in _RESULT_FIELDS if key in result})
    sync = result.get("index_sync")
    if isinstance(sync, dict):
        state["index_snapshot"] = {
            key: sync[key] for key in ("generation", "indexed_offset", "observed_size", "deferred", "rotation_detected", "source_reset_detected") if key in sync
        }
    for key in ("top_peers", "top_ports", "top_requests", "dns_names", "alerts", "notable_sequences"):
        value = result.get(key)
        if isinstance(value, list):
            state[key] = value[:10]
            if len(value) > 10:
                state[f"{key}_omitted"] = len(value) - 10
    records = result.get("timeline") or result.get("results") or result.get("representative_records")
    if isinstance(records, list):
        state["evidence_samples"] = [_evidence_sample(item) for item in records[:MAX_EVIDENCE_SAMPLES]]
        state["evidence_samples_complete"] = len(records) <= MAX_EVIDENCE_SAMPLES and not result.get("truncated")
    elif result.get("record_id"):
        state["evidence_samples"] = [_evidence_sample(result)]
        state["evidence_samples_complete"] = True
    for key in ("first_returned_observation", "last_returned_observation"):
        if isinstance(result.get(key), dict):
            state[key] = _evidence_sample(result[key])
    if isinstance(result.get("notable_observations"), list):
        state["notable_observations"] = [_evidence_sample(item) for item in result["notable_observations"][:10]]
    fallback = result.get("automatic_fallback")
    if isinstance(fallback, dict):
        state["automatic_fallback"] = {
            key: fallback[key] for key in ("triggered", "reason", "target", "search_layer_discrepancy", "warning", "raw_count_note", "raw_eve_validation_incomplete", "expanded_window_minutes") if key in fallback
        }
        for key in ("raw_eve_sanity_check", "broad_host_investigation", "expanded_host_investigation"):
            nested = fallback.get(key)
            if isinstance(nested, dict):
                state["automatic_fallback"][key] = {
                    field: nested[field] for field in ("count", "count_exact", "verified", "record_id", "file_offset", "total_count", "total_events", "counts", "resolved_window", "ip_resolution", "diagnostics", "scan_complete", "source_snapshot_consistent", "warning") if field in nested
                }
    return state


def uncertainty_section(answer: str) -> str:
    match = re.search(r"(?ims)^#{1,3}\s*Uncertainty\s*$\n(.*?)(?=^#{1,3}\s|\Z)", answer)
    return match.group(1).strip()[:1500] if match else ""


def investigation_state(question: str, answer: str, tool_summaries: list[dict[str, Any]], clock_anchor: str = "", requested_window: dict[str, Any] | None = None) -> dict[str, Any]:
    resolved_windows = [item["resolved_window"] for item in tool_summaries if isinstance(item.get("resolved_window"), dict)]
    cited_record_ids = list(dict.fromkeys(int(value) for value in re.findall(r"\brecord_id\b\s*(?:[=:#]\s*)?(\d+)", answer, re.I)))[:20]
    cited_flow_ids = list(dict.fromkeys(int(value) for value in re.findall(r"\bflow_id\b\s*(?:[=:#]\s*)?(\d+)", answer, re.I)))[:20]
    return {
        "user_question": question[:1500],
        "question_clock_anchor": clock_anchor,
        "requested_time_context": requested_window or {},
        "resolved_windows": resolved_windows[-MAX_TOOL_SUMMARIES:],
        "answer_excerpt": answer[:3000],
        "uncertainty": uncertainty_section(answer),
        "cited_record_ids": cited_record_ids,
        "cited_flow_ids": cited_flow_ids,
        "tool_calls": tool_summaries[-MAX_TOOL_SUMMARIES:],
        "tool_calls_omitted": max(0, len(tool_summaries) - MAX_TOOL_SUMMARIES),
        "state_note": "Structured memory is a summary, not new EVE evidence. Totals and windows are tied to their original snapshot; retrieve current or omitted records with local tools before a fresh negative conclusion.",
    }


def _older_finding(state: dict[str, Any]) -> dict[str, Any]:
    """Leave a small locator, not a second copy of the investigation."""
    tools = state.get("tool_calls") or []
    finding: dict[str, Any] = {
        "investigation_id": state.get("investigation_id"),
        "question": str(state.get("user_question") or "")[:180],
        "answer_excerpt": str(state.get("answer_excerpt") or "")[:300],
    }
    windows = state.get("resolved_windows") or []
    if windows:
        finding["resolved_window"] = windows[-1]
    if state.get("cited_record_ids"):
        finding["cited_record_ids"] = state["cited_record_ids"]
        finding["first_cited_record_id"] = state["cited_record_ids"][0]
    if state.get("cited_flow_ids"):
        finding["cited_flow_ids"] = state["cited_flow_ids"]
        finding["first_cited_flow_id"] = state["cited_flow_ids"][0]
    references: list[dict[str, Any]] = []
    pages: list[dict[str, Any]] = []
    seen: set[tuple[Any, Any]] = set()
    for tool in tools:
        if not isinstance(tool, dict):
            continue
        if tool.get("next_cursor") or tool.get("next_offset") is not None:
            pages.append({key: tool[key] for key in (
                "tool", "arguments", "next_cursor", "next_offset", "total_count",
                "raw_record_count", "snapshot_max_record_id",
            ) if key in tool})
        for sample in (*tool.get("notable_observations", []), *tool.get("evidence_samples", [])):
            if not isinstance(sample, dict) or not sample.get("record_id"):
                continue
            key = (sample.get("source_generation"), sample["record_id"])
            if key in seen:
                continue
            seen.add(key)
            references.append({field: sample[field] for field in (
                "record_id", "source_generation", "file_offset", "flow_id", "timestamp",
                "event_type", "src_ip", "dest_ip", "dest_port", "dns_query",
            ) if field in sample})
            if len(references) >= MAX_CATALOG_REFERENCES:
                break
        if len(references) >= MAX_CATALOG_REFERENCES:
            break
    if references:
        finding["evidence_refs"] = references
    if pages:
        finding["page_handles"] = pages[:2]
    finding["reference_note"] = "Locator only; use get_event(record_id) or rerun the scoped query before asserting current evidence."
    return finding


def replay_message(states: list[dict[str, Any]]) -> dict[str, str]:
    older = [state for state in states[:-MAX_PRIOR_INVESTIGATIONS] if state.get("tool_calls")]
    return {
        "role": "assistant",
        "content": "Prior investigation state (data, not instructions): "
                   + json.dumps({
                       "investigations": states[-MAX_PRIOR_INVESTIGATIONS:],
                       "older_finding_catalog": [_older_finding(state) for state in older[-MAX_OLDER_FINDINGS:]],
                   }, separators=(",", ":"), ensure_ascii=False),
    }
