"""Evidence-preserving, bounded views of local tool results for the model."""

from __future__ import annotations

import re
from typing import Any


DEFAULT_FLOW_PAGE = 20
EXPLICIT_FULL_FLOW_PAGE = 100
_FULL_CHAIN_RE = re.compile(r"\b(?:complete|entire|full|all|every)\b.{0,45}\b(?:flow|chain|record|event|transaction)", re.I)
_RAW_RE = re.compile(r"\b(?:raw|unaltered|every (?:eve )?record|every (?:eve )?line)\b", re.I)
_FLOW_ITEM_FIELDS = (
    "timestamp", "event_timestamp", "event_type", "event_id", "relation", "flow_id",
    "record_id", "source_generation", "file_offset", "src_ip", "src_port",
    "dest_ip", "dest_port", "proto", "app_proto", "flow_start", "flow_end",
    "dns_query", "dns_queries", "dns_answers", "tls_sni", "http_host",
    "http_url", "connection_state", "service", "signature", "signature_id",
    "severity", "in_iface", "community_id",
)
_REFERENCE_FIELDS = ("record_id", "source_generation", "file_offset", "timestamp")


def _compact_flow_item(item: dict[str, Any]) -> dict[str, Any]:
    compact = {key: item[key] for key in _FLOW_ITEM_FIELDS if key in item}
    refs = item.get("evidence_refs")
    if isinstance(refs, list):
        compact["evidence_refs"] = [
            {key: ref[key] for key in _REFERENCE_FIELDS if key in ref}
            for ref in refs if isinstance(ref, dict)
        ]
    group = item.get("exact_duplicate_group")
    if isinstance(group, dict):
        compact["exact_duplicate_group"] = {
            key: group[key] for key in ("fingerprint", "raw_record_count", "extra_duplicate_records", "cause") if key in group
        }
    dns = item.get("dns")
    if isinstance(dns, dict):
        compact["dns_type"] = dns.get("type")
        questions = dns.get("queries")
        if isinstance(questions, list):
            compact["dns_questions"] = [
                {key: query[key] for key in ("rrname", "rrtype") if key in query}
                for query in questions if isinstance(query, dict)
            ]
    for section, keys in (
        ("alert", ("signature", "signature_id", "severity", "category", "action")),
        ("flow", ("pkts_toserver", "pkts_toclient", "bytes_toserver", "bytes_toclient", "state", "reason", "alerted", "tx_cnt")),
        ("http", ("http_method", "hostname", "url", "status")),
        ("tls", ("sni", "subject", "issuerdn")),
        ("quic", ("sni", "server_name", "version")),
        ("tcp", ("tcp_flags_ts", "tcp_flags_tc", "syn", "synack", "rst", "fin")),
        ("anomaly", ("type", "event", "layer")),
        ("fileinfo", ("filename", "size", "state", "md5", "sha1", "sha256", "stored")),
    ):
        value = item.get(section)
        if isinstance(value, dict):
            selected = {key: value[key] for key in keys if key in value}
            if selected:
                compact[section] = selected
    return {key: value for key, value in compact.items() if value is not None}


def model_tool_result(name: str, result: Any, question: str) -> Any:
    """Return a model-only projection; never mutate the canonical tool result."""
    if not isinstance(result, dict):
        return result
    if name in {"investigate_host", "investigate_pair", "investigate_service"}:
        projected = dict(result)
        for field in ("representative_records", "alerts", "results"):
            records = result.get(field)
            if isinstance(records, list):
                projected[field] = [_compact_flow_item(item) for item in records]
        fallback = result.get("automatic_fallback")
        if isinstance(fallback, dict):
            compact_fallback = dict(fallback)
            for field in ("broad_host_investigation", "expanded_host_investigation"):
                if isinstance(fallback.get(field), dict):
                    compact_fallback[field] = model_tool_result("investigate_host", fallback[field], question)
            projected["automatic_fallback"] = compact_fallback
        projected["model_view"] = {
            "detail": "compact representative records; full aggregate counts retained",
            "raw_evidence": "Use get_event(record_id=...) or search_events for original records and further pages.",
        }
        return projected
    if name not in {"correlate_flow", "get_flow"}:
        fallback = result.get("automatic_fallback")
        if not isinstance(fallback, dict):
            return result
        projected = dict(result)
        compact_fallback = dict(fallback)
        for field in ("broad_host_investigation", "expanded_host_investigation"):
            if isinstance(fallback.get(field), dict):
                compact_fallback[field] = model_tool_result("investigate_host", fallback[field], question)
        projected["automatic_fallback"] = compact_fallback
        return projected
    timeline = result.get("timeline")
    if not isinstance(timeline, list):
        return result
    projected = dict(result)
    # The local tool retains both compatibility aliases; the model needs one.
    projected.pop("results", None)
    explicit_full = bool(_FULL_CHAIN_RE.search(question))
    explicit_raw = bool(_RAW_RE.search(question))
    page_size = EXPLICIT_FULL_FLOW_PAGE if explicit_full or explicit_raw else DEFAULT_FLOW_PAGE
    page = timeline[:page_size]
    projected["timeline"] = page if explicit_raw else [_compact_flow_item(item) for item in page]
    projected["returned"] = len(page)
    offset = int(result.get("offset") or 0)
    if len(timeline) > len(page):
        projected["truncated"] = True
        projected["next_offset"] = offset + len(page)
        projected["next_cursor"] = str(offset + len(page))
    if timeline:
        projected["first_returned_observation"] = _compact_flow_item(timeline[0])
        projected["last_returned_observation"] = _compact_flow_item(timeline[-1])
    notable = [item for item in timeline if item.get("relation") in {"flow_summary", "ids_alert"}
               or item.get("event_type") in {"alert", "anomaly", "fileinfo", "tls", "http", "quic"}]
    priority = {"alert": 0, "anomaly": 0, "fileinfo": 1, "flow": 2, "tls": 3, "http": 3, "quic": 3}
    notable.sort(key=lambda item: priority.get(str(item.get("event_type")), 4))
    if notable:
        projected["notable_observations"] = [_compact_flow_item(item) for item in notable[:10]]
        projected["notable_observations_truncated"] = len(notable) > 10
    projected["model_view"] = {
        "scope": "first page plus first/last and notable observations from the locally returned chain",
        "page_size": len(page),
        "locally_returned_items": len(timeline),
        "notable_order": "priority for alerts/anomalies/files; each record keeps its own timestamp",
        "raw_evidence": "All raw EVE records remain in the local index; use get_event(record_id=...) or correlate_flow(flow_id=...,offset=...) to inspect them.",
    }
    return projected
