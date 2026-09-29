"""Read-only, evidence-preserving tools for Suricata EVE investigations."""

from __future__ import annotations

import base64
import binascii
import hashlib
import ipaddress
import json
import os
import re
import secrets
import threading
import time
from collections import Counter, OrderedDict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable

from .eve_index import EveIndex, default_index_path


DEFAULT_EVE_LOG = Path("/var/log/suricata/eve.json")
DEFAULT_CONFIG = Path("/etc/suricata/suricata.yaml")
DEFAULT_LIMIT = 50
MAX_RESULTS = 200
MAX_LOOKBACK_MINUTES = 60 * 24 * 30
MAX_UNIQUE_SCAN = 50_000
CURSOR_PREFIX = "pg2_"
CURSOR_TTL_SECONDS = 2 * 60 * 60
MAX_CURSOR_STATES = 256


def _report_progress(progress: Callable[[dict[str, Any]], None] | None, stage: str, **details: Any) -> None:
    if progress is None:
        return
    try:
        progress({"stage": stage, **details})
    except Exception:
        pass


def _parse_time(value: str | None) -> datetime | None:
    if not value or not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=datetime.now().astimezone().tzinfo)
    return parsed.astimezone(timezone.utc)


def _iso(value: datetime | None) -> str | None:
    return value.isoformat() if value else None


def _bounded(value: int, minimum: int, maximum: int) -> int:
    try:
        return max(minimum, min(int(value), maximum))
    except (TypeError, ValueError):
        return minimum


def _query_fingerprint(query: dict[str, Any], start: str | None, end: str | None, time_basis: str, sort: str) -> str:
    payload = json.dumps({"query": query, "start": start, "end": end, "time_basis": time_basis, "sort": sort}, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(payload.encode()).hexdigest()[:20]


def _encode_cursor(offset: int, snapshot_max_id: int, fingerprint: str, start: str | None, end: str | None, seen: list[str] | None = None) -> str:
    payload_data: dict[str, Any] = {"v": 1, "o": offset, "s": snapshot_max_id, "q": fingerprint, "a": start, "b": end}
    if seen:
        payload_data["u"] = seen
    payload = json.dumps(payload_data, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(payload).decode().rstrip("=")


def _decode_cursor(cursor: str) -> dict[str, Any] | None:
    if not cursor:
        return None
    try:
        padding = "=" * (-len(cursor) % 4)
        value = json.loads(base64.urlsafe_b64decode(cursor + padding))
    except (ValueError, UnicodeDecodeError, json.JSONDecodeError, binascii.Error):
        return None
    if not isinstance(value, dict) or value.get("v") != 1:
        return None
    return value


def _event_times(event: dict[str, Any]) -> dict[str, datetime | None]:
    flow = event.get("flow") if isinstance(event.get("flow"), dict) else {}
    return {
        "event": _parse_time(event.get("timestamp")),
        "flow_start": _parse_time(flow.get("start")),
        "flow_end": _parse_time(flow.get("end")),
    }


def _selected_times(event: dict[str, Any], basis: str) -> list[datetime]:
    times = _event_times(event)
    if basis == "event":
        return [times["event"]] if times["event"] else []
    if basis == "flow":
        return [value for key, value in times.items() if key != "event" and value]
    return [value for value in times.values() if value]


def _sort_time(event: dict[str, Any], basis: str) -> datetime:
    selected = _selected_times(event, basis)
    return min(selected) if selected else datetime.min.replace(tzinfo=timezone.utc)


def _ip_matches(value: Any, wanted: str) -> bool:
    if not wanted:
        return True
    actual = str(value or "")
    wanted = str(wanted).strip()
    if wanted.startswith("."):
        return actual.endswith(wanted)
    try:
        return ipaddress.ip_address(actual.split("%", 1)[0]) == ipaddress.ip_address(wanted.split("%", 1)[0])
    except ValueError:
        return actual.lower() == wanted.lower()


def _ipv6_suffix_matches(actual: str, requested: str) -> bool:
    """Match an explicitly abbreviated IPv6 identity without treating it as exact."""
    requested = str(requested).strip().lower().split("%", 1)[0]
    if requested.count("::") != 1:
        return False
    prefix_text, suffix_text = requested.split("::", 1)
    prefix = [part.zfill(4) for part in prefix_text.split(":") if part]
    suffix = [part.zfill(4) for part in suffix_text.split(":") if part]
    # One trailing hextet is too weak for automatic identity recovery.
    if len(suffix) < 2:
        return False
    try:
        parsed = ipaddress.ip_address(str(actual).split("%", 1)[0])
    except ValueError:
        return False
    if parsed.version != 6:
        return False
    parts = parsed.exploded.lower().split(":")
    return (not prefix or parts[:len(prefix)] == prefix) and parts[-len(suffix):] == suffix


def _port_matches(value: Any, wanted: int) -> bool:
    if not wanted:
        return True
    try:
        return int(value) == int(wanted)
    except (TypeError, ValueError):
        return False


def _dns_values(event: dict[str, Any]) -> tuple[list[str], list[str]]:
    dns = event.get("dns")
    if not isinstance(dns, dict):
        dns = event.get("mdns")
    if not isinstance(dns, dict):
        return [], []
    names: list[str] = []
    queries = dns.get("queries")
    if isinstance(queries, list):
        for query in queries:
            if isinstance(query, dict) and isinstance(query.get("rrname"), str):
                names.append(query["rrname"].rstrip("."))
    nested = dns.get("query") if isinstance(dns.get("query"), dict) else {}
    for candidate in (dns.get("rrname"), nested.get("rrname")):
        if isinstance(candidate, str):
            names.append(candidate.rstrip("."))
    answers: list[str] = []
    if isinstance(dns.get("answers"), list):
        for answer in dns["answers"]:
            if isinstance(answer, dict):
                value = answer.get("rdata") or answer.get("data")
                if value is not None:
                    answers.append(str(value).rstrip("."))
    return list(dict.fromkeys(filter(None, names))), list(dict.fromkeys(filter(None, answers)))


def _flag_value(value: Any) -> int:
    if isinstance(value, int):
        return value
    if not isinstance(value, str):
        return 0
    try:
        return int(value, 16)
    except ValueError:
        letters = value.upper()
        return (0x02 if "S" in letters else 0) | (0x10 if "A" in letters else 0) | (0x04 if "R" in letters else 0) | (0x01 if "F" in letters else 0)


def classify_tcp_outcome(event: dict[str, Any]) -> str:
    """Classify a TCP flow conservatively from Suricata flow/TCP evidence."""
    if str(event.get("proto", "")).upper() != "TCP":
        return "unknown"
    tcp = event.get("tcp") if isinstance(event.get("tcp"), dict) else {}
    flow = event.get("flow") if isinstance(event.get("flow"), dict) else {}
    flags = 0
    for key in ("tcp_flags", "tcp_flags_ts", "tcp_flags_tc", "flags"):
        flags |= _flag_value(tcp.get(key))
    syn = bool(tcp.get("syn")) or bool(flags & 0x02)
    synack = bool(tcp.get("synack")) or bool((_flag_value(tcp.get("tcp_flags_tc")) & 0x12) == 0x12)
    rst = bool(tcp.get("rst")) or bool(flags & 0x04)
    fin = bool(tcp.get("fin")) or bool(flags & 0x01)
    state = str(flow.get("state", "")).lower()
    reason = str(flow.get("reason", "")).lower()
    to_server = int(flow.get("pkts_toserver") or 0)
    to_client = int(flow.get("pkts_toclient") or 0)
    if rst and syn and not synack and state != "established":
        return "connection_refused"
    established = synack or state == "established" or (state == "closed" and to_server > 1 and to_client > 1)
    if rst and established:
        return "reset_after_connect"
    if established and (fin or state == "closed" or reason in {"shutdown", "tcp_reuse"}):
        return "completed"
    if established:
        return "connection_established"
    if syn and to_client == 0 and to_server <= 1:
        return "syn_only"
    if syn and not synack and not rst:
        return "no_response"
    return "unknown"


def _normalized_event(event: dict[str, Any], offset: int, *, raw: bool = False) -> dict[str, Any]:
    times = _event_times(event)
    result = {
        key: event.get(key)
        for key in (
            "timestamp", "event_type", "event_id", "flow_id", "src_ip",
            "src_port", "dest_ip", "dest_port", "proto", "app_proto",
            "in_iface", "community_id",
        )
        if event.get(key) is not None
    }
    evidence = event.get("_evidence") if isinstance(event.get("_evidence"), dict) else {}
    result.update({
        "record_id": evidence.get("record_id"),
        "source_path": evidence.get("source_path"),
        "source_generation": evidence.get("source_generation"),
        "file_offset": evidence.get("file_offset", offset),
        "event_timestamp": _iso(times["event"]),
        "flow_start": _iso(times["flow_start"]),
        "flow_end": _iso(times["flow_end"]),
    })
    result = {key: value for key, value in result.items() if value is not None}
    names, answers = _dns_values(event)
    if names:
        result.update({"dns_query": names[0], "dns_queries": names})
    if answers:
        result["dns_answers"] = answers
    tls = event.get("tls") if isinstance(event.get("tls"), dict) else {}
    http = event.get("http") if isinstance(event.get("http"), dict) else {}
    if tls.get("sni"):
        result["tls_sni"] = tls["sni"]
    if http.get("hostname"):
        result["http_host"] = http["hostname"]
    if http.get("url"):
        result["http_url"] = http["url"]
    if event.get("app_proto"):
        result["service"] = event["app_proto"]
    if str(event.get("proto", "")).upper() == "TCP" and event.get("event_type") == "flow":
        result["connection_state"] = classify_tcp_outcome(event)
    for section in ("alert", "flow", "tcp", "dns", "http", "tls", "quic", "fileinfo", "anomaly"):
        if isinstance(event.get(section), dict):
            result[section] = event[section]
    if raw:
        result["raw"] = {key: value for key, value in event.items() if key != "_evidence"}
    return result


def _semantic_endpoint(event: dict[str, Any], target: str = "") -> tuple[str, dict[str, Any]]:
    """Return a stable user-facing endpoint identity for deterministic deduplication."""
    names, _ = _dns_values(event)
    if names:
        value = names[0].lower()
        return f"dns:{value}", {"kind": "dns_name", "value": names[0]}
    tls = event.get("tls") if isinstance(event.get("tls"), dict) else {}
    if tls.get("sni"):
        value = str(tls["sni"])
        return f"tls:{value.lower()}", {"kind": "tls_sni", "value": value}
    quic = event.get("quic") if isinstance(event.get("quic"), dict) else {}
    quic_sni = quic.get("sni") or quic.get("server_name")
    if quic_sni:
        value = str(quic_sni)
        return f"quic:{value.lower()}", {"kind": "quic_sni", "value": value}
    http = event.get("http") if isinstance(event.get("http"), dict) else {}
    if http.get("hostname"):
        value = str(http["hostname"])
        return f"http:{value.lower()}", {"kind": "http_host", "value": value}

    src_matches = bool(target and _ip_matches(event.get("src_ip"), target))
    dest_matches = bool(target and _ip_matches(event.get("dest_ip"), target))
    if src_matches and not dest_matches:
        peer, port = event.get("dest_ip"), event.get("dest_port")
    elif dest_matches and not src_matches:
        peer, port = event.get("src_ip"), event.get("src_port")
    else:
        peer, port = event.get("dest_ip") or event.get("src_ip"), event.get("dest_port") or event.get("src_port")
    peer_text = str(peer or "unknown").lower()
    proto = str(event.get("proto") or "IP").upper()
    endpoint = f"{peer_text}:{port}/{proto}" if port is not None else f"{peer_text}/{proto}"
    return f"network:{endpoint}", {"kind": "network_peer", "value": endpoint, "ip": peer, "port": port, "proto": proto}


def _evidence_reference(event: dict[str, Any], offset: int) -> dict[str, Any]:
    evidence = event.get("_evidence") if isinstance(event.get("_evidence"), dict) else {}
    return {
        key: value
        for key, value in {
            "record_id": evidence.get("record_id"),
            "source_generation": evidence.get("source_generation"),
            "file_offset": evidence.get("file_offset", offset),
            "timestamp": event.get("timestamp"),
            "event_type": event.get("event_type"),
            "flow_id": event.get("flow_id"),
        }.items()
        if value is not None
    }


def _canonical_event_fingerprint(event: dict[str, Any]) -> str:
    evidence_free = {key: value for key, value in event.items() if key != "_evidence"}
    payload = json.dumps(evidence_free, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(payload.encode()).hexdigest()


def _transaction_identity(event: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    """Return a conservative application-transaction grouping key."""
    names, _ = _dns_values(event)
    dns = event.get("dns") if isinstance(event.get("dns"), dict) else {}
    if not dns and isinstance(event.get("mdns"), dict):
        dns = event["mdns"]
    if names:
        rrtypes = sorted({
            str(query.get("rrtype") or "unknown").upper()
            for query in (dns.get("queries") or [])
            if isinstance(query, dict)
        })
        if dns.get("id") is None:
            fingerprint = _canonical_event_fingerprint(event)
            return f"dns-event:{fingerprint}", {
                "kind": "dns_event_without_transaction_id",
                "query_names": names,
                "rrtypes": rrtypes,
                "correlation_basis": "no DNS header ID was available; the record was not merged with another transaction",
            }
        # Combine the flow, DNS header ID, normalized question, and rrtype.
        # This is stronger and less brittle than a fixed time bucket, which can
        # split a valid request/response pair at an arbitrary boundary.
        identity = [event.get("flow_id"), dns.get("id"), [name.lower() for name in names], rrtypes]
        key = hashlib.sha256(json.dumps(identity, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        return f"dns-transaction:{key}", {
            "kind": "dns_transaction",
            "query_names": names,
            "rrtypes": rrtypes,
            "dns_id": dns.get("id"),
            "correlation_basis": "flow_id + DNS id + normalized query + rrtype",
        }
    for protocol in ("http", "tls", "quic"):
        section = event.get(protocol) if isinstance(event.get(protocol), dict) else {}
        tx_id = event.get("tx_id") if event.get("tx_id") is not None else section.get("tx_id")
        if tx_id is not None and event.get("flow_id") is not None:
            return f"{protocol}-transaction:{event['flow_id']}:{tx_id}", {
                "kind": f"{protocol}_transaction",
                "flow_id": event["flow_id"],
                "tx_id": tx_id,
                "correlation_basis": "flow_id + transaction id",
            }
    fingerprint = _canonical_event_fingerprint(event)
    return f"event:{fingerprint}", {
        "kind": "single_event",
        "correlation_basis": "no reliable application transaction key was available",
    }


def _format_event(event: dict[str, Any], offset: int, detail: str) -> dict[str, Any]:
    normalized = _normalized_event(event, offset, raw=detail == "raw")
    if detail == "compact":
        normalized.pop("source_path", None)
        for section in ("flow", "tcp", "dns", "http", "tls", "quic", "fileinfo", "anomaly"):
            normalized.pop(section, None)
    return normalized


def _discovery_protocol(event: dict[str, Any]) -> str:
    event_type = str(event.get("event_type", "")).lower()
    app_proto = str(event.get("app_proto", "")).lower()
    ports = {event.get("src_port"), event.get("dest_port")}
    for name in (event_type, app_proto):
        if name in {"mdns", "ssdp", "llmnr", "nbns", "dhcp"}:
            return name
    for port, name in ((5353, "mdns"), (1900, "ssdp"), (5355, "llmnr"), (137, "nbns"), (3702, "ws-discovery")):
        if port in ports:
            return name
    if ports & {67, 68}:
        return "dhcp"
    return ""


class SuricataTools:
    """Read-only local Suricata evidence provider backed by canonical EVE JSON."""

    def __init__(self, eve_log: Path = DEFAULT_EVE_LOG, config: Path = DEFAULT_CONFIG, index_path: Path | str | None = None):
        self.eve_log = Path(eve_log).expanduser()
        self.config = Path(config).expanduser()
        selected_index = index_path or default_index_path(self.eve_log)
        try:
            self.index = EveIndex(selected_index)
        except Exception as exc:
            raise RuntimeError(f"Could not initialize EVE index at {selected_index}: {exc}") from exc
        self._last_index_sync: dict[str, Any] = {}
        self._index_healthy = True
        self._sync_gate = threading.Lock()
        self._sync_state_lock = threading.Lock()
        self._background_sync_active = threading.Event()
        self._cursor_lock = threading.Lock()
        self._cursor_states: OrderedDict[str, dict[str, Any]] = OrderedDict()

    def _purge_cursor_states_locked(self, now: float) -> None:
        expired = [
            token
            for token, state in self._cursor_states.items()
            if now - float(state.get("last_access", 0.0)) > CURSOR_TTL_SECONDS
        ]
        for token in expired:
            self._cursor_states.pop(token, None)
        while len(self._cursor_states) >= MAX_CURSOR_STATES:
            self._cursor_states.popitem(last=False)

    def _load_cursor_state(self, cursor: str) -> tuple[dict[str, Any] | None, bool]:
        """Resolve a compact local cursor or decode a legacy self-contained cursor."""
        if not cursor.startswith(CURSOR_PREFIX):
            return _decode_cursor(cursor), False
        now = time.monotonic()
        with self._cursor_lock:
            self._purge_cursor_states_locked(now)
            stored = self._cursor_states.get(cursor)
            if stored is None:
                return None, True
            stored["last_access"] = now
            self._cursor_states.move_to_end(cursor)
            state = dict(stored)
            state["u"] = set(stored.get("u") or ())
            return state, True

    def _store_cursor_state(self, state: dict[str, Any], previous: str = "") -> str:
        """Keep pagination state locally and return only a short opaque token."""
        now = time.monotonic()
        stored = dict(state)
        stored["u"] = frozenset(state.get("u") or ())
        stored["last_access"] = now
        with self._cursor_lock:
            if previous.startswith(CURSOR_PREFIX):
                self._cursor_states.pop(previous, None)
            self._purge_cursor_states_locked(now)
            while True:
                token = CURSOR_PREFIX + secrets.token_urlsafe(16)
                if token not in self._cursor_states:
                    break
            self._cursor_states[token] = stored
        return token

    def _discard_cursor_state(self, cursor: str) -> None:
        if cursor.startswith(CURSOR_PREFIX):
            with self._cursor_lock:
                self._cursor_states.pop(cursor, None)

    def _remember_sync(self, result: dict[str, Any]) -> dict[str, Any]:
        with self._sync_state_lock:
            self._last_index_sync = dict(result)
        return result

    def _sync_snapshot(self) -> dict[str, Any]:
        with self._sync_state_lock:
            return dict(self._last_index_sync)

    def _sync_index(self, progress: Callable[[dict[str, Any]], None] | None = None, *, wait: bool = False) -> dict[str, Any]:
        if not self._index_healthy:
            raise RuntimeError("SQLite index is marked unhealthy; rebuild or verify it before indexed searches")
        if not self._sync_gate.acquire(blocking=wait):
            return {
                **self._sync_snapshot(),
                "deferred": True,
                "deferred_reason": "An isolated background refresh is updating the next committed index snapshot; this query may use the previous committed snapshot.",
            }
        try:
            return self._remember_sync(self.index.sync(self.eve_log, progress=progress))
        finally:
            self._sync_gate.release()

    def sync_index(self, progress: Callable[[dict[str, Any]], None] | None = None, verify: bool | str = False, *, wait: bool = True) -> dict[str, Any]:
        """Incrementally bring the persistent index up to the current EVE EOF."""
        result = self._sync_index(progress, wait=wait)
        if result.get("deferred"):
            return result
        if verify and not result.get("error"):
            mode = "full" if verify is True else str(verify).lower()
            policy = self.index.verification_policy(force_blocking=bool(result.get("source_reset_detected")))
            blocking_reasons = list(policy["blocking_reasons"])
            full_check = mode == "full" or (mode == "auto" and policy["blocking_required"])
            if full_check:
                _report_progress(progress, "verify_start", index_path=str(self.index.path), reasons=policy["blocking_reasons"], mode=mode)
                verification = self.index.verify_integrity()
                if verification["index_integrity"] != "ok":
                    self._index_healthy = False
                    raise RuntimeError(f"SQLite index integrity check failed: {verification['index_integrity']}")
                policy = self.index.verification_policy()
            else:
                verification = {
                    "index_integrity": policy["index_integrity"],
                    "record_count": policy["record_count"],
                    "verified_at": policy["last_full_check_at"],
                }
                _report_progress(
                    progress,
                    "verify_fast_complete",
                    index_integrity=policy["index_integrity"],
                    record_count=policy["record_count"],
                    last_full_check_at=policy["last_full_check_at"],
                    verification_age_hours=policy["verification_age_hours"],
                    background_due=policy["background_due"],
                )
            source_size = self.eve_log.stat().st_size if self.eve_log.is_file() else 0
            fidelity = {
                "index_integrity": verification.get("index_integrity"),
                "schema_version": policy.get("index_schema_version"),
                "record_count": verification.get("record_count", policy.get("record_count", 0)),
                "index_lag_bytes": max(0, source_size - int(result.get("indexed_offset", 0))),
                "malformed_lines": result.get("malformed_lines", 0),
                "partial_line_pending": result.get("partial_line_pending", False),
                "full_check_performed": full_check,
                "last_full_check_at": policy.get("last_full_check_at"),
                "background_verify_due": policy.get("background_due", False),
                "previous_clean_shutdown": policy.get("previous_clean_shutdown"),
            }
            result["fidelity"] = fidelity
            result["verification_policy"] = {**policy, "blocking_check_reasons": blocking_reasons}
            if full_check:
                _report_progress(progress, "verify_complete", **fidelity)
        return result

    def sync_index_independently(self, progress: Callable[[dict[str, Any]], None] | None = None) -> dict[str, Any]:
        """Refresh through an isolated WAL writer while foreground reads continue."""
        if not self._index_healthy:
            raise RuntimeError("SQLite index is marked unhealthy; rebuild or verify it before indexed searches")
        if not self._sync_gate.acquire(blocking=False):
            return {
                **self._sync_snapshot(),
                "deferred": True,
                "deferred_reason": "Another index synchronization is already active.",
            }
        self._background_sync_active.set()
        auxiliary: EveIndex | None = None
        try:
            auxiliary = EveIndex(self.index.path, session_owner=False)
            return self._remember_sync(auxiliary.sync(self.eve_log, progress=progress))
        finally:
            if auxiliary is not None:
                auxiliary.close(clean=False)
            self._background_sync_active.clear()
            self._sync_gate.release()

    def index_sync_in_progress(self) -> bool:
        return self._background_sync_active.is_set()

    def verify_index_independently(self, progress: Callable[[dict[str, Any]], None] | None = None) -> dict[str, Any]:
        """Run a database-wide SQLite quick_check on a separate connection."""
        _report_progress(progress, "verify_start", index_path=str(self.index.path), mode="background", reasons=["scheduled periodic verification"])
        result = EveIndex.verify_database(self.index.path)
        self._index_healthy = result.get("index_integrity") == "ok"
        _report_progress(progress, "verify_complete", **result, background=True)
        return result

    def close(self) -> None:
        with self._cursor_lock:
            self._cursor_states.clear()
        self.index.close()

    @staticmethod
    def _indexed_event(row: Any) -> tuple[int, dict[str, Any]]:
        event = json.loads(row["raw_json"])
        event["_evidence"] = {
            "record_id": row["id"],
            "source_path": row["source_path"],
            "source_generation": row["generation"],
            "source_inode": row["source_inode"],
            "file_offset": row["file_offset"],
            "line_length": row["line_length"],
        }
        return int(row["file_offset"]), event

    def _resolve_window(self, start_time: str = "", end_time: str = "", lookback_minutes: int = 0, lookback_hours: int = 24, all_history: bool = False) -> tuple[datetime | None, datetime | None, dict[str, Any]]:
        if all_history and not start_time and not end_time:
            return None, None, {"start": None, "end": None, "timezone": "event offsets", "basis_note": "all retained EVE records"}
        start = _parse_time(start_time)
        end = _parse_time(end_time) or datetime.now(timezone.utc)
        if not start:
            minutes = _bounded(lookback_minutes, 1, MAX_LOOKBACK_MINUTES) if lookback_minutes else _bounded(lookback_hours, 1, 24 * 30) * 60
            start = end - timedelta(minutes=minutes)
        return start, end, {
            "start": _iso(start),
            "end": _iso(end),
            "requested_start": start_time or None,
            "requested_end": end_time or None,
            "timezone": "ISO-8601 offsets honored; resolved comparison bounds shown in UTC",
        }

    @staticmethod
    def _in_window(event: dict[str, Any], start: datetime | None, end: datetime | None, basis: str) -> bool:
        if start is None and end is None:
            return True
        return any((start is None or when >= start) and (end is None or when <= end) for when in _selected_times(event, basis))

    def _resolve_ip_identity(self, requested: str, start: datetime | None, end: datetime | None, time_basis: str, direction: str = "either", field: str = "either_ip") -> tuple[str, dict[str, Any]]:
        """Resolve canonical or uniquely abbreviated IPv6 identities in the selected window."""
        requested = str(requested or "").strip()
        resolution: dict[str, Any] = {
            "requested_ip": requested,
            "resolved_ip": requested,
            "status": "unchanged",
            "candidates": [],
        }
        if not requested or requested.startswith("."):
            return requested, resolution
        try:
            parsed = ipaddress.ip_address(requested.split("%", 1)[0])
        except ValueError:
            resolution["status"] = "not_an_ip_literal"
            return requested, resolution
        if parsed.version != 6:
            resolution["resolved_ip"] = parsed.compressed
            resolution["status"] = "canonical_exact"
            return parsed.compressed, resolution

        identities = self.index.distinct_ip_values(direction)
        exact = sorted({candidate for candidate in identities if _ip_matches(candidate, requested)})
        candidates = exact or sorted({candidate for candidate in identities if _ipv6_suffix_matches(candidate, requested)})
        active: list[dict[str, Any]] = []
        for candidate in candidates[:100]:
            filters: dict[str, Any] = {field: candidate}
            if field == "either_ip":
                filters["direction"] = direction
            count = self.index.count_events(filters, _iso(start), _iso(end), time_basis)
            if count:
                active.append({"ip": candidate, "count": count})
        resolution["candidates"] = active
        if len(active) == 1:
            resolved = active[0]["ip"]
            resolution.update({
                "resolved_ip": resolved,
                "status": "canonical_equivalent" if exact else "unique_suffix_match",
                "confidence": "exact" if exact else "high",
                "note": "A unique active EVE identity was resolved in the selected window." if not exact else "Equivalent IPv6 text was normalized to the EVE representation.",
            })
            return resolved, resolution
        if len(active) > 1:
            resolution.update({
                "status": "ambiguous_suffix" if not exact else "multiple_equivalent_representations",
                "confidence": "ambiguous",
                "note": "Multiple active EVE identities match; results were not merged automatically.",
            })
        else:
            resolution.update({
                "status": "not_found",
                "confidence": "none",
                "note": "No exact, equivalent, or uniquely recoverable active EVE identity was found in this window; this does not prove that a device was inactive if the supplied address may be incomplete.",
            })
        return requested, resolution

    def _matching_records(self, query: dict[str, Any], start: datetime | None, end: datetime | None, time_basis: str, *, sync: bool = True) -> tuple[list[tuple[int, dict[str, Any]]], int]:
        if sync:
            self._sync_index()
        start_iso, end_iso = _iso(start), _iso(end)
        matches = [self._indexed_event(row) for row in self.index.iter_events(query, start_iso, end_iso, time_basis)]
        records_in_window = 0 if matches else self.index.count_events({}, start_iso, end_iso, time_basis)
        return matches, records_in_window

    def _zero_diagnostics(self, query: dict[str, Any], start: datetime | None, end: datetime | None, time_basis: str, records_in_window: int) -> dict[str, Any]:
        target = query.get("either_ip") or query.get("src_ip") or query.get("dest_ip")
        near_start = start - timedelta(minutes=15) if start else None
        near_end = end + timedelta(minutes=15) if end else None
        start_iso, end_iso = _iso(start), _iso(end)
        target_query = {"either_ip": target} if target else {}
        target_in_window = self.index.count_events(target_query, start_iso, end_iso, "either") if target else 0
        target_near_window = bool(target and self.index.count_events(target_query, _iso(near_start), _iso(near_end), "either"))
        possible_direction_issue = False
        if query.get("src_ip"):
            possible_direction_issue = bool(self.index.count_events({"dest_ip": query["src_ip"]}, start_iso, end_iso, time_basis))
        elif query.get("dest_ip"):
            possible_direction_issue = bool(self.index.count_events({"src_ip": query["dest_ip"]}, start_iso, end_iso, time_basis))
        event_count = self.index.count_events(target_query, start_iso, end_iso, "event") if target else 0
        flow_count = self.index.count_events(target_query, start_iso, end_iso, "flow") if target else 0
        possible_timestamp_basis_issue = time_basis == "event" and flow_count > event_count
        return {
            "eve_records_in_window": records_in_window,
            "target_records_in_window": target_in_window,
            "target_seen_near_window": target_near_window,
            "possible_timestamp_basis_issue": possible_timestamp_basis_issue,
            "possible_direction_issue": possible_direction_issue,
            "possible_index_discrepancy": target_in_window > 0 and not query.get("event_types") and not query.get("signature"),
            "search_backend": "incremental SQLite index backed by canonical EVE JSON",
        }

    def search_events(self, src_ip: str = "", dest_ip: str = "", either_ip: str = "", src_port: int = 0, dest_port: int = 0, either_port: int = 0, proto: str = "", app_proto: str = "", event_types: Any = None, flow_id: int = 0, signature: str = "", hostname: str = "", dns_name: str = "", sni: str = "", http_host: str = "", http_url: str = "", start_time: str = "", end_time: str = "", lookback_minutes: int = 0, lookback_hours: int = 24, time_basis: str = "either", limit: int = DEFAULT_LIMIT, offset: int = 0, cursor: str = "", sort: str = "asc", direction: str = "either", unique_by: str = "none", view: str = "events", duplicates: str = "preserve", detail: str = "standard", free_text: str = "", all_history: bool = False, signature_id: int = 0, severity: int = 0) -> dict[str, Any]:
        """Search EVE while keeping result unit, duplicate policy, and detail independent."""
        if not self.eve_log.is_file():
            return {"error": f"EVE log is unavailable: {self.eve_log}"}
        time_basis = time_basis if time_basis in {"event", "flow", "either"} else "either"
        unique_by = str(unique_by or "none").lower()
        if unique_by not in {"none", "endpoint", "flow_id"}:
            return {"error": "unique_by must be one of: none, endpoint, flow_id"}
        view = str(view or "events").lower()
        duplicates = str(duplicates or "preserve").lower()
        detail = str(detail or "standard").lower()
        if unique_by == "endpoint":
            view = "endpoints"
        elif unique_by == "flow_id":
            view = "flows"
        if view not in {"events", "endpoints", "flows", "transactions"}:
            return {"error": "view must be one of: events, endpoints, flows, transactions"}
        if duplicates not in {"preserve", "annotate", "group_exact"}:
            return {"error": "duplicates must be one of: preserve, annotate, group_exact"}
        if detail not in {"compact", "standard", "raw"}:
            return {"error": "detail must be one of: compact, standard, raw"}
        query = {
            "src_ip": src_ip, "dest_ip": dest_ip, "either_ip": either_ip,
            "src_port": src_port, "dest_port": dest_port, "either_port": either_port,
            "proto": proto, "app_proto": app_proto, "event_types": event_types,
            "flow_id": flow_id, "signature": signature, "hostname": hostname,
            "dns_name": dns_name, "sni": sni, "http_host": http_host,
            "http_url": http_url, "direction": direction, "unique_by": unique_by,
            "view": view, "duplicates": duplicates, "detail": detail, "free_text": free_text,
            "signature_id": signature_id, "severity": severity,
        }
        start, end, window = self._resolve_window(start_time, end_time, lookback_minutes, lookback_hours, all_history)
        cursor_text = str(cursor or "")
        numeric_cursor = bool(cursor_text and cursor_text.isdigit())
        decoded_cursor, local_cursor = self._load_cursor_state(cursor_text) if cursor_text and not numeric_cursor else (None, False)
        if cursor_text and not numeric_cursor and not decoded_cursor:
            message = "Pagination cursor expired or belongs to a previous agent process" if local_cursor else "Invalid pagination cursor"
            return {"error": message}
        if decoded_cursor and not start_time and not end_time:
            start = _parse_time(decoded_cursor.get("a"))
            end = _parse_time(decoded_cursor.get("b"))
            window.update({"start": _iso(start), "end": _iso(end), "cursor_window_reused": True})
        index_sync = self._sync_index()
        requested_query = dict(query)
        ip_resolutions: dict[str, Any] = {}
        for field, field_direction in (("src_ip", "source"), ("dest_ip", "destination"), ("either_ip", direction)):
            if query.get(field):
                resolved, resolution = self._resolve_ip_identity(str(query[field]), start, end, time_basis, direction=field_direction, field=field)
                query[field] = resolved
                ip_resolutions[field] = resolution
        fingerprint = _query_fingerprint(query, _iso(start), _iso(end), time_basis, sort)
        if decoded_cursor and decoded_cursor.get("q") != fingerprint:
            return {"error": "Pagination cursor does not match this query or time window", "query_fingerprint": fingerprint}
        page_offset = _bounded(decoded_cursor.get("o") if decoded_cursor else cursor_text or offset or 0, 0, 2**63 - 1)
        snapshot_max_id = int(decoded_cursor.get("s")) if decoded_cursor else self.index.max_record_id()
        indexed_query = {**query, "_snapshot_max_id": snapshot_max_id}
        page_limit = _bounded(limit, 1, MAX_RESULTS)
        grouping = view != "events" or duplicates == "group_exact"
        cross_page_uniqueness = view != "events"
        scan_batch = min(1000, max(200, page_limit * 20)) if grouping else page_limit
        indexed = self.index.search(indexed_query, _iso(start), _iso(end), time_basis, scan_batch, page_offset, sort)
        total_count = int(indexed["total"])
        selected: list[dict[str, Any]] = []
        selected_by_key: dict[str, dict[str, Any]] = {}
        raw_scanned = 0
        seen_unique = {
            str(value)
            for value in ((decoded_cursor or {}).get("u") or [])
            if isinstance(value, str)
        }
        next_offset = page_offset
        rows = indexed["rows"]
        target = str(query.get("either_ip") or query.get("src_ip") or query.get("dest_ip") or "")
        page_boundary_reached = False
        while rows:
            for row in rows:
                record_offset, event = self._indexed_event(row)
                group_meta: dict[str, Any] | None = None
                if view == "endpoints":
                    group_key, group_meta = _semantic_endpoint(event, target)
                elif view == "flows":
                    if event.get("flow_id") is not None:
                        group_key = f"flow:{event['flow_id']}"
                        group_meta = {"kind": "flow_id", "value": event["flow_id"]}
                    else:
                        group_key = f"unassigned:{_canonical_event_fingerprint(event)}"
                        group_meta = {"kind": "event_without_flow_id", "value": None}
                elif view == "transactions":
                    group_key, group_meta = _transaction_identity(event)
                elif duplicates == "group_exact":
                    fingerprint_value = _canonical_event_fingerprint(event)
                    group_key = f"exact:{fingerprint_value}"
                    group_meta = {"kind": "exact_event", "fingerprint": fingerprint_value}
                else:
                    evidence = event.get("_evidence") if isinstance(event.get("_evidence"), dict) else {}
                    group_key = f"record:{evidence.get('record_id', record_offset)}"

                if grouping:
                    if group_key in selected_by_key:
                        item = selected_by_key[group_key]
                        next_offset += 1
                        raw_scanned += 1
                        item["records"].append((record_offset, event))
                        item["evidence_refs"].append(_evidence_reference(event, record_offset))
                        continue
                    if cross_page_uniqueness and group_key in seen_unique:
                        next_offset += 1
                        raw_scanned += 1
                        continue
                    if len(selected) >= page_limit:
                        page_boundary_reached = True
                        break
                    if cross_page_uniqueness:
                        seen_unique.add(group_key)

                next_offset += 1
                raw_scanned += 1
                item = {
                    "key": group_key,
                    "meta": group_meta,
                    "records": [(record_offset, event)],
                    "evidence_refs": [_evidence_reference(event, record_offset)],
                }
                selected.append(item)
                selected_by_key[group_key] = item
                if not grouping and len(selected) >= page_limit:
                    page_boundary_reached = True
                    break
            if page_boundary_reached or next_offset >= total_count or raw_scanned >= MAX_UNIQUE_SCAN:
                break
            rows = self.index.search_rows(indexed_query, _iso(start), _iso(end), time_basis, scan_batch, next_offset, sort)

        normalized_results: list[dict[str, Any]] = []
        for item in selected:
            record_offset, event = item["records"][0]
            normalized = _format_event(event, record_offset, detail)
            if view == "endpoints":
                normalized["unique_endpoint"] = item["meta"]
            elif view == "flows":
                normalized["flow_group"] = item["meta"]
            elif view == "transactions":
                names: list[str] = []
                answers: list[str] = []
                message_types: Counter[str] = Counter()
                exact_groups: dict[str, list[dict[str, Any]]] = {}
                for _, grouped_event in item["records"]:
                    grouped_names, grouped_answers = _dns_values(grouped_event)
                    names.extend(grouped_names)
                    answers.extend(grouped_answers)
                    dns = grouped_event.get("dns") if isinstance(grouped_event.get("dns"), dict) else {}
                    if not dns and isinstance(grouped_event.get("mdns"), dict):
                        dns = grouped_event["mdns"]
                    message_types[str(dns.get("type") or grouped_event.get("event_type") or "event")] += 1
                for (grouped_offset, grouped_event), reference in zip(item["records"], item["evidence_refs"]):
                    exact_groups.setdefault(_canonical_event_fingerprint(grouped_event), []).append(reference)
                duplicate_groups = [
                    {"fingerprint": fingerprint_value[:20], "raw_record_count": len(refs), "evidence_refs": refs, "cause": "unknown"}
                    for fingerprint_value, refs in exact_groups.items()
                    if len(refs) > 1
                ]
                normalized["transaction"] = {
                    **(item["meta"] or {}),
                    "records_in_group": len(item["records"]),
                    "message_types": dict(message_types),
                    "dns_queries": list(dict.fromkeys(names)),
                    "dns_answers": list(dict.fromkeys(answers)),
                    "evidence_refs": item["evidence_refs"],
                    "exact_duplicate_records": sum(group["raw_record_count"] - 1 for group in duplicate_groups),
                    "exact_duplicate_groups": duplicate_groups,
                }
            elif duplicates == "group_exact":
                if len(item["records"]) > 1:
                    normalized["exact_duplicate_group"] = {
                        "fingerprint": str((item["meta"] or {}).get("fingerprint", ""))[:20],
                        "raw_record_count": len(item["records"]),
                        "extra_duplicate_records": len(item["records"]) - 1,
                        "evidence_refs": item["evidence_refs"],
                        "duplicate_origin": "multiple matching canonical EVE records",
                        "cause": "unknown",
                    }
            normalized_results.append(normalized)

        if view == "events" and duplicates == "annotate":
            page_groups: dict[str, list[tuple[dict[str, Any], dict[str, Any]]]] = {}
            for normalized, item in zip(normalized_results, selected):
                _, event = item["records"][0]
                page_groups.setdefault(_canonical_event_fingerprint(event), []).append((normalized, item["evidence_refs"][0]))
            for fingerprint_value, members in page_groups.items():
                if len(members) < 2:
                    continue
                refs = [reference for _, reference in members]
                for normalized, _ in members:
                    normalized["exact_duplicate_annotation"] = {
                        "fingerprint": fingerprint_value[:20],
                        "copies_on_returned_page": len(members),
                        "evidence_refs": refs,
                        "duplicate_origin": "multiple matching canonical EVE records",
                        "cause": "unknown",
                    }
        has_more = next_offset < total_count
        if has_more:
            next_cursor = self._store_cursor_state(
                {
                    "v": 2,
                    "o": next_offset,
                    "s": snapshot_max_id,
                    "q": fingerprint,
                    "a": _iso(start),
                    "b": _iso(end),
                    "u": seen_unique if cross_page_uniqueness else set(),
                },
                previous=cursor_text if local_cursor else "",
            )
        else:
            self._discard_cursor_state(cursor_text)
            next_cursor = None
        result: dict[str, Any] = {
            "query": {key: value for key, value in query.items() if value not in ("", 0, None, [], {})},
            "requested_query": {key: value for key, value in requested_query.items() if value not in ("", 0, None, [], {})},
            "ip_resolution": ip_resolutions,
            "resolved_window": {**window, "time_basis": time_basis},
            "index_sync": index_sync,
            "source_path": str(self.eve_log),
            "snapshot_max_record_id": snapshot_max_id,
            "query_fingerprint": fingerprint,
            "total_count": total_count, "count": len(selected), "returned": len(selected),
            "total_raw_records": total_count,
            "returned_items": len(selected),
            "raw_records_scanned": raw_scanned,
            "raw_records_covered": sum(len(item["records"]) for item in selected),
            "view": view,
            "duplicate_policy": duplicates,
            "detail": detail,
            "resolved_semantics": {
                "result_unit": view,
                "duplicate_policy": duplicates,
                "detail": detail,
                "order": "descending/newest-first" if str(sort).lower() == "desc" else "ascending/oldest-first",
                "raw_evidence_preserved": True,
            },
            "offset": page_offset,
            "next_cursor": next_cursor,
            "truncated": has_more,
            "counts_by_type": indexed["counts"],
            "results": normalized_results,
        }
        if grouping:
            result.update({
                "unique_by": unique_by if unique_by != "none" else None,
                "duplicates_skipped": raw_scanned - len(selected),
                "unique_scan_limit": MAX_UNIQUE_SCAN,
                "unique_scan_truncated": raw_scanned >= MAX_UNIQUE_SCAN and has_more,
                "grouping_note": "Grouping changes presentation only; every grouped canonical record remains traceable through evidence_refs or get_event.",
            })
            if view == "endpoints":
                result["uniqueness_note"] = "Endpoint view groups DNS/mDNS by queried name, TLS/QUIC by SNI, HTTP by host, and other traffic by peer IP/port/protocol relative to the target."
            elif duplicates == "group_exact":
                result["exact_duplicates_grouped"] = sum(max(0, len(item["records"]) - 1) for item in selected)
                result["duplicate_cause"] = "unknown; the tool only establishes that matching records exist in canonical EVE"
                result["exact_grouping_scope"] = "matching canonical events encountered in the ordered page scan; noncontiguous later copies remain eligible for later pages rather than being discarded"
        shorthand = either_ip or src_ip or dest_ip
        if shorthand.startswith("."):
            all_rows = self.index.iter_events(indexed_query, _iso(start), _iso(end), time_basis)
            result["resolved_ips"] = sorted({str(value) for row in all_rows for value in (row["src_ip"], row["dest_ip"]) if _ip_matches(value, shorthand)})
        if not total_count:
            records_in_window = self.index.search({}, _iso(start), _iso(end), time_basis, 1, 0, "asc")["total"]
            result["diagnostics"] = self._zero_diagnostics(query, start, end, time_basis, records_in_window)
        return result

    def search_alerts(self, src_ip: str = "", dest_ip: str = "", either_ip: str = "", signature: str = "", sid: int = 0, severity: int = 0, start_time: str = "", end_time: str = "", lookback_minutes: int = 0, lookback_hours: int = 24, time_basis: str = "either", limit: int = 20, offset: int = 0, all_history: bool = False) -> dict[str, Any]:
        result = self.search_events(src_ip=src_ip, dest_ip=dest_ip, either_ip=either_ip, event_types=["alert"], signature=signature, signature_id=sid, severity=severity, start_time=start_time, end_time=end_time, lookback_minutes=lookback_minutes, lookback_hours=lookback_hours, time_basis=time_basis, limit=limit, offset=offset, all_history=all_history)
        result["scope_note"] = "This result covers IDS alert records only; it does not establish whether network traffic occurred."
        return result

    def get_event(self, event_id: str = "", flow_id: int = 0, file_offset: int = -1, record_id: int = 0) -> dict[str, Any]:
        if not self.eve_log.is_file():
            return {"error": f"EVE log is unavailable: {self.eve_log}"}
        self._sync_index()
        requested_flow = int(flow_id or 0)
        if not requested_flow and str(event_id).isdigit():
            requested_flow = int(event_id)
        row = self.index.get_event(record_id=record_id, event_id=event_id, flow_id=requested_flow, file_offset=file_offset)
        if row:
            offset, event = self._indexed_event(row)
            return _normalized_event(event, offset, raw=True)
        return {"error": "Event was not found in indexed retained EVE data", "requested": {"record_id": record_id, "event_id": event_id, "flow_id": requested_flow, "file_offset": file_offset}}

    def verify_raw_eve_witness(self, record_id: int, ip: str, resolved_window: dict[str, Any], time_basis: str = "either") -> dict[str, Any]:
        """Verify one indexed positive against its exact canonical EVE line."""
        row = self.index.get_event(record_id=int(record_id))
        if row is None:
            return {"verified": False, "warning": "Indexed witness record was not found"}
        try:
            with self.eve_log.open("rb") as stream:
                stat = os.fstat(stream.fileno())
                if (stat.st_dev, stat.st_ino) != (row["source_dev"], row["source_inode"]):
                    return {"verified": False, "warning": "Witness belongs to a rotated EVE generation; current file cannot verify its offset"}
                stream.seek(int(row["file_offset"]))
                raw = stream.readline()
        except OSError:
            return {"verified": False, "warning": "Canonical EVE file was unavailable for witness verification"}
        try:
            original = raw.decode("utf-8").rstrip("\r\n")
            if original != row["raw_json"]:
                return {"verified": False, "warning": "Canonical EVE line differs from the indexed witness"}
            event = json.loads(original)
        except (UnicodeDecodeError, json.JSONDecodeError):
            return {"verified": False, "warning": "Canonical EVE witness line could not be decoded"}
        start = _parse_time(resolved_window.get("start"))
        end = _parse_time(resolved_window.get("end"))
        if not isinstance(event, dict) or not self._in_window(event, start, end, time_basis):
            return {"verified": False, "warning": "Canonical EVE witness does not match the requested time window"}
        if not any(_ip_matches(event.get(field), ip) for field in ("src_ip", "dest_ip")):
            return {"verified": False, "warning": "Canonical EVE witness does not involve the target IP"}
        return {
            "verified": True, "count": 1, "count_exact": False,
            "record_id": int(row["id"]), "file_offset": int(row["file_offset"]),
            "timestamp": event.get("timestamp"), "flow_id": event.get("flow_id"),
            "source": "direct canonical EVE offset verification",
            "note": "One matching raw record was verified; count=1 is a lower bound, not the full-window total.",
        }

    @staticmethod
    def _flow_relation(event: dict[str, Any]) -> str:
        event_type = str(event.get("event_type") or "event").lower()
        if event_type in {"dns", "mdns"}:
            section = event.get("dns") if isinstance(event.get("dns"), dict) else event.get("mdns") if isinstance(event.get("mdns"), dict) else {}
            kind = str(section.get("type") or "message").lower()
            return f"{event_type}_{kind}"
        return {
            "flow": "flow_summary",
            "tls": "tls_handshake",
            "http": "http_transaction",
            "alert": "ids_alert",
        }.get(event_type, event_type)

    def correlate_flow(self, flow_id: int, limit: int = MAX_RESULTS, offset: int = 0, duplicates: str = "group_exact", detail: str = "compact") -> dict[str, Any]:
        """Build a chronological, lossless flow chain with reversible duplicate grouping."""
        duplicates = str(duplicates or "group_exact").lower()
        detail = str(detail or "compact").lower()
        if duplicates not in {"preserve", "annotate", "group_exact"}:
            return {"error": "duplicates must be one of: preserve, annotate, group_exact"}
        if detail not in {"compact", "standard", "raw"}:
            return {"error": "detail must be one of: compact, standard, raw"}
        index_sync = self._sync_index()
        indexed_query = {"flow_id": int(flow_id)}
        records = [self._indexed_event(row) for row in self.index.iter_events(indexed_query, None, None, "either")]
        # A flow summary may describe an earlier flow.start but is emitted at
        # its top-level event timestamp. Chain chronology follows observation
        # emission order while still exposing flow_start/flow_end separately.
        records.sort(key=lambda item: (_sort_time(item[1], "event"), item[0]))
        counts = Counter(str(event.get("event_type") or "unknown") for _, event in records)

        groups: list[dict[str, Any]] = []
        groups_by_key: dict[str, dict[str, Any]] = {}
        for record_offset, event in records:
            key = _canonical_event_fingerprint(event) if duplicates == "group_exact" else f"record:{_evidence_reference(event, record_offset).get('record_id', record_offset)}"
            if duplicates == "group_exact" and key in groups_by_key:
                group = groups_by_key[key]
                group["records"].append((record_offset, event))
                group["evidence_refs"].append(_evidence_reference(event, record_offset))
                continue
            group = {
                "key": key,
                "records": [(record_offset, event)],
                "evidence_refs": [_evidence_reference(event, record_offset)],
            }
            groups.append(group)
            groups_by_key[key] = group

        page_limit = _bounded(limit, 1, MAX_RESULTS)
        page_offset = _bounded(offset, 0, 2**63 - 1)
        page = groups[page_offset:page_offset + page_limit]
        timeline: list[dict[str, Any]] = []
        for group in page:
            record_offset, event = group["records"][0]
            item = _format_event(event, record_offset, detail)
            item["relation"] = self._flow_relation(event)
            item["evidence_refs"] = group["evidence_refs"]
            if duplicates == "group_exact" and len(group["records"]) > 1:
                item["exact_duplicate_group"] = {
                    "fingerprint": group["key"][:20],
                    "raw_record_count": len(group["records"]),
                    "extra_duplicate_records": max(0, len(group["records"]) - 1),
                    "cause": "unknown",
                }
            timeline.append(item)

        if duplicates == "annotate":
            fingerprints: dict[str, list[dict[str, Any]]] = {}
            for item, group in zip(timeline, page):
                _, event = group["records"][0]
                fingerprints.setdefault(_canonical_event_fingerprint(event), []).append(item)
            for fingerprint_value, members in fingerprints.items():
                if len(members) > 1:
                    refs = [reference for member in members for reference in member["evidence_refs"]]
                    for member in members:
                        member["exact_duplicate_annotation"] = {
                            "fingerprint": fingerprint_value[:20],
                            "copies_on_returned_page": len(members),
                            "evidence_refs": refs,
                            "cause": "unknown",
                        }

        next_offset = page_offset + len(page)
        return {
            "flow_id": int(flow_id),
            "index_sync": index_sync,
            "source_path": str(self.eve_log),
            "duplicate_policy": duplicates,
            "detail": detail,
            "resolved_semantics": {
                "result_unit": "flow_chain",
                "duplicate_policy": duplicates,
                "detail": detail,
                "order": "chronological by EVE event timestamp",
                "raw_evidence_preserved": True,
            },
            "raw_record_count": len(records),
            "logical_event_count": len(groups),
            "exact_duplicate_records": len(records) - len({_canonical_event_fingerprint(event) for _, event in records}),
            "counts_by_type": dict(counts),
            "returned": len(timeline),
            "offset": page_offset,
            "next_offset": next_offset if next_offset < len(groups) else None,
            "next_cursor": str(next_offset) if next_offset < len(groups) else None,
            "truncated": next_offset < len(groups),
            "timeline": timeline,
            "results": timeline,
            "ordering": "chronological by EVE event timestamp and record ID; flow_start/flow_end remain exposed separately",
            "evidence_policy": "Distinct request, response, alert, TLS, HTTP, and flow records are preserved. Exact grouping only combines matching canonical events and retains every record reference.",
            "duplicate_cause": "unknown; matching canonical EVE records do not establish why they were emitted more than once",
        }

    def get_flow(self, flow_id: int, limit: int = MAX_RESULTS, offset: int = 0, duplicates: str = "group_exact", detail: str = "compact") -> dict[str, Any]:
        return self.correlate_flow(flow_id, limit, offset, duplicates, detail)

    def search_related_events(self, src_ip: str = "", dest_ip: str = "", flow_id: int = 0, lookback_minutes: int = 15, limit: int = 30, all_history: bool = False) -> dict[str, Any]:
        """Compatibility search that now handles one-IP and bidirectional queries."""
        if flow_id:
            return self.correlate_flow(flow_id, limit)
        if src_ip and dest_ip:
            return self.investigate_pair(src_ip, dest_ip, lookback_minutes=lookback_minutes, limit=limit, all_history=all_history)
        return self.search_events(either_ip=src_ip or dest_ip, lookback_minutes=lookback_minutes, limit=limit, all_history=all_history)

    def events_around(self, timestamp: str, seconds_before: int = 30, seconds_after: int = 30, ip: str = "", peer: str = "", event_types: Any = None, time_basis: str = "either", limit: int = DEFAULT_LIMIT, offset: int = 0) -> dict[str, Any]:
        center = _parse_time(timestamp)
        if not center:
            return {"error": f"Invalid ISO-8601 timestamp: {timestamp}"}
        start = _iso(center - timedelta(seconds=_bounded(seconds_before, 0, MAX_LOOKBACK_MINUTES * 60))) or ""
        end = _iso(center + timedelta(seconds=_bounded(seconds_after, 0, MAX_LOOKBACK_MINUTES * 60))) or ""
        if ip and peer:
            result = self.investigate_pair(ip, peer, start_time=start, end_time=end, event_types=event_types, time_basis=time_basis, limit=limit, offset=offset)
        else:
            result = self.search_events(either_ip=ip, event_types=event_types, start_time=start, end_time=end, time_basis=time_basis, limit=limit, offset=offset)
        result["center_timestamp"] = _iso(center)
        return result

    @staticmethod
    def _notable_sequences(records: list[tuple[int, dict[str, Any]]], target: str) -> list[dict[str, Any]]:
        chronological = sorted(records, key=lambda item: (_sort_time(item[1], "either"), item[0]))
        discoveries: list[tuple[datetime, int, list[str], str]] = []
        attempts: list[tuple[datetime, int, dict[str, Any]]] = []
        dns_answers: list[tuple[datetime, str, str, int]] = []
        for offset, event in chronological:
            times = _selected_times(event, "either")
            if not times:
                continue
            when = min(times)
            names, answers = _dns_values(event)
            event_type = str(event.get("event_type", "")).lower()
            discovery_protocol = _discovery_protocol(event)
            if discovery_protocol:
                discoveries.append((when, offset, names or [discovery_protocol], discovery_protocol))
            for name in names:
                for answer in answers:
                    dns_answers.append((when, name, answer, offset))
            if event_type == "flow" and str(event.get("proto", "")).upper() == "TCP" and _ip_matches(event.get("src_ip"), target):
                attempts.append((when, offset, event))
        sequences: list[dict[str, Any]] = []
        for when, offset, names, protocol in discoveries:
            nearby = [(attempt_when, attempt_offset, event) for attempt_when, attempt_offset, event in attempts if timedelta(0) <= attempt_when - when <= timedelta(seconds=60)]
            if nearby:
                delta = min((attempt_when - when).total_seconds() for attempt_when, _, _ in nearby)
                sequences.append({
                    "pattern": "service_discovery_followed_by_service_check",
                    "confidence": "high" if delta <= 15 else "medium",
                    "discovery_protocol": protocol, "services": names,
                    "discovery_timestamp": _iso(when),
                    "source_offsets": [offset, *[attempt_offset for _, attempt_offset, _ in nearby]],
                    "attempts": [{"timestamp": _iso(attempt_when), "flow_id": event.get("flow_id"), "destination": event.get("dest_ip"), "destination_port": event.get("dest_port"), "outcome": classify_tcp_outcome(event), "file_offset": attempt_offset} for attempt_when, attempt_offset, event in nearby[:20]],
                })
        for when, name, answer, dns_offset in dns_answers:
            nearby = [(attempt_when, attempt_offset, event) for attempt_when, attempt_offset, event in attempts if str(event.get("dest_ip")) == answer and timedelta(0) <= attempt_when - when <= timedelta(seconds=120)]
            if nearby:
                sequences.append({
                    "pattern": "dns_answer_followed_by_connection",
                    "confidence": "high" if (nearby[0][0] - when).total_seconds() <= 30 else "medium",
                    "dns_name": name, "answer": answer, "dns_timestamp": _iso(when), "dns_file_offset": dns_offset,
                    "connections": [{"timestamp": _iso(item[0]), "flow_id": item[2].get("flow_id"), "destination_port": item[2].get("dest_port"), "outcome": classify_tcp_outcome(item[2]), "file_offset": item[1]} for item in nearby[:10]],
                })
        return sequences[:50]

    def _summarize_host_records(self, target: str, records: list[tuple[int, dict[str, Any]]], window: dict[str, Any], limit: int) -> dict[str, Any]:
        counts, peers, ports, directions = Counter(), Counter(), Counter(), Counter()
        dns_names, dns_answers, tls_sni, http_hosts, http_urls, outcomes, requests = Counter(), Counter(), Counter(), Counter(), Counter(), Counter(), Counter()
        outbound_observations = Counter()
        discovery_protocols, application_protocols = Counter(), Counter()
        alerts, tcp_attempts, flows = [], [], []
        destination_ips: set[str] = set()
        destination_ports: set[int] = set()
        bytes_total = packets_total = 0
        for offset, event in records:
            event_type = str(event.get("event_type", "unknown"))
            counts[event_type] += 1
            discovery_protocol = _discovery_protocol(event)
            if discovery_protocol:
                discovery_protocols[discovery_protocol] += 1
            if event.get("app_proto"):
                application_protocols[str(event["app_proto"])] += 1
            src_matches, dest_matches = _ip_matches(event.get("src_ip"), target), _ip_matches(event.get("dest_ip"), target)
            if src_matches and not dest_matches:
                directions["outbound"] += 1
                peer = event.get("dest_ip")
                if peer:
                    destination_ips.add(str(peer))
                if event.get("dest_port") is not None:
                    try:
                        destination_ports.add(int(event["dest_port"]))
                    except (TypeError, ValueError):
                        pass
            elif dest_matches and not src_matches:
                directions["inbound"] += 1
                peer = event.get("src_ip")
            else:
                directions["local_or_ambiguous"] += 1
                peer = event.get("dest_ip") or event.get("src_ip")
            if peer:
                peers[str(peer)] += 1
            port = event.get("dest_port") if src_matches else event.get("src_port")
            if port is not None:
                ports[str(port)] += 1
            names, answers = _dns_values(event)
            dns_names.update(names)
            dns_answers.update(answers)
            tls = event.get("tls") if isinstance(event.get("tls"), dict) else {}
            http = event.get("http") if isinstance(event.get("http"), dict) else {}
            if tls.get("sni"):
                tls_sni[str(tls["sni"])] += 1
            if http.get("hostname"):
                http_hosts[str(http["hostname"])] += 1
            if http.get("url"):
                http_urls[str(http["url"])] += 1
            if src_matches:
                dns = event.get("dns") if isinstance(event.get("dns"), dict) else {}
                mdns = event.get("mdns") if isinstance(event.get("mdns"), dict) else {}
                dns_kind = str(dns.get("type") or mdns.get("type") or "").lower()
                if names and dns_kind in {"request", "query"}:
                    request_protocol = "mDNS" if event_type == "mdns" or event.get("app_proto") == "mdns" else "DNS"
                    requests.update(f"{request_protocol} query {name}" for name in names)
                elif event_type == "http" and (http.get("hostname") or http.get("url")):
                    requests[f"HTTP {http.get('hostname', '')}{http.get('url', '')}"] += 1
                elif event_type == "tls" and tls.get("sni"):
                    outbound_observations[f"TLS SNI {tls['sni']}"] += 1
                elif event_type == "flow":
                    destination = str(event.get("dest_ip") or "?")
                    destination_port = f":{event['dest_port']}" if event.get("dest_port") is not None else ""
                    outbound_observations[f"{event.get('proto', 'IP')} -> {destination}{destination_port}"] += 1
            flow = event.get("flow") if isinstance(event.get("flow"), dict) else {}
            bytes_total += int(flow.get("bytes_toserver") or 0) + int(flow.get("bytes_toclient") or 0)
            packets_total += int(flow.get("pkts_toserver") or 0) + int(flow.get("pkts_toclient") or 0)
            if event_type == "flow":
                normalized = _normalized_event(event, offset)
                flows.append(normalized)
                if str(event.get("proto", "")).upper() == "TCP":
                    outcome = classify_tcp_outcome(event)
                    outcomes[outcome] += 1
                    tcp_attempts.append({"timestamp": normalized.get("flow_start") or normalized.get("event_timestamp"), "flow_id": event.get("flow_id"), "src_ip": event.get("src_ip"), "src_port": event.get("src_port"), "dest_ip": event.get("dest_ip"), "dest_port": event.get("dest_port"), "outcome": outcome, "file_offset": offset})
            if event_type == "alert":
                alerts.append(_normalized_event(event, offset))
        sample_limit = _bounded(limit, 1, MAX_RESULTS)
        chronological = sorted(records, key=lambda item: (_sort_time(item[1], "either"), item[0]))
        candidates: list[tuple[int, dict[str, Any]]] = []
        if chronological:
            candidates.extend((chronological[0], chronological[-1]))
        seen_types: set[str] = set()
        for item in chronological:
            event_type = str(item[1].get("event_type", "unknown"))
            if event_type not in seen_types:
                candidates.append(item)
                seen_types.add(event_type)
            if event_type == "alert":
                candidates.append(item)
            elif event_type == "flow" and classify_tcp_outcome(item[1]) in {"connection_refused", "no_response", "syn_only", "reset_after_connect", "unknown"}:
                candidates.append(item)
        candidates.extend(chronological)
        selected: list[tuple[int, dict[str, Any]]] = []
        selected_ids: set[Any] = set()
        for item in candidates:
            evidence = item[1].get("_evidence") if isinstance(item[1].get("_evidence"), dict) else {}
            identity = evidence.get("record_id", (evidence.get("source_generation"), item[0]))
            if identity in selected_ids:
                continue
            selected_ids.add(identity)
            selected.append(item)
            if len(selected) >= sample_limit:
                break
        selected.sort(key=lambda item: (_sort_time(item[1], "either"), item[0]))
        return {
            "target": target,
            "resolved_ips": sorted({str(value) for _, event in records for value in (event.get("src_ip"), event.get("dest_ip")) if _ip_matches(value, target)}),
            "resolved_window": window, "total_events": len(records),
            "counts": dict(counts.most_common()), "direction_counts": dict(directions),
            "top_peers": [{"ip": key, "count": value} for key, value in peers.most_common(25)],
            "top_ports": [{"port": key, "count": value} for key, value in ports.most_common(25)],
            "dns_names": [{"name": key, "count": value} for key, value in dns_names.most_common(50)],
            "dns_answers": [{"answer": key, "count": value} for key, value in dns_answers.most_common(50)],
            "discovery_protocols": dict(discovery_protocols.most_common()),
            "application_protocols": dict(application_protocols.most_common()),
            "tls_sni": [{"sni": key, "count": value} for key, value in tls_sni.most_common(30)],
            "http_hosts": [{"host": key, "count": value} for key, value in http_hosts.most_common(30)],
            "http_urls": [{"url": key, "count": value} for key, value in http_urls.most_common(30)],
            "top_requests": [{"request": key, "count": value} for key, value in requests.most_common(sample_limit)],
            "outbound_observations": [{"observation": key, "count": value} for key, value in outbound_observations.most_common(sample_limit)],
            "request_semantics_note": "top_requests contains observed DNS/mDNS queries and HTTP requests. TLS SNI and generic destination flows are reported separately as outbound_observations.",
            "connection_outcomes": dict(outcomes), "tcp_attempts": tcp_attempts[:50], "alerts": alerts[:50],
            "flow_count": len(flows), "unique_destination_ips": sorted(destination_ips), "unique_destination_ports": sorted(destination_ports),
            "totals": {"bytes": bytes_total, "packets": packets_total},
            "notable_sequences": self._notable_sequences(records, target),
            "representative_records": [_normalized_event(event, offset) for offset, event in selected],
            "representative_records_truncated": len(records) > sample_limit,
            "representative_sampling": "stratified boundaries, event types, alerts, and non-success TCP outcomes",
            "raw_reference_note": "Use get_event(record_id=...) or correlate_flow(flow_id=...) to retrieve original evidence.",
        }

    def investigate_host(self, ip: str, start_time: str = "", end_time: str = "", lookback_minutes: int = 0, lookback_hours: int = 24, peer_ip: str = "", ports: Any = None, focus: str = "", direction: str = "either", time_basis: str = "either", limit: int = 25, all_history: bool = False) -> dict[str, Any]:
        if not ip:
            return {"error": "ip is required"}
        start, end, window = self._resolve_window(start_time, end_time, lookback_minutes, lookback_hours, all_history)
        index_sync = self._sync_index()
        resolved_ip, ip_resolution = self._resolve_ip_identity(ip, start, end, time_basis, direction=direction, field="either_ip")
        query: dict[str, Any] = {"either_ip": resolved_ip, "direction": direction}
        normalized_focus = str(focus or "").strip().lower().replace("_", " ")
        if normalized_focus not in {"", "all", "any", "everything", "all events", "any events", "all event types", "any event types", "all traffic"}:
            known = normalized_focus in {"alert", "flow", "dns", "mdns", "tls", "http", "quic", "dhcp", "anomaly", "fileinfo"}
            query["event_types" if known else "free_text"] = [normalized_focus] if known else focus
        records, records_in_window = self._matching_records(query, start, end, time_basis, sync=False)
        if peer_ip:
            records = [(offset, event) for offset, event in records if _ip_matches(event.get("src_ip"), peer_ip) or _ip_matches(event.get("dest_ip"), peer_ip)]
        if ports:
            requested = {int(value) for value in (ports if isinstance(ports, list) else [ports])}
            records = [(offset, event) for offset, event in records if any(_port_matches(event.get("src_port"), port) or _port_matches(event.get("dest_port"), port) for port in requested)]
        result = self._summarize_host_records(resolved_ip, records, {**window, "time_basis": time_basis}, limit)
        result.update({"requested_target": ip, "ip_resolution": ip_resolution, "index_sync": index_sync})
        if not records:
            result["diagnostics"] = self._zero_diagnostics(query, start, end, time_basis, records_in_window)
        return result

    def investigate_pair(self, ip1: str, ip2: str, start_time: str = "", end_time: str = "", lookback_minutes: int = 0, lookback_hours: int = 24, event_types: Any = None, time_basis: str = "either", limit: int = 50, offset: int = 0, all_history: bool = False) -> dict[str, Any]:
        start, end, window = self._resolve_window(start_time, end_time, lookback_minutes, lookback_hours, all_history)
        records, _ = self._matching_records({"pair": (ip1, ip2), "event_types": event_types}, start, end, time_basis)
        result = self._summarize_host_records(ip1, records, {**window, "time_basis": time_basis}, limit)
        result.update({"pair": [ip1, ip2], "offset": offset})
        page_limit = _bounded(limit, 1, MAX_RESULTS)
        ordered = sorted(records, key=lambda item: (_sort_time(item[1], time_basis), item[0]))
        result["results"] = [_normalized_event(event, record_offset) for record_offset, event in ordered[offset:offset + page_limit]]
        result.update({"total_count": len(records), "next_cursor": str(offset + page_limit) if offset + page_limit < len(records) else None, "truncated": offset + page_limit < len(records)})
        return result

    def investigate_service(self, ip: str, port: int, start_time: str = "", end_time: str = "", lookback_minutes: int = 0, lookback_hours: int = 24, time_basis: str = "either", limit: int = 50, all_history: bool = False) -> dict[str, Any]:
        start, end, window = self._resolve_window(start_time, end_time, lookback_minutes, lookback_hours, all_history)
        records, _ = self._matching_records({"either_ip": ip, "either_port": port}, start, end, time_basis)
        result = self._summarize_host_records(ip, records, {**window, "time_basis": time_basis}, limit)
        result["service_port"] = port
        return result

    def count_raw_eve_matches(self, ip: str = "", start_time: str = "", end_time: str = "", lookback_minutes: int = 0, lookback_hours: int = 24, time_basis: str = "either", all_history: bool = False) -> dict[str, Any]:
        """Sanity-check canonical EVE directly, independent of the SQLite index."""
        if not self.eve_log.is_file():
            return {"error": f"EVE log is unavailable: {self.eve_log}"}
        start, end, window = self._resolve_window(start_time, end_time, lookback_minutes, lookback_hours, all_history)
        def empty_summary() -> dict[str, Any]:
            return {"count": 0, "counts": Counter(), "first": None, "last": None}

        def add(summary: dict[str, Any], event: dict[str, Any], offset: int) -> None:
            summary["count"] += 1
            summary["counts"][str(event.get("event_type", "unknown"))] += 1
            reference = {"timestamp": event.get("timestamp"), "flow_id": event.get("flow_id"), "file_offset": offset}
            summary["first"] = summary["first"] or reference
            summary["last"] = reference

        exact = empty_summary()
        suffix_matches: dict[str, dict[str, Any]] = {}
        # For a canonical IPv4 literal, a nonmatching JSON line cannot contain
        # that src_ip/dest_ip value unless the JSON string was Unicode-escaped.
        # Keep escaped lines as candidates. IPv6/shorthand searches still parse
        # every line because textual spellings may differ from the requested IP.
        literal_ip: bytes | None = None
        try:
            parsed_ip = ipaddress.ip_address(ip)
            if parsed_ip.version == 4 and str(parsed_ip) == ip:
                literal_ip = b'"' + ip.encode("ascii") + b'"'
        except (TypeError, ValueError):
            pass
        started = time.perf_counter()
        lines_scanned = decoded_lines = 0
        scan_complete = True
        with self.eve_log.open("rb") as stream:
            source_stat = os.fstat(stream.fileno())
            source_snapshot_bytes = source_stat.st_size
            while stream.tell() < source_snapshot_bytes:
                offset = stream.tell()
                raw = stream.readline(source_snapshot_bytes - offset)
                if not raw:
                    scan_complete = False
                    break
                if not raw.endswith(b"\n"):
                    scan_complete = False
                    break
                lines_scanned += 1
                if literal_ip and literal_ip not in raw and b"\\u" not in raw:
                    continue
                try:
                    event = json.loads(raw)
                except (UnicodeDecodeError, json.JSONDecodeError):
                    continue
                decoded_lines += 1
                if not isinstance(event, dict) or not self._in_window(event, start, end, time_basis):
                    continue
                values = {str(value) for value in (event.get("src_ip"), event.get("dest_ip")) if value}
                if not ip or any(_ip_matches(value, ip) for value in values):
                    add(exact, event, offset)
                    continue
                for candidate in {value for value in values if _ipv6_suffix_matches(value, ip)}:
                    add(suffix_matches.setdefault(candidate, empty_summary()), event, offset)

        selected = exact
        resolution: dict[str, Any] = {
            "requested_ip": ip,
            "resolved_ip": ip,
            "status": "exact" if exact["count"] else "not_found",
            "candidates": [],
        }
        if not exact["count"] and len(suffix_matches) == 1:
            resolved_ip, selected = next(iter(suffix_matches.items()))
            resolution.update({
                "resolved_ip": resolved_ip,
                "status": "unique_suffix_match",
                "confidence": "high",
                "candidates": [{"ip": resolved_ip, "count": selected["count"]}],
                "note": "The exact IPv6 literal was absent; one unique active raw-EVE identity matched its prefix and trailing hextets.",
            })
        elif not exact["count"] and suffix_matches:
            resolution.update({
                "status": "ambiguous_suffix",
                "confidence": "ambiguous",
                "candidates": sorted(({"ip": candidate, "count": summary["count"]} for candidate, summary in suffix_matches.items()), key=lambda item: (-item["count"], item["ip"])),
                "note": "Multiple raw-EVE identities matched; records were not merged.",
            })
        elif not exact["count"] and ip:
            resolution.update({
                "confidence": "none",
                "note": "No exact or uniquely recoverable raw-EVE identity matched in this window; this does not prove that a device was inactive if the supplied address may be incomplete.",
            })
        try:
            current_stat = self.eve_log.stat()
            source_snapshot_consistent = (current_stat.st_dev, current_stat.st_ino) == (source_stat.st_dev, source_stat.st_ino) and current_stat.st_size >= source_snapshot_bytes
            growth_deferred = max(0, current_stat.st_size - source_snapshot_bytes) if source_snapshot_consistent else 0
        except FileNotFoundError:
            source_snapshot_consistent = False
            growth_deferred = 0
        return {
            "count": selected["count"],
            "counts_by_type": dict(selected["counts"]),
            "resolved_window": {**window, "time_basis": time_basis},
            "first_match": selected["first"],
            "last_match": selected["last"],
            "requested_ip": ip,
            "resolved_ip": resolution["resolved_ip"],
            "ip_resolution": resolution,
            "source": "direct canonical EVE scan",
            "source_snapshot_bytes": source_snapshot_bytes,
            "source_growth_deferred_bytes": growth_deferred,
            "source_snapshot_consistent": source_snapshot_consistent,
            "scan_complete": scan_complete,
            "scan_elapsed_seconds": round(time.perf_counter() - started, 3),
            "lines_scanned": lines_scanned,
            "json_records_decoded": decoded_lines,
            "scan_strategy": "exact_ipv4_prefilter" if literal_ip else "full_json_parse",
            "warning": "Raw EVE changed or ended before its snapshot was fully read; do not treat a zero count as conclusive." if not source_snapshot_consistent or not scan_complete else None,
        }

    def compare_host_baseline(self, ip: str, current_start: str, current_end: str, baseline_start: str, baseline_end: str, time_basis: str = "either") -> dict[str, Any]:
        current = self.investigate_host(ip, current_start, current_end, time_basis=time_basis, limit=20)
        baseline = self.investigate_host(ip, baseline_start, baseline_end, time_basis=time_basis, limit=20)
        current_peers, baseline_peers = set(current.get("unique_destination_ips", [])), set(baseline.get("unique_destination_ips", []))
        current_dns = {item["name"] for item in current.get("dns_names", [])}
        baseline_dns = {item["name"] for item in baseline.get("dns_names", [])}
        return {
            "target": ip, "current_window": current.get("resolved_window"), "baseline_window": baseline.get("resolved_window"),
            "current_event_count": current.get("total_events", 0), "baseline_event_count": baseline.get("total_events", 0),
            "event_count_delta": current.get("total_events", 0) - baseline.get("total_events", 0),
            "counts_by_type_current": current.get("counts", {}), "counts_by_type_baseline": baseline.get("counts", {}),
            "new_destination_ips": sorted(current_peers - baseline_peers), "previously_seen_destination_ips": sorted(current_peers & baseline_peers),
            "new_dns_names": sorted(current_dns - baseline_dns), "previously_seen_dns_names": sorted(current_dns & baseline_dns),
            "interpretation_note": "New means absent from the selected baseline only; it is not a threat score.",
        }

    def suricata_status(self, progress: Callable[[dict[str, Any]], None] | None = None, full_verify: bool = False) -> dict[str, Any]:
        status: dict[str, Any] = {
            "eve_log": str(self.eve_log), "eve_log_exists": self.eve_log.is_file(), "eve_log_readable": os.access(self.eve_log, os.R_OK),
            "config": str(self.config), "config_exists": self.config.is_file(),
            "timestamp_interpretation": "ISO-8601 offsets honored; naive tool inputs use the local timezone; comparisons use UTC",
            "search_backend": "incremental SQLite index backed by canonical EVE JSON",
        }
        if self.eve_log.is_file():
            stat = self.eve_log.stat()
            sync = self.sync_index(progress=progress, verify="full" if full_verify else "auto", wait=full_verify)
            index_stats = self.index.fast_statistics()
            if full_verify:
                _report_progress(progress, "statistics_start")
                index_stats.update(self.index.statistics(run_integrity=False))
                _report_progress(progress, "statistics_complete", record_count=index_stats.get("record_count", 0), event_type_count=len(index_stats.get("event_types_present", {})))
            status.update(index_stats)
            status.update({
                "eve_log_bytes": stat.st_size,
                "eve_log_mtime": datetime.fromtimestamp(stat.st_mtime, timezone.utc).isoformat(),
                "index_sync": sync,
                "index_lag_bytes": max(0, stat.st_size - int(sync.get("indexed_offset", 0))),
                "duplicate_event_detection": self.index.duplicate_statistics(),
            })
            last_time = _parse_time(index_stats.get("last_event_timestamp"))
            latest = self.index.latest_record()
            if last_time:
                age = (datetime.now(timezone.utc) - last_time).total_seconds()
                status.update({
                    "eve_stale": age > 300,
                    "last_event_age_seconds": max(0, int(age)),
                    "last_event_file_offset": latest["file_offset"] if latest else None,
                    "last_event_record_id": latest["id"] if latest else None,
                })
            engine_row = self.index.latest_event_of_type("engine")
            if engine_row:
                engine_event = json.loads(engine_row["raw_json"])
                engine = engine_event.get("engine") if isinstance(engine_event.get("engine"), dict) else {}
                if engine.get("version"):
                    status["suricata_version"] = engine["version"]
        if self.config.is_file():
            text = self.config.read_text(errors="replace")
            sections = re.findall(r"(?ms)^af-packet:\s*(.*?)(?=^[A-Za-z][^ \n]*:|\Z)", text)
            status["capture_interfaces"] = list(dict.fromkeys(interface for section in sections for interface in re.findall(r"^\s*- interface:\s*(\S+)", section, re.MULTILINE) if interface != "default"))
            match = re.search(r"^default-rule-path:\s*(\S+)", text, re.MULTILINE)
            if match:
                rule_path = Path(match.group(1))
                status["rule_path"] = str(rule_path)
                rule_file = rule_path / "suricata.rules"
                if rule_file.is_file():
                    status["managed_rules_bytes"] = rule_file.stat().st_size
                    with rule_file.open(errors="ignore") as stream:
                        status["managed_rule_lines"] = sum(1 for _ in stream)
        return status

    def get_sensor_status(self) -> dict[str, Any]:
        return self.suricata_status()

    def tool_registry(self) -> dict[str, Any]:
        return {
            "suricata_status": self.suricata_status, "get_sensor_status": self.get_sensor_status,
            "search_events": self.search_events, "search_alerts": self.search_alerts,
            "investigate_host": self.investigate_host, "investigate_pair": self.investigate_pair,
            "investigate_service": self.investigate_service, "events_around": self.events_around,
            "correlate_flow": self.correlate_flow, "get_flow": self.get_flow, "get_event": self.get_event,
            "search_related_events": self.search_related_events, "count_raw_eve_matches": self.count_raw_eve_matches,
            "compare_host_baseline": self.compare_host_baseline,
        }
