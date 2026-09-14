"""Bounded, read-only tools for local Suricata EVE JSON investigations."""

from __future__ import annotations

import json
import os
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any


DEFAULT_EVE_LOG = Path("/var/log/suricata/eve.json")
DEFAULT_CONFIG = Path("/etc/suricata/suricata.yaml")
MAX_RESULTS = 50
MAX_SCAN_BYTES = 256 * 1024 * 1024


def _parse_time(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def _event_time(event: dict[str, Any]) -> datetime | None:
    return _parse_time(event.get("timestamp"))


def _bounded_limit(limit: int) -> int:
    return max(1, min(int(limit), MAX_RESULTS))


def _iter_events(path: Path, scan_bytes: int | None = MAX_SCAN_BYTES):
    """Yield JSONL events from the tail, or the full EVE file when requested."""
    with path.open("rb") as stream:
        size = stream.seek(0, os.SEEK_END)
        stream.seek(0 if scan_bytes is None else max(0, size - scan_bytes))
        if stream.tell():
            stream.readline()  # discard a partial first line
        for raw in stream:
            try:
                event = json.loads(raw)
            except (UnicodeDecodeError, json.JSONDecodeError):
                continue
            if isinstance(event, dict):
                yield event


def _compact_event(event: dict[str, Any]) -> dict[str, Any]:
    """Keep investigation-relevant fields while retaining event identity."""
    result = {
        key: event.get(key)
        for key in (
            "timestamp", "event_type", "event_id", "flow_id", "src_ip",
            "src_port", "dest_ip", "dest_port", "proto", "app_proto",
            "in_iface", "community_id",
        )
        if event.get(key) is not None
    }
    if event.get("event_type") == "alert":
        alert = event.get("alert", {})
        result["alert"] = {
            key: alert.get(key)
            for key in ("signature", "signature_id", "severity", "category", "action")
            if alert.get(key) is not None
        }
    for section in ("dns", "http", "tls", "ssh", "fileinfo"):
        if isinstance(event.get(section), dict):
            result[section] = event[section]
    return result


def _alert_matches_text(event: dict[str, Any], query: str) -> bool:
    """Match alert signatures and DNS names, including ET's spaced domains."""
    needle = query.strip().lower()
    if not needle:
        return True

    alert = event.get("alert", {})
    signature = str(alert.get("signature", "")).lower()
    if needle in signature or needle in re.sub(r"\s+", "", signature):
        return True

    dns = event.get("dns", {})
    for query_record in dns.get("queries", []) if isinstance(dns, dict) else []:
        if not isinstance(query_record, dict):
            continue
        name = str(query_record.get("rrname", "")).lower()
        if needle in name or needle in re.sub(r"\s+", "", name):
            return True
    return False


class SuricataTools:
    """Read-only local Suricata evidence provider."""

    def __init__(self, eve_log: Path = DEFAULT_EVE_LOG, config: Path = DEFAULT_CONFIG):
        self.eve_log = Path(eve_log).expanduser()
        self.config = Path(config).expanduser()

    def get_sensor_status(self) -> dict[str, Any]:
        """Return Suricata version, capture interfaces, rules, and log status."""
        status: dict[str, Any] = {
            "eve_log": str(self.eve_log),
            "eve_log_exists": self.eve_log.is_file(),
            "config": str(self.config),
            "config_exists": self.config.is_file(),
        }
        if self.eve_log.is_file():
            stat = self.eve_log.stat()
            status.update({"eve_log_bytes": stat.st_size, "eve_log_mtime": datetime.fromtimestamp(stat.st_mtime, timezone.utc).isoformat()})
        if self.config.is_file():
            text = self.config.read_text(errors="replace")
            af_packet_sections = re.findall(
                r"(?ms)^af-packet:\s*(.*?)(?=^[A-Za-z][^ \n]*:|\Z)", text
            )
            interfaces = [
                interface
                for section in af_packet_sections
                for interface in re.findall(
                    r"^\s*- interface:\s*(\S+)", section, re.MULTILINE
                )
                if interface != "default"
            ]
            status["capture_interfaces"] = list(dict.fromkeys(interfaces))
            match = re.search(r"^default-rule-path:\s*(\S+)", text, re.MULTILINE)
            if match:
                rule_path = Path(match.group(1))
                status["rule_path"] = str(rule_path)
                rule_file = rule_path / "suricata.rules"
                if rule_file.is_file():
                    status["managed_rules_bytes"] = rule_file.stat().st_size
                    status["managed_rule_lines"] = sum(1 for _ in rule_file.open(errors="ignore"))
        return status

    def search_alerts(
        self,
        src_ip: str = "",
        dest_ip: str = "",
        signature: str = "",
        sid: int = 0,
        severity: int = 0,
        lookback_hours: int = 24,
        limit: int = 20,
        all_history: bool = False,
    ) -> dict[str, Any]:
        """Find alert events by signature or nested DNS name."""
        if not self.eve_log.is_file():
            return {"error": f"EVE log is unavailable: {self.eve_log}"}
        cutoff = None if all_history else datetime.now(timezone.utc) - timedelta(hours=max(1, min(lookback_hours, 24 * 30)))
        matches = []
        scanned = 0
        for event in _iter_events(self.eve_log, scan_bytes=None if all_history else MAX_SCAN_BYTES):
            scanned += 1
            if event.get("event_type") != "alert":
                continue
            when = _event_time(event)
            if cutoff and when and when < cutoff:
                continue
            alert = event.get("alert", {})
            if src_ip and event.get("src_ip") != src_ip:
                continue
            if dest_ip and event.get("dest_ip") != dest_ip:
                continue
            if signature and not _alert_matches_text(event, signature):
                continue
            if sid and int(alert.get("signature_id", 0)) != sid:
                continue
            if severity and int(alert.get("severity", 0)) != severity:
                continue
            matches.append(_compact_event(event))
            if len(matches) >= _bounded_limit(limit):
                break
        return {"count": len(matches), "scanned_events": scanned, "truncated": len(matches) >= _bounded_limit(limit), "results": matches}

    def get_event(self, event_id: str = "", flow_id: int = 0) -> dict[str, Any]:
        """Retrieve one EVE event by event_id or exact flow_id."""
        if not self.eve_log.is_file():
            return {"error": f"EVE log is unavailable: {self.eve_log}"}

        requested_flow_id = int(flow_id or 0)
        if not requested_flow_id and str(event_id).isdigit():
            # Some Suricata alert records expose flow_id but no event_id. Keep
            # the chain safe if a model passes that numeric value as event_id.
            requested_flow_id = int(event_id)
        for event in _iter_events(self.eve_log):
            if event_id and event.get("event_id") == event_id:
                return _compact_event(event)
            if requested_flow_id and event.get("flow_id") == requested_flow_id:
                return _compact_event(event)
        identifier = f"flow_id={requested_flow_id}" if requested_flow_id else f"event_id={event_id}"
        return {"error": f"Event not found in the bounded EVE window: {identifier}"}

    def search_related_events(
        self,
        src_ip: str = "",
        dest_ip: str = "",
        flow_id: int = 0,
        lookback_minutes: int = 15,
        limit: int = 30,
        all_history: bool = False,
    ) -> dict[str, Any]:
        """Find nearby events; use all_history for an explicit full-file search."""
        if not self.eve_log.is_file():
            return {"error": f"EVE log is unavailable: {self.eve_log}"}
        # An exact flow ID is a strong correlation key. Do not discard its
        # records merely because they are older than the wall-clock window.
        cutoff = None if all_history or flow_id else datetime.now(timezone.utc) - timedelta(minutes=max(1, min(lookback_minutes, 1440)))
        matches = []
        for event in _iter_events(self.eve_log, scan_bytes=None if all_history else MAX_SCAN_BYTES):
            when = _event_time(event)
            if cutoff and when and when < cutoff:
                continue
            same_flow = flow_id and event.get("flow_id") == flow_id
            same_pair = src_ip and dest_ip and event.get("src_ip") == src_ip and event.get("dest_ip") == dest_ip
            if same_flow or same_pair:
                matches.append(_compact_event(event))
                if len(matches) >= _bounded_limit(limit):
                    break
        return {"count": len(matches), "truncated": len(matches) >= _bounded_limit(limit), "results": matches}

    def tool_registry(self) -> dict[str, Any]:
        return {
            "get_sensor_status": self.get_sensor_status,
            "search_alerts": self.search_alerts,
            "get_event": self.get_event,
            "search_related_events": self.search_related_events,
        }
