"""Incremental SQLite index for canonical Suricata EVE JSON evidence."""

from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
import stat as stat_module
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterator

from .agent_config import source_access_error


SCHEMA_VERSION = 1
FULL_VERIFY_INTERVAL_HOURS = 24
FULL_VERIFY_RECORD_GROWTH = 250_000
ProgressCallback = Callable[[dict[str, Any]], None]


def _notify(progress: ProgressCallback | None, stage: str, **details: Any) -> None:
    if progress is None:
        return
    try:
        progress({"stage": stage, **details})
    except Exception:
        # Reporting must never compromise evidence ingestion.
        pass


def default_index_path(eve_path: Path) -> Path:
    cache_root = Path(os.environ.get("XDG_CACHE_HOME", Path.home() / ".cache"))
    identity = hashlib.sha256(str(eve_path.expanduser().resolve()).encode()).hexdigest()[:16]
    return cache_root / "suricata-agent" / f"eve-{identity}.sqlite3"


def _parse_time(value: Any) -> str | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=datetime.now().astimezone().tzinfo)
    return parsed.astimezone(timezone.utc).isoformat()


def _dns_values(event: dict[str, Any]) -> tuple[list[str], list[str]]:
    dns = event.get("dns")
    if not isinstance(dns, dict):
        dns = event.get("mdns")
    if not isinstance(dns, dict):
        return [], []
    names: list[str] = []
    if isinstance(dns.get("queries"), list):
        for query in dns["queries"]:
            if isinstance(query, dict) and isinstance(query.get("rrname"), str):
                names.append(query["rrname"].rstrip("."))
    nested = dns.get("query") if isinstance(dns.get("query"), dict) else {}
    for value in (dns.get("rrname"), nested.get("rrname")):
        if isinstance(value, str):
            names.append(value.rstrip("."))
    answers: list[str] = []
    if isinstance(dns.get("answers"), list):
        for answer in dns["answers"]:
            if isinstance(answer, dict):
                value = answer.get("rdata") or answer.get("data")
                if value is not None:
                    answers.append(str(value).rstrip("."))
    return list(dict.fromkeys(filter(None, names))), list(dict.fromkeys(filter(None, answers)))


def _activity_time(*values: str | None) -> str | None:
    present = [value for value in values if value]
    return min(present) if present else None


def _like(value: str, *, suffix: bool = False) -> str:
    escaped = str(value).lower().replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return f"%{escaped}" if suffix else f"%{escaped}%"


class EveIndex:
    """Persistent append-only index with source-generation provenance."""

    def __init__(self, path: Path | str, *, session_owner: bool = True):
        self.path = Path(path).expanduser() if str(path) != ":memory:" else Path(":memory:")
        self.session_owner = session_owner
        if str(self.path) != ":memory:":
            self._prepare_index_path(self.path)
        self.connection = sqlite3.connect(str(self.path), timeout=30, check_same_thread=False)
        self.connection.row_factory = sqlite3.Row
        self.connection.execute("PRAGMA journal_mode=WAL")
        self.connection.execute("PRAGMA synchronous=NORMAL")
        self.connection.execute("PRAGMA temp_store=MEMORY")
        self._create_schema()
        health = self.connection.execute("SELECT * FROM index_health WHERE id=1").fetchone()
        self.was_clean_shutdown = bool(health and health["clean_shutdown"])
        if self.session_owner:
            self.connection.execute(
                "UPDATE index_health SET clean_shutdown=0, opened_at=? WHERE id=1",
                (datetime.now(timezone.utc).isoformat(),),
            )
            self.connection.commit()
        if str(self.path) != ":memory:":
            self._lock_permissions()

    def _create_schema(self) -> None:
        self.connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS metadata (
                source_path TEXT PRIMARY KEY,
                source_dev INTEGER NOT NULL,
                source_inode INTEGER NOT NULL,
                generation INTEGER NOT NULL,
                indexed_offset INTEGER NOT NULL,
                observed_size INTEGER NOT NULL,
                observed_mtime_ns INTEGER NOT NULL,
                head_hash TEXT,
                head_length INTEGER NOT NULL DEFAULT 0,
                checkpoint_hash TEXT,
                malformed_lines INTEGER NOT NULL DEFAULT 0,
                updated_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS index_health (
                id INTEGER PRIMARY KEY CHECK(id=1),
                clean_shutdown INTEGER NOT NULL DEFAULT 1,
                opened_at TEXT,
                closed_at TEXT,
                last_full_check_at TEXT,
                last_full_check_result TEXT,
                last_full_check_record_id INTEGER NOT NULL DEFAULT 0,
                last_full_check_page_count INTEGER NOT NULL DEFAULT 0,
                last_full_check_error TEXT
            );
            INSERT OR IGNORE INTO index_health(id, clean_shutdown) VALUES(1, 1);
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY,
                source_path TEXT NOT NULL,
                source_dev INTEGER NOT NULL,
                source_inode INTEGER NOT NULL,
                generation INTEGER NOT NULL,
                file_offset INTEGER NOT NULL,
                line_length INTEGER NOT NULL,
                event_ts TEXT,
                flow_start TEXT,
                flow_end TEXT,
                activity_ts TEXT,
                event_type TEXT,
                event_id TEXT,
                flow_id INTEGER,
                src_ip TEXT,
                dest_ip TEXT,
                src_port INTEGER,
                dest_port INTEGER,
                proto TEXT,
                app_proto TEXT,
                signature TEXT,
                signature_compact TEXT,
                signature_id INTEGER,
                severity INTEGER,
                dns_names TEXT,
                dns_answers TEXT,
                tls_sni TEXT,
                http_host TEXT,
                http_url TEXT,
                raw_json TEXT NOT NULL,
                UNIQUE(source_path, generation, file_offset)
            );
            CREATE INDEX IF NOT EXISTS idx_events_activity ON events(activity_ts, id);
            CREATE INDEX IF NOT EXISTS idx_events_event_ts ON events(event_ts);
            CREATE INDEX IF NOT EXISTS idx_events_flow_start ON events(flow_start);
            CREATE INDEX IF NOT EXISTS idx_events_flow_end ON events(flow_end);
            CREATE INDEX IF NOT EXISTS idx_events_src_ip ON events(src_ip, activity_ts);
            CREATE INDEX IF NOT EXISTS idx_events_dest_ip ON events(dest_ip, activity_ts);
            CREATE INDEX IF NOT EXISTS idx_events_flow_id ON events(flow_id);
            CREATE INDEX IF NOT EXISTS idx_events_type ON events(event_type, activity_ts);
            CREATE INDEX IF NOT EXISTS idx_events_dest_port ON events(dest_port, activity_ts);
            PRAGMA user_version = 1;
            """
        )
        version = self.connection.execute("PRAGMA user_version").fetchone()[0]
        if version != SCHEMA_VERSION:
            raise RuntimeError(f"Unsupported EVE index schema {version}; expected {SCHEMA_VERSION}")
        columns = {row[1] for row in self.connection.execute("PRAGMA table_info(metadata)")}
        if "head_hash" not in columns:
            self.connection.execute("ALTER TABLE metadata ADD COLUMN head_hash TEXT")
            self.connection.commit()
        if "head_length" not in columns:
            self.connection.execute("ALTER TABLE metadata ADD COLUMN head_length INTEGER NOT NULL DEFAULT 0")
            self.connection.commit()
        if "checkpoint_hash" not in columns:
            self.connection.execute("ALTER TABLE metadata ADD COLUMN checkpoint_hash TEXT")
            self.connection.commit()

    @staticmethod
    def _prepare_index_path(path: Path) -> None:
        """Reject unsafe paths before SQLite can read or create evidence files."""
        path = Path(os.path.abspath(path))
        for directory in reversed((path.parent, *path.parent.parents)):
            if directory.is_symlink():
                raise PermissionError(f"Index path contains a symbolic link: {directory}")
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        parent = path.parent.lstat()
        if not stat_module.S_ISDIR(parent.st_mode) or parent.st_uid != os.getuid() or parent.st_mode & 0o077:
            raise PermissionError(f"Index directory must be owned by this user and mode 0700: {path.parent}")
        for candidate in (path, Path(f"{path}-wal"), Path(f"{path}-shm"), Path(f"{path}-journal")):
            try:
                info = candidate.lstat()
            except FileNotFoundError:
                continue
            if not stat_module.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
                raise PermissionError(f"Index file must be a regular owner-only file: {candidate}")
        if not path.exists():
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            try:
                descriptor = os.open(path, flags, 0o600)
            except FileExistsError:
                raise PermissionError(f"Index path changed while opening: {path}") from None
            else:
                os.close(descriptor)

    def _lock_permissions(self) -> None:
        if str(self.path) != ":memory:":
            self._prepare_index_path(self.path)

    @staticmethod
    def _head_hash(path: Path, length: int) -> str:
        try:
            with path.open("rb") as stream:
                return hashlib.sha256(stream.read(length)).hexdigest()
        except PermissionError as exc:
            raise source_access_error(path, exc) from exc

    @staticmethod
    def _checkpoint_hash(path: Path, end_offset: int) -> str:
        start = max(0, end_offset - 4096)
        try:
            with path.open("rb") as stream:
                stream.seek(start)
                return hashlib.sha256(stream.read(end_offset - start)).hexdigest()
        except PermissionError as exc:
            raise source_access_error(path, exc) from exc

    def close(self, clean: bool = True) -> None:
        if clean and self.session_owner:
            self.connection.execute(
                "UPDATE index_health SET clean_shutdown=1, closed_at=? WHERE id=1",
                (datetime.now(timezone.utc).isoformat(),),
            )
            self.connection.commit()
        self.connection.close()

    @staticmethod
    def _row_values(event: dict[str, Any], source_path: str, stat: os.stat_result, generation: int, offset: int, line_length: int, raw_json: str) -> tuple[Any, ...]:
        flow = event.get("flow") if isinstance(event.get("flow"), dict) else {}
        alert = event.get("alert") if isinstance(event.get("alert"), dict) else {}
        tls = event.get("tls") if isinstance(event.get("tls"), dict) else {}
        http = event.get("http") if isinstance(event.get("http"), dict) else {}
        event_ts = _parse_time(event.get("timestamp"))
        flow_start = _parse_time(flow.get("start"))
        flow_end = _parse_time(flow.get("end"))
        names, answers = _dns_values(event)
        signature = str(alert.get("signature", "")) or None
        return (
            source_path, stat.st_dev, stat.st_ino, generation, offset, line_length,
            event_ts, flow_start, flow_end, _activity_time(event_ts, flow_start, flow_end),
            event.get("event_type"), str(event.get("event_id")) if event.get("event_id") is not None else None,
            event.get("flow_id"), event.get("src_ip"), event.get("dest_ip"),
            event.get("src_port"), event.get("dest_port"), event.get("proto"), event.get("app_proto"),
            signature, re.sub(r"\s+", "", signature.lower()) if signature else None,
            alert.get("signature_id"), alert.get("severity"),
            json.dumps(names, separators=(",", ":")), json.dumps(answers, separators=(",", ":")),
            tls.get("sni"), http.get("hostname"), http.get("url"), raw_json,
        )

    def _ingest(self, file_path: Path, canonical_path: str, generation: int, start_offset: int, progress: ProgressCallback | None = None, source_kind: str = "current") -> tuple[int, int, int]:
        stat = file_path.stat()
        snapshot_size = stat.st_size
        inserted = malformed = 0
        lines_processed = 0
        offset = start_offset
        sql = """
            INSERT OR IGNORE INTO events (
                source_path, source_dev, source_inode, generation, file_offset, line_length,
                event_ts, flow_start, flow_end, activity_ts, event_type, event_id, flow_id,
                src_ip, dest_ip, src_port, dest_port, proto, app_proto, signature,
                signature_compact, signature_id, severity, dns_names, dns_answers,
                tls_sni, http_host, http_url, raw_json
            ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        """
        batch: list[tuple[Any, ...]] = []
        try:
            source_stream = file_path.open("rb")
        except PermissionError as exc:
            raise source_access_error(file_path, exc) from exc
        with source_stream as stream:
            stream.seek(start_offset)
            while stream.tell() < snapshot_size:
                line_offset = stream.tell()
                raw = stream.readline(snapshot_size - line_offset)
                if not raw:
                    offset = stream.tell()
                    break
                if not raw.endswith(b"\n"):
                    offset = line_offset
                    break
                offset = stream.tell()
                lines_processed += 1
                try:
                    event = json.loads(raw)
                except (UnicodeDecodeError, json.JSONDecodeError):
                    malformed += 1
                    if lines_processed % 1000 == 0:
                        _notify(progress, "ingest_progress", source_kind=source_kind, source_path=str(file_path), indexed_offset=offset, source_size=snapshot_size, records_inserted=inserted, malformed_lines=malformed)
                    continue
                if not isinstance(event, dict):
                    malformed += 1
                    if lines_processed % 1000 == 0:
                        _notify(progress, "ingest_progress", source_kind=source_kind, source_path=str(file_path), indexed_offset=offset, source_size=snapshot_size, records_inserted=inserted, malformed_lines=malformed)
                    continue
                raw_json = raw.decode("utf-8").rstrip("\r\n")
                batch.append(self._row_values(event, canonical_path, stat, generation, line_offset, len(raw), raw_json))
                if len(batch) >= 1000:
                    before = self.connection.total_changes
                    self.connection.executemany(sql, batch)
                    inserted += self.connection.total_changes - before
                    batch.clear()
                if lines_processed % 1000 == 0:
                    _notify(progress, "ingest_progress", source_kind=source_kind, source_path=str(file_path), indexed_offset=offset, source_size=snapshot_size, records_inserted=inserted, malformed_lines=malformed)
        if batch:
            before = self.connection.total_changes
            self.connection.executemany(sql, batch)
            inserted += self.connection.total_changes - before
        _notify(progress, "ingest_progress", source_kind=source_kind, source_path=str(file_path), indexed_offset=offset, source_size=snapshot_size, records_inserted=inserted, malformed_lines=malformed, complete=offset >= snapshot_size)
        return offset, inserted, malformed

    def _find_rotated_inode(self, eve_path: Path, dev: int, inode: int) -> Path | None:
        for candidate in eve_path.parent.glob(f"{eve_path.name}.*"):
            try:
                stat = candidate.stat()
            except OSError:
                continue
            if candidate.is_file() and stat.st_dev == dev and stat.st_ino == inode:
                return candidate
        return None

    def sync(self, eve_path: Path, progress: ProgressCallback | None = None) -> dict[str, Any]:
        try:
            eve_path = eve_path.expanduser().resolve()
        except PermissionError as exc:
            raise source_access_error(eve_path, exc) from exc
        canonical = str(eve_path)
        _notify(progress, "source_check", source_path=canonical)
        try:
            source_stat = eve_path.stat()
        except FileNotFoundError:
            _notify(progress, "source_error", source_path=canonical, error="not a readable regular file")
            return {"error": f"EVE log is unavailable: {eve_path}", "inserted": 0}
        except PermissionError as exc:
            raise source_access_error(eve_path, exc) from exc
        if not stat_module.S_ISREG(source_stat.st_mode):
            _notify(progress, "source_error", source_path=canonical, error="not a readable regular file")
            return {"error": f"EVE log is not a regular file: {eve_path}", "inserted": 0}
        stat = source_stat
        meta = self.connection.execute("SELECT * FROM metadata WHERE source_path=?", (canonical,)).fetchone()
        generation = int(meta["generation"]) if meta else 1
        start_offset = int(meta["indexed_offset"]) if meta else 0
        malformed = int(meta["malformed_lines"]) if meta else 0
        head_length = int(meta["head_length"]) if meta else min(stat.st_size, 4096)
        head_hash = self._head_hash(eve_path, head_length)
        checkpoint_changed = bool(
            meta
            and start_offset
            and stat.st_size >= start_offset
            and meta["checkpoint_hash"]
            and meta["checkpoint_hash"] != self._checkpoint_hash(eve_path, start_offset)
        )
        rotation_completed = 0
        rotation_detected = False
        source_reset_detected = False
        _notify(progress, "source_ready", source_path=canonical, source_size=stat.st_size, existing_index=bool(meta), indexed_offset=start_offset, generation=generation)

        if meta and (meta["source_dev"] != stat.st_dev or meta["source_inode"] != stat.st_ino):
            rotation_detected = True
            rotated = self._find_rotated_inode(eve_path, int(meta["source_dev"]), int(meta["source_inode"]))
            _notify(progress, "rotation_detected", source_path=canonical, rotated_path=str(rotated) if rotated else None, prior_generation=generation)
            if rotated:
                _, rotation_completed, extra_malformed = self._ingest(rotated, canonical, generation, start_offset, progress, "rotated")
                malformed += extra_malformed
            generation += 1
            start_offset = 0
            head_length = min(stat.st_size, 4096)
            head_hash = self._head_hash(eve_path, head_length)
        elif meta and (stat.st_size < start_offset or checkpoint_changed or (head_length and meta["head_hash"] and meta["head_hash"] != head_hash)):
            source_reset_detected = True
            _notify(progress, "source_reset_detected", source_path=canonical, prior_generation=generation, prior_offset=start_offset, source_size=stat.st_size, checkpoint_changed=checkpoint_changed)
            generation += 1
            start_offset = 0
            head_length = min(stat.st_size, 4096)
            head_hash = self._head_hash(eve_path, head_length)
        elif not head_length and stat.st_size:
            head_length = min(stat.st_size, 4096)
            head_hash = self._head_hash(eve_path, head_length)

        current_start_offset = start_offset
        indexed_offset, inserted, extra_malformed = self._ingest(eve_path, canonical, generation, start_offset, progress, "current")
        malformed += extra_malformed
        checkpoint_hash = self._checkpoint_hash(eve_path, indexed_offset)
        self.connection.execute(
            """
            INSERT INTO metadata(source_path, source_dev, source_inode, generation, indexed_offset,
                                 observed_size, observed_mtime_ns, head_hash, head_length,
                                 checkpoint_hash, malformed_lines, updated_at)
            VALUES(?,?,?,?,?,?,?,?,?,?,?,?)
            ON CONFLICT(source_path) DO UPDATE SET
                source_dev=excluded.source_dev, source_inode=excluded.source_inode,
                generation=excluded.generation, indexed_offset=excluded.indexed_offset,
                observed_size=excluded.observed_size, observed_mtime_ns=excluded.observed_mtime_ns,
                head_hash=excluded.head_hash, head_length=excluded.head_length,
                checkpoint_hash=excluded.checkpoint_hash,
                malformed_lines=excluded.malformed_lines,
                updated_at=excluded.updated_at
            """,
            (canonical, stat.st_dev, stat.st_ino, generation, indexed_offset, stat.st_size, stat.st_mtime_ns, head_hash, head_length, checkpoint_hash, malformed, datetime.now(timezone.utc).isoformat()),
        )
        self.connection.commit()
        self._lock_permissions()
        result = {
            "source_path": canonical,
            "generation": generation,
            "indexed_offset": indexed_offset,
            "observed_size": stat.st_size,
            "bytes_indexed_this_sync": max(0, indexed_offset - current_start_offset),
            "inserted": inserted + rotation_completed,
            "rotation_records_completed": rotation_completed,
            "rotation_detected": rotation_detected,
            "source_reset_detected": source_reset_detected,
            "malformed_lines": malformed,
            "partial_line_pending": indexed_offset < stat.st_size,
        }
        _notify(progress, "sync_complete", **result)
        return result

    @staticmethod
    def _where(filters: dict[str, Any], start: str | None, end: str | None, time_basis: str) -> tuple[str, list[Any]]:
        clauses: list[str] = []
        params: list[Any] = []

        def add(clause: str, *values: Any) -> None:
            clauses.append(clause)
            params.extend(values)

        src_ip, dest_ip, either_ip = filters.get("src_ip", ""), filters.get("dest_ip", ""), filters.get("either_ip", "")
        if src_ip:
            if str(src_ip).startswith("."):
                add("lower(src_ip) LIKE ? ESCAPE '\\'", _like(src_ip, suffix=True))
            else:
                add("src_ip=?", str(src_ip))
        if dest_ip:
            if str(dest_ip).startswith("."):
                add("lower(dest_ip) LIKE ? ESCAPE '\\'", _like(dest_ip, suffix=True))
            else:
                add("dest_ip=?", str(dest_ip))
        if either_ip:
            shorthand = str(either_ip).startswith(".")
            pattern = _like(either_ip, suffix=True) if shorthand else str(either_ip)
            operator = "LIKE ? ESCAPE '\\'" if shorthand else "=?"
            direction = str(filters.get("direction", "either")).lower()
            if direction in {"outbound", "source", "src"}:
                add(f"{'lower(src_ip)' if shorthand else 'src_ip'} {operator}", pattern)
            elif direction in {"inbound", "destination", "dest"}:
                add(f"{'lower(dest_ip)' if shorthand else 'dest_ip'} {operator}", pattern)
            else:
                src_field = "lower(src_ip)" if shorthand else "src_ip"
                dest_field = "lower(dest_ip)" if shorthand else "dest_ip"
                add(f"({src_field} {operator} OR {dest_field} {operator})", pattern, pattern)
        if filters.get("pair"):
            ip1, ip2 = filters["pair"]
            add("((src_ip=? AND dest_ip=?) OR (src_ip=? AND dest_ip=?))", ip1, ip2, ip2, ip1)
        if filters.get("_snapshot_max_id"):
            add("id<=?", int(filters["_snapshot_max_id"]))
        for field in ("src_port", "dest_port"):
            if filters.get(field):
                add(f"{field}=?", int(filters[field]))
        if filters.get("either_port"):
            add("(src_port=? OR dest_port=?)", int(filters["either_port"]), int(filters["either_port"]))
        for field in ("proto", "app_proto"):
            if filters.get(field):
                add(f"lower({field})=?", str(filters[field]).lower())
        event_types = filters.get("event_types") or []
        if isinstance(event_types, str):
            event_types = [item.strip() for item in event_types.split(",") if item.strip()]
        if event_types:
            placeholders = ",".join("?" for _ in event_types)
            add(f"lower(event_type) IN ({placeholders})", *(str(item).lower() for item in event_types))
        for field in ("flow_id", "signature_id", "severity"):
            if filters.get(field):
                add(f"{field}=?", int(filters[field]))
        if filters.get("signature"):
            needle = str(filters["signature"]).lower()
            add("(lower(signature) LIKE ? ESCAPE '\\' OR signature_compact LIKE ? ESCAPE '\\')", _like(needle), _like(re.sub(r"\s+", "", needle)))
        if filters.get("dns_name"):
            add("lower(dns_names) LIKE ? ESCAPE '\\'", _like(filters["dns_name"]))
        if filters.get("sni"):
            add("lower(tls_sni) LIKE ? ESCAPE '\\'", _like(filters["sni"]))
        if filters.get("http_host"):
            add("lower(http_host) LIKE ? ESCAPE '\\'", _like(filters["http_host"]))
        if filters.get("http_url"):
            add("lower(http_url) LIKE ? ESCAPE '\\'", _like(filters["http_url"]))
        if filters.get("hostname"):
            pattern = _like(filters["hostname"])
            add("(lower(dns_names) LIKE ? ESCAPE '\\' OR lower(tls_sni) LIKE ? ESCAPE '\\' OR lower(http_host) LIKE ? ESCAPE '\\')", pattern, pattern, pattern)
        if filters.get("free_text"):
            add("lower(raw_json) LIKE ? ESCAPE '\\'", _like(filters["free_text"]))
        if start or end:
            def bounds(field: str) -> tuple[str, list[Any]]:
                if start and end:
                    return f"({field}>=? AND {field}<=?)", [start, end]
                if start:
                    return f"{field}>=?", [start]
                return f"{field}<=?", [end]
            time_fields = ["event_ts"] if time_basis == "event" else ["flow_start", "flow_end"] if time_basis == "flow" else ["event_ts", "flow_start", "flow_end"]
            pieces, values = [], []
            for field in time_fields:
                clause, bound_values = bounds(field)
                pieces.append(clause)
                values.extend(bound_values)
            add(f"({' OR '.join(pieces)})", *values)
        return (" WHERE " + " AND ".join(clauses)) if clauses else "", params

    def count_events(self, filters: dict[str, Any], start: str | None, end: str | None, time_basis: str) -> int:
        """Return only a match count without running aggregate or page queries."""
        where, params = self._where(filters, start, end, time_basis)
        return int(self.connection.execute(f"SELECT count(*) FROM events{where}", params).fetchone()[0])

    def search(self, filters: dict[str, Any], start: str | None, end: str | None, time_basis: str, limit: int, offset: int, sort: str) -> dict[str, Any]:
        where, params = self._where(filters, start, end, time_basis)
        total = self.connection.execute(f"SELECT count(*) FROM events{where}", params).fetchone()[0]
        counts = dict(self.connection.execute(f"SELECT coalesce(event_type, 'unknown'), count(*) FROM events{where} GROUP BY event_type ORDER BY count(*) DESC", params).fetchall())
        direction = "DESC" if str(sort).lower() == "desc" else "ASC"
        rows = self.connection.execute(
            f"SELECT * FROM events{where} ORDER BY coalesce(activity_ts, event_ts, '') {direction}, id {direction} LIMIT ? OFFSET ?",
            [*params, limit, offset],
        ).fetchall()
        return {"total": total, "counts": counts, "rows": rows}

    def search_rows(self, filters: dict[str, Any], start: str | None, end: str | None, time_basis: str, limit: int, offset: int, sort: str) -> list[sqlite3.Row]:
        """Return a raw page without repeating total and aggregate queries."""
        where, params = self._where(filters, start, end, time_basis)
        direction = "DESC" if str(sort).lower() == "desc" else "ASC"
        return self.connection.execute(
            f"SELECT * FROM events{where} ORDER BY coalesce(activity_ts, event_ts, '') {direction}, id {direction} LIMIT ? OFFSET ?",
            [*params, limit, offset],
        ).fetchall()

    def iter_events(self, filters: dict[str, Any], start: str | None, end: str | None, time_basis: str, batch_size: int = 1000) -> Iterator[sqlite3.Row]:
        where, params = self._where(filters, start, end, time_basis)
        cursor = self.connection.execute(f"SELECT * FROM events{where} ORDER BY coalesce(activity_ts, event_ts, ''), id", params)
        while rows := cursor.fetchmany(batch_size):
            yield from rows

    def get_event(self, *, record_id: int = 0, event_id: str = "", flow_id: int = 0, file_offset: int = -1) -> sqlite3.Row | None:
        if record_id:
            return self.connection.execute("SELECT * FROM events WHERE id=?", (record_id,)).fetchone()
        if event_id:
            row = self.connection.execute("SELECT * FROM events WHERE event_id=? ORDER BY id DESC LIMIT 1", (str(event_id),)).fetchone()
            if row:
                return row
        if flow_id:
            return self.connection.execute("SELECT * FROM events WHERE flow_id=? ORDER BY id LIMIT 1", (int(flow_id),)).fetchone()
        if file_offset >= 0:
            return self.connection.execute("SELECT * FROM events WHERE file_offset=? ORDER BY generation DESC, id DESC LIMIT 1", (file_offset,)).fetchone()
        return None

    @staticmethod
    def _verification_snapshot(connection: sqlite3.Connection) -> dict[str, Any]:
        integrity = connection.execute("PRAGMA quick_check").fetchone()[0]
        record_id = int(connection.execute("SELECT coalesce(max(id), 0) FROM events").fetchone()[0])
        page_count = int(connection.execute("PRAGMA page_count").fetchone()[0])
        page_size = int(connection.execute("PRAGMA page_size").fetchone()[0])
        return {
            "index_integrity": integrity,
            "record_count": record_id,
            "verified_record_id": record_id,
            "verified_page_count": page_count,
            "index_database_bytes": page_count * page_size,
            "verified_at": datetime.now(timezone.utc).isoformat(),
        }

    @staticmethod
    def _store_verification(connection: sqlite3.Connection, result: dict[str, Any]) -> None:
        connection.execute(
            """
            UPDATE index_health
            SET last_full_check_at=?, last_full_check_result=?,
                last_full_check_record_id=?, last_full_check_page_count=?,
                last_full_check_error=?
            WHERE id=1
            """,
            (
                result["verified_at"],
                result["index_integrity"],
                result["verified_record_id"],
                result["verified_page_count"],
                None if result["index_integrity"] == "ok" else str(result["index_integrity"]),
            ),
        )
        connection.commit()

    def verify_integrity(self) -> dict[str, Any]:
        result = self._verification_snapshot(self.connection)
        self._store_verification(self.connection, result)
        if result["index_integrity"] == "ok":
            self.was_clean_shutdown = True
        return result

    @staticmethod
    def verify_database(path: Path | str) -> dict[str, Any]:
        """Deep-check a disk index through an independent SQLite connection."""
        path = Path(path).expanduser()
        EveIndex._prepare_index_path(path)
        connection = sqlite3.connect(str(path), timeout=30)
        connection.row_factory = sqlite3.Row
        try:
            result = EveIndex._verification_snapshot(connection)
            EveIndex._store_verification(connection, result)
            return result
        finally:
            connection.close()

    def fast_statistics(self) -> dict[str, Any]:
        health = self.connection.execute("SELECT * FROM index_health WHERE id=1").fetchone()
        record_id = self.max_record_id()
        page_count = int(self.connection.execute("PRAGMA page_count").fetchone()[0])
        page_size = int(self.connection.execute("PRAGMA page_size").fetchone()[0])
        return {
            "record_count": record_id,
            "index_path": str(self.path),
            "index_schema_version": self.connection.execute("PRAGMA user_version").fetchone()[0],
            "index_database_bytes": page_count * page_size,
            "index_integrity": health["last_full_check_result"] or "unverified",
            "last_full_check_at": health["last_full_check_at"],
            "last_full_check_record_id": int(health["last_full_check_record_id"] or 0),
            "last_full_check_page_count": int(health["last_full_check_page_count"] or 0),
            "previous_clean_shutdown": self.was_clean_shutdown,
        }

    def verification_policy(self, force_blocking: bool = False) -> dict[str, Any]:
        stats = self.fast_statistics()
        reasons: list[str] = []
        background_reasons: list[str] = []
        if force_blocking:
            reasons.append("source checkpoint discontinuity")
        if stats["index_integrity"] != "ok" or not stats["last_full_check_at"]:
            reasons.append("index has no successful database-wide verification")
        elif not self.was_clean_shutdown:
            background_reasons.append("previous process did not close the index cleanly; SQLite recovery and EVE synchronization succeeded")
        blocking = bool(reasons)
        age_hours: float | None = None
        if stats["last_full_check_at"]:
            try:
                verified_at = datetime.fromisoformat(str(stats["last_full_check_at"]).replace("Z", "+00:00"))
                age_hours = max(0.0, (datetime.now(timezone.utc) - verified_at.astimezone(timezone.utc)).total_seconds() / 3600)
            except ValueError:
                reasons.append("stored verification timestamp is invalid")
                blocking = True
        record_growth = max(0, int(stats["record_count"]) - int(stats["last_full_check_record_id"]))
        if age_hours is None:
            background_reasons.append("verification age is unavailable")
        elif age_hours >= FULL_VERIFY_INTERVAL_HOURS:
            background_reasons.append(f"last database-wide check is {age_hours:.1f} hours old")
        if record_growth >= FULL_VERIFY_RECORD_GROWTH:
            background_reasons.append(f"{record_growth} records were added since the last database-wide check")
        background_due = not blocking and bool(background_reasons)
        return {
            "blocking_required": blocking,
            "blocking_reasons": reasons,
            "background_due": background_due,
            "background_reasons": background_reasons,
            "verification_age_hours": age_hours,
            "records_since_full_check": record_growth,
            "interval_hours": FULL_VERIFY_INTERVAL_HOURS,
            "record_growth_threshold": FULL_VERIFY_RECORD_GROWTH,
            **stats,
        }

    def statistics(self, run_integrity: bool = True) -> dict[str, Any]:
        total = self.connection.execute("SELECT count(*) FROM events").fetchone()[0]
        first, last = self.connection.execute("SELECT min(event_ts), max(event_ts) FROM events").fetchone()
        counts = dict(self.connection.execute("SELECT coalesce(event_type, 'unknown'), count(*) FROM events GROUP BY event_type ORDER BY count(*) DESC").fetchall())
        generations = self.connection.execute("SELECT count(DISTINCT source_path || ':' || generation) FROM events").fetchone()[0]
        page_count = self.connection.execute("PRAGMA page_count").fetchone()[0]
        page_size = self.connection.execute("PRAGMA page_size").fetchone()[0]
        if run_integrity:
            integrity = self.connection.execute("PRAGMA quick_check").fetchone()[0]
        else:
            health = self.connection.execute("SELECT last_full_check_result FROM index_health WHERE id=1").fetchone()
            integrity = health[0] if health and health[0] else "unverified"
        return {
            "record_count": total,
            "first_event_timestamp": first,
            "last_event_timestamp": last,
            "event_types_present": counts,
            "source_generations": generations,
            "index_path": str(self.path),
            "index_schema_version": self.connection.execute("PRAGMA user_version").fetchone()[0],
            "index_database_bytes": page_count * page_size,
            "index_integrity": integrity,
        }

    def duplicate_statistics(self, sample_size: int = 10000) -> dict[str, int]:
        rows = self.connection.execute("SELECT raw_json FROM events ORDER BY id DESC LIMIT ?", (sample_size,)).fetchall()
        fingerprints = Counter(row["raw_json"] for row in rows)
        return {"sample_size": len(rows), "exact_duplicate_records": sum(count - 1 for count in fingerprints.values() if count > 1)}

    def latest_event_of_type(self, event_type: str) -> sqlite3.Row | None:
        return self.connection.execute("SELECT * FROM events WHERE lower(event_type)=? ORDER BY id DESC LIMIT 1", (event_type.lower(),)).fetchone()

    def latest_record(self) -> sqlite3.Row | None:
        return self.connection.execute("SELECT * FROM events ORDER BY id DESC LIMIT 1").fetchone()

    def max_record_id(self) -> int:
        return int(self.connection.execute("SELECT coalesce(max(id), 0) FROM events").fetchone()[0])

    def distinct_ip_values(self, direction: str = "either") -> list[str]:
        direction = str(direction).lower()
        if direction in {"outbound", "source", "src"}:
            rows = self.connection.execute("SELECT DISTINCT src_ip FROM events WHERE src_ip IS NOT NULL").fetchall()
        elif direction in {"inbound", "destination", "dest"}:
            rows = self.connection.execute("SELECT DISTINCT dest_ip FROM events WHERE dest_ip IS NOT NULL").fetchall()
        else:
            rows = self.connection.execute(
                "SELECT src_ip AS ip FROM events WHERE src_ip IS NOT NULL UNION SELECT dest_ip AS ip FROM events WHERE dest_ip IS NOT NULL"
            ).fetchall()
        return [str(row[0]) for row in rows if row[0]]
