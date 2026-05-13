import importlib.util
from pathlib import Path
from types import SimpleNamespace


VIEWER_PATH = (
    Path(__file__).resolve().parents[1]
    / "/home/prizm/suri_dash_cli/slog.py"
)


def load_viewer():
    spec = importlib.util.spec_from_file_location(
        "suri_log_viewer",
        VIEWER_PATH
    )

    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)

    return mod


def test_pretty_size_bytes():
    mod = load_viewer()

    assert mod.pretty_size(512) == "512.0B"


def test_pretty_size_kilobytes():
    mod = load_viewer()

    assert mod.pretty_size(2048) == "2.0KB"


def test_limit_lines_head():
    mod = load_viewer()

    raw = "a\nb\nc\nd"

    result = mod.limit_lines(
        raw,
        limit=2,
        tail_mode=False
    )

    assert result == "a\nb"


def test_limit_lines_tail():
    mod = load_viewer()

    raw = "a\nb\nc\nd"

    result = mod.limit_lines(
        raw,
        limit=2,
        tail_mode=True
    )

    assert result == "c\nd"


def test_limit_lines_no_limit():
    mod = load_viewer()

    raw = "a\nb\nc"

    result = mod.limit_lines(
        raw,
        limit=0,
        tail_mode=False
    )

    assert result == raw


def test_format_alert_event():
    mod = load_viewer()

    obj = {
        "timestamp": "2026-01-01T12:00:00",
        "event_type": "alert",
        "src_ip": "1.1.1.1",
        "src_port": 1111,
        "dest_ip": "2.2.2.2",
        "dest_port": 80,
        "proto": "TCP",
        "alert": {
            "severity": 1,
            "signature": "Test Alert",
            "category": "Attempted Admin",
            "signature_id": 12345,
        },
    }

    result = mod.format_eve_event(obj)

    assert "ALERT" in result
    assert "Test Alert" in result
    assert "sid=12345" in result


def test_format_dns_event():
    mod = load_viewer()

    obj = {
        "timestamp": "2026-01-01T12:00:00",
        "event_type": "dns",
        "src_ip": "1.1.1.1",
        "dest_ip": "8.8.8.8",
        "dns": {
            "rrname": "example.com",
            "rrtype": "A"
        }
    }

    result = mod.format_eve_event(obj)

    assert "DNS" in result
    assert "example.com" in result


def test_format_http_event():
    mod = load_viewer()

    obj = {
        "timestamp": "2026-01-01T12:00:00",
        "event_type": "http",
        "src_ip": "1.1.1.1",
        "dest_ip": "2.2.2.2",
        "http": {
            "hostname": "example.com",
            "url": "/index.html",
            "http_method": "GET",
            "status": 200,
        }
    }

    result = mod.format_eve_event(obj)

    assert "HTTP" in result
    assert "GET" in result
    assert "example.com/index.html" in result


def test_format_tls_event():
    mod = load_viewer()

    obj = {
        "timestamp": "2026-01-01T12:00:00",
        "event_type": "tls",
        "src_ip": "1.1.1.1",
        "dest_ip": "2.2.2.2",
        "tls": {
            "sni": "openai.com",
            "version": "TLS 1.3"
        }
    }

    result = mod.format_eve_event(obj)

    assert "TLS" in result
    assert "openai.com" in result


def test_format_smb_event():
    mod = load_viewer()

    obj = {
        "timestamp": "2026-01-01T12:00:00",
        "event_type": "smb",
        "src_ip": "1.1.1.1",
        "dest_ip": "2.2.2.2",
        "smb": {
            "command": "CREATE",
            "filename": "secret.txt",
            "share": "Users"
        }
    }

    result = mod.format_eve_event(obj)

    assert "SMB" in result
    assert "secret.txt" in result
    assert "Users" in result


def test_format_eve_json_filter_alert():
    mod = load_viewer()

    raw = '\n'.join([
        '{"event_type":"alert","alert":{"signature":"ALERT1"}}',
        '{"event_type":"dns","dns":{"rrname":"example.com"}}'
    ])

    result = mod.format_eve_json(
        raw,
        limit=0,
        tail_mode=False,
        event_type_filter="alert"
    )

    assert "ALERT1" in result
    assert "example.com" not in result


def test_resolve_output_default(tmp_path):
    mod = load_viewer()

    out = mod.resolve_output_path(
        None,
        tmp_path,
        "eve.json"
    )

    assert out.name == "cleaned_eve.json.txt"


def test_resolve_output_filename_only(tmp_path):
    mod = load_viewer()

    out = mod.resolve_output_path(
        "output.txt",
        tmp_path,
        "eve.json"
    )

    assert out == tmp_path / "output.txt"


def test_validate_args_good(tmp_path):
    mod = load_viewer()

    log_dir = tmp_path / "logs"
    log_dir.mkdir()

    args = SimpleNamespace(
        version=False,
        limit=500,
        page_lines=20,
        log_dir=str(log_dir),
    )

    assert mod.validate_args(args) is True


def test_validate_args_bad_limit(tmp_path):
    mod = load_viewer()

    log_dir = tmp_path / "logs"
    log_dir.mkdir()

    args = SimpleNamespace(
        version=False,
        limit=-1,
        page_lines=20,
        log_dir=str(log_dir),
    )

    assert mod.validate_args(args) is False


def test_validate_log_file_missing(tmp_path):
    mod = load_viewer()

    missing = tmp_path / "missing.log"

    assert mod.validate_log_file(missing) is False


def test_validate_log_file_exists(tmp_path):
    mod = load_viewer()

    f = tmp_path / "eve.json"
    f.write_text("{}", encoding="utf-8")

    assert mod.validate_log_file(f) is True


def test_colorize_alert_line():
    mod = load_viewer()

    mod.USE_COLOR = False

    line = "ALERT possible scan"

    result = mod.colorize_line(line)

    assert "ALERT" in result


def test_colorize_dns_line():
    mod = load_viewer()

    mod.USE_COLOR = False

    line = "DNS example.com"

    result = mod.colorize_line(line)

    assert "DNS" in result
