import importlib.util
from pathlib import Path
from types import SimpleNamespace


SDASH_PATH = Path(__file__).resolve().parents[1] / "/home/prizm/suri_dash_cli/sdash.py"


def load_sdash():
    spec = importlib.util.spec_from_file_location("sdash", SDASH_PATH)
    sdash = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(sdash)
    return sdash


def test_shorten_ipv4_unchanged():
    sdash = load_sdash()
    sdash.ARGS = SimpleNamespace(full_ip=False)

    assert sdash.shorten_ip("192.168.2.16") == "192.168.2.16"


def test_shorten_ipv6_default():
    sdash = load_sdash()
    sdash.ARGS = SimpleNamespace(full_ip=False)

    result = sdash.shorten_ip("fe80::92d6:a585:56de:0429")

    assert result == "fe80::56de:429"


def test_full_ip_flag_keeps_ipv6_full():
    sdash = load_sdash()
    sdash.ARGS = SimpleNamespace(full_ip=True)

    ip = "fe80::92d6:a585:56de:0429"

    assert sdash.shorten_ip(ip) == ip


def test_short_pair_uses_shortened_ips():
    sdash = load_sdash()
    sdash.ARGS = SimpleNamespace(full_ip=False)

    result = sdash.short_pair(
        "fe80::92d6:a585:56de:0429",
        "192.168.2.5"
    )

    assert result == "fe80::56de:429->192.168.2.5"


def test_validate_rejects_missing_log(tmp_path):
    sdash = load_sdash()

    args = SimpleNamespace(
        log=str(tmp_path / "missing-eve.json"),
        scan_threshold=5,
        light_threshold=2,
        window=30,
        max_events=40,
    )

    assert sdash.validate_startup(args) is False


def test_validate_accepts_existing_log(tmp_path):
    sdash = load_sdash()

    log = tmp_path / "eve.json"
    log.write_text("", encoding="utf-8")

    args = SimpleNamespace(
        log=str(log),
        scan_threshold=5,
        light_threshold=2,
        window=30,
        max_events=40,
    )

    assert sdash.validate_startup(args) is True


def test_format_item_shortens_ipv6():
    sdash = load_sdash()
    sdash.ARGS = SimpleNamespace(full_ip=False)

    result = sdash.format_item("fe80::92d6:a585:56de:0429", 7, width=24)

    assert "fe80::56de:429" in result
    assert "7" in result

def test_parse_args_full_ip(monkeypatch):
    sdash = load_sdash()

    monkeypatch.setattr(
        "sys.argv",
        ["sdash.py", "--full-ip"]
    )

    args = sdash.parse_args()

    assert args.full_ip is True

def test_parse_args_threshold(monkeypatch):
    sdash = load_sdash()

    monkeypatch.setattr(
        "sys.argv",
        [
            "sdash.py",
            "--scan-threshold",
            "12"
        ]
    )

    args = sdash.parse_args()

    assert args.scan_threshold == 12
