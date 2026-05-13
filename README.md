# Suricata PRIZM Utilities

https://www.github.com/prizmatik666/suri_dash_cli
a Prizmatik Underground production


A small pair of Python utilities for working with Suricata logs in a home-lab, learning, or defensive monitoring environment.

This repo contains:

- `sdash.py` — a live terminal dashboard for `eve.json`
- `slog.py` — an interactive Suricata log viewer / prettifier / exporter

Both tools are designed for readable terminal workflows, SSH/tmux usage, and small-lab network analysis.

---

# Project Status

Current release target:

```text
v0.1.0
```

These utilities are lab-ready, but not intended to replace a full SIEM, SOC platform, or enterprise Suricata deployment stack.

They are best used for:

- home-lab monitoring
- learning Suricata event structure
- reviewing `eve.json`
- watching alerts/flows in a terminal
- exporting cleaned log summaries
- correlating local scans, SMB tests, DNS, TLS, HTTP, and Suricata alerts

---

# Requirements

## System

- Linux
- Python 3.9+
- Suricata installed and writing logs
- Terminal with ANSI color support
- Recommended: `jq`, `tmux`

## Python

Both tools currently use Python standard-library modules only.

No external Python packages are required for normal use.

For testing:

```bash
sudo apt install python3-pytest
```

or:

```bash
python3 -m pip install pytest
```

---

# Suricata Log Expectations

By default, both tools expect Suricata logs in:

```bash
/var/log/suricata/
```

The most important file is:

```bash
/var/log/suricata/eve.json
```

Common Suricata logs:

```text
eve.json       Structured JSON event log
fast.log       Human-readable alerts
stats.log      Suricata stats output
suricata.log   Engine/runtime messages
```

Check your log directory:

```bash
sudo ls -lh /var/log/suricata/
```

Check where Suricata is configured to write logs:

```bash
grep -n "default-log-dir" /etc/suricata/suricata.yaml
```

Check whether Suricata is running:

```bash
systemctl status suricata
```

or:

```bash
ps aux | grep suricata
```

---

# sdash.py

`sdash.py` is a live terminal dashboard for Suricata `eve.json`.

It follows the log, parses events, and displays compact live sections for:

- event counts
- top alerts
- top destination ports
- top talkers
- protocols
- SMB flows
- scan/probe detections
- recent events

It is branded as:

```text
SURICATA LIVE DASHBOARD - PRIZM BUILD
```

---

## What sdash.py Watches

`sdash.py` reads Suricata EVE JSON events such as:

```text
alert
flow
dns
http
tls
stats
smb
```

It uses both Suricata-native alerts and local dashboard heuristics.

The dashboard can identify:

- Suricata alert signatures
- Nmap / scan-related alert signatures
- flow-heavy port scans
- light watched-port probes
- SMB 139/445 probes
- SMB flows
- DNS queries
- HTTP/TLS activity

---

## Scan Detection Behavior

The dashboard has its own scan/probe tracker.

Default behavior:

```text
SCAN_WINDOW = 30 seconds
SCAN_THRESHOLD = 5 unique destination ports
LIGHT_SCAN_THRESHOLD = 2 unique watched ports
```

Meaning:

- a wide scan usually appears quickly
- a tiny two-port scan may only show if both ports are seen within the tracking window
- full network-wide detection is only possible for traffic the Suricata sensor can actually see

Important network visibility note:

A Suricata sensor on one host usually sees:

```text
traffic to/from itself
broadcast traffic
multicast traffic
some local discovery traffic
```

It usually does not see all device-to-device unicast traffic on a switched LAN or Wi-Fi network unless you use:

- router/gateway placement
- SPAN/mirror port
- network tap
- host-based Suricata on each endpoint
- controlled lab MITM setup

So if Suricata runs on `192.168.2.5`, scanning `192.168.2.5` from another machine should be visible, but scanning two other LAN hosts may not be.

---

## Running sdash.py

Basic run:

```bash
sudo python3 sdash.py
```

Make executable:

```bash
chmod +x sdash.py
sudo ./sdash.py
```

Run against a specific EVE log:

```bash
sudo python3 sdash.py --log /var/log/suricata/eve.json
```

Lower scan threshold for a small home lab:

```bash
sudo python3 sdash.py --scan-threshold 2 --window 60
```

Show full IPv6 addresses:

```bash
sudo python3 sdash.py --full-ip
```

Start from the beginning of the log instead of only following new events:

```bash
sudo python3 sdash.py --no-follow-end
```

---

## sdash.py Keyboard Controls

Inside the dashboard:

```text
q    quit
p    pause/resume
```

---

## sdash.py Flags

```text
--log PATH
    Path to Suricata eve.json.
    Default: /var/log/suricata/eve.json

--scan-threshold N
    Number of unique destination ports required before a possible scan is shown.
    Default: 5

--light-threshold N
    Number of watched ports required for light probe detection.
    Default: 2

--window SECONDS
    Time window for scan/probe tracking.
    Default: 30

--max-events N
    Number of recent events kept in memory.
    Default: 40

--full-ip
    Show full IP addresses instead of shortening IPv6 addresses.

--no-follow-end
    Start reading from the beginning of the log instead of tailing only new events.
```

---

## sdash.py Operational Notes

### Permission Errors

Suricata logs are often root-readable only.

If you see:

```text
Permission denied
Log file is not readable
```

Run:

```bash
sudo python3 sdash.py
```

### Terminal Too Small

If the dashboard says:

```text
TERMINAL TOO SMALL - resize pane
```

Fix:

- enlarge the terminal
- enlarge the tmux pane
- reduce font size
- use fullscreen terminal mode

### Light Scans May Not Show

A tiny scan such as:

```bash
nmap -Pn -p 139,445 TARGET
```

may not always show depending on:

- Suricata visibility
- whether flow events are generated
- whether both ports appear inside the scan window
- whether the traffic reaches the sensor
- whether the correct interface is monitored

Try:

```bash
nmap -Pn -p 1-300 TARGET
```

or:

```bash
sudo python3 sdash.py --scan-threshold 2 --window 60
```

### Wrong Interface

A VERY common issue:

Suricata may be monitoring the wrong NIC.

Check active interface:

```bash
grep "interface:" /etc/suricata/suricata.yaml
```

Verify traffic:

```bash
sudo tcpdump -i wlan1
```

If tcpdump sees traffic but sdash remains empty:

- Suricata may not be attached to the correct interface
- EVE logging may be disabled
- eve.json may not be enabled in suricata.yaml

### EVE Logging Disabled

If `eve.json` never updates:

Check:

```bash
grep -n "eve-log" /etc/suricata/suricata.yaml
```

Make sure:

```yaml
- eve-log:
    enabled: yes
```

exists.

Restart Suricata after changes:

```bash
sudo systemctl restart suricata
```

### No Alerts Appearing

Possible causes:

- no rules loaded
- ET/Open not installed
- Suricata running without rule sources
- HOME_NET misconfigured
- interface mismatch
- scans too light

Check rules:

```bash
sudo suricata-update list-sources
sudo suricata-update
```

Then restart:

```bash
sudo systemctl restart suricata
```

### Dashboard Shows Traffic But No Scan Detection

Possible causes:

- thresholds too high
- scans too small
- flow events missing
- Suricata only seeing partial traffic

Try:

```bash
sudo python3 sdash.py --scan-threshold 2
```

---

# slog.py

`slog.py` is a Suricata log viewer, browser, prettifier, and exporter.

It can:

- list logs from `/var/log/suricata`
- open `.log`, `.json`, and `.gz` files
- pretty-format `eve.json`
- browse cleaned output page-by-page
- filter by `event_type`
- export cleaned log output to `~/logs`
- run interactively or in export-only mode

It is branded as:

```text
suri-log-viewer - PRIZM BUILD
```

---

## What slog.py Is For

Use `slog.py` when you want to inspect logs after the fact.

Good use cases:

- review `eve.json`
- export readable alert summaries
- inspect DNS/HTTP/TLS/flow activity
- clean noisy JSON into readable text
- prepare notes for reports or portfolio writeups
- browse compressed rotated logs

---

## Running slog.py

Basic interactive run:

```bash
sudo python3 slog.py
```

Make executable:

```bash
chmod +x slog.py
sudo ./slog.py
```

Open a specific log:

```bash
sudo python3 slog.py --file eve.json
```

Open compressed logs:

```bash
sudo python3 slog.py --file eve.json.1.gz
```

Export alert-only events:

```bash
sudo python3 slog.py \
  --file eve.json \
  --event-type alert \
  --export-only \
  --output alerts.txt
```

Disable color:

```bash
sudo python3 slog.py --no-color
```

---

## slog.py Viewer Controls

Inside the viewer:

```text
n / Enter   next page
p           previous page
g           top
G           bottom
q           quit viewer
```

---

## slog.py Flags

```text
--log-dir PATH
    Directory containing Suricata logs.
    Default: /var/log/suricata

--save-dir PATH
    Default export directory.
    Default: ~/logs

--file FILE
    Specific log file to open.

--limit N
    Number of events/lines to load.
    Use 0 for whole file.
    Default: 500

--tail
    Read the last --limit lines instead of the first.

--no-color
    Disable ANSI colors.

--export-only
    Export prettified output without opening the interactive viewer.

--output FILE
    Output filename/path for export-only mode.

--page-lines N
    Lines shown per page in the viewer.
    Default: 28

--event-type TYPE
    Filter eve.json by event type.
    Example:
        alert
        dns
        http
        tls
        flow

--version
    Show version and exit.
```

---

## slog.py Operational Notes

### Permission Problems

If you cannot read logs:

```text
Permission denied
```

Run:

```bash
sudo python3 slog.py
```

### Large eve.json Files

Some Suricata installs generate HUGE logs.

Using:

```bash
--limit 0
```

on a massive `eve.json` may consume large amounts of RAM and become slow.

Safer options:

```bash
--limit 500
--limit 2000
--tail
```

### Corrupted JSON Lines

If Suricata crashes or rotates logs mid-write, some lines may not parse cleanly.

The viewer attempts to continue safely and will display raw lines when parsing fails.

### Gzip Log Support

Compressed logs such as:

```text
eve.json.1.gz
```

are supported automatically.

### Missing SMB Fields

Not all Suricata installs/log formats include SMB event metadata.

If SMB sections appear sparse:

- SMB logging may not be enabled
- Suricata version may differ
- SMB parser/app-layer support may differ

### Empty Log Files

Possible causes:

- Suricata not running
- wrong log directory
- EVE logging disabled
- no traffic
- wrong monitored interface

Check:

```bash
systemctl status suricata
```

and:

```bash
ls -lh /var/log/suricata/
```

---

# Testing

Install pytest:

```bash
sudo apt install python3-pytest
```

Run all tests:

```bash
pytest -v
```

Run only sdash tests:

```bash
pytest -v tests/test_sdash.py
```

Run only slog tests:

```bash
pytest -v tests/test_slog.py
```

Expected output:

```text
18 passed
```

or similar.

---

# Recommended Environment

These tools work especially well in:

- tmux
- Warp terminal
- SSH sessions
- Kali Linux
- Suricata home labs
- small monitoring VMs
- Raspberry Pi sensors
- local Wi-Fi analysis setups

---

# Future Ideas

Possible future upgrades:

- dashboard snapshots
- live alert sound hooks
- ncurses window resizing
- device-name labeling
- protocol heatmaps
- alert search
- grep-style filtering
- offline replay mode
- multi-log correlation
- pcap correlation
- Zeek integration
- JSON export modes
- dark/light terminal themes
- alert severity sorting
- keyboard toggles inside sdash
- Suricata rule hit statistics

---

