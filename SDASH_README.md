# `sdash.py` — Suricata Live Dashboard v3.5 PRIZM BUILD

`sdash.py` follows a Suricata EVE JSON file and presents a compact terminal view of native alerts, recent events, and optional side statistics.

## Run

```bash
python3 sdash.py --log /var/log/suricata/eve.json
```

For an interactive settings panel with recommended defaults, run:

```bash
python3 sdash_setup.py
```

The setup panel lets users edit the log path, scan thresholds, heuristic window, event limits, DNS behavior, IPv6 display, and startup behavior. Press `s` to save, `f` to restore the built-in v3.5 PRIZM factory defaults, `i` to launch the privileged AF_PACKET interface selector, and `q` to quit. The interface selector performs the system-level YAML backup, validation, and restart flow.

Settings are saved to `~/.config/sdash/config.json` with mode `0600`. Dashboard precedence is:

```text
built-in v3.5 PRIZM defaults -> user config -> explicit sdash.py command-line flags
```

To ignore customized settings for one run:

```bash
python3 sdash.py --factory-defaults
```

If the current user cannot read the log, use the local system’s approved access method or run:

```bash
sudo python3 sdash.py --log /var/log/suricata/eve.json
```

Useful options:

```text
--scan-threshold N    Unique destination ports for the dashboard heuristic
--light-threshold N   Unique watched ports for a light probe heuristic
--window N             Heuristic tracking window in seconds
--max-events N         Recent-event buffer size
--full-ip              Keep full IPv6 addresses
--no-follow-end        Read existing log content instead of starting at EOF
--hide-dns-events      Count DNS but omit routine DNS from Recent Events
--supress-dns          Suppress DNS and mDNS from the readout and event counts
--suppress-dns         Correctly spelled alias for --supress-dns
--ignore-dns-scans     Exclude port 53 from scan heuristics
--dns-server IP        Mark trusted DNS infrastructure; repeatable
--config PATH           Use an alternate user settings JSON file
--factory-defaults      Ignore user settings for this run
```

### Tuning scan heuristics

The dashboard displays the active values in its header:

- `threshold=5` means five unique destination ports observed between the same source/destination pair within the `--window` period produces a `POSSIBLE PORT SCAN` heuristic.
- `light=2` means two unique watched service ports can produce a lighter service or SMB probe heuristic.
- These are dashboard correlation settings, not Suricata rule thresholds. They do not alter native EVE alerts.

Users can change the values at launch without editing the source code:

```bash
python3 sdash.py \
  --scan-threshold 10 \
  --light-threshold 3 \
  --window 60 \
  --log /var/log/suricata/eve.json
```

The settings currently apply for that dashboard session. A wrapper, service command, or shell alias can preserve preferred values across launches.

## Screen and controls

The default layout keeps the main security view visible:

- `TOP ALERTS` — most frequent native alert signatures.
- `SURICATA ALERTS (native EVE) / SCAN (heuristic)` — recent native Suricata alerts and separately labeled dashboard detections.
- `RECENT EVENTS` — the live event stream.

Native alert lines include the EVE timestamp, SID, severity, source/destination, and signature. The `c` command clears only the live native-alert panel; it does not delete EVE data, clear Recent Events, or reset Top Alerts.

| Key | Action |
|---|---|
| `p` | Pause/resume processing |
| `r` | Reset counters and active displays |
| `c` | Clear native Suricata-alert panel only |
| `e` | Toggle event counts |
| `s` | Toggle side statistics: top ports, talkers, protocols, SMB flows |
| `q` | Quit |

## Native alerts versus heuristics

Native alerts come directly from EVE records with `event_type == "alert"`. The dashboard preserves their timestamps and alert metadata.

Dashboard scan/probe messages are derived from `flow` records by counting unique destination ports for a source/destination pair during the configured window. They are not converted into fake Suricata alerts and do not prove a unique-port scan by themselves.

Use `--supress-dns` when routine DNS or mDNS volume overwhelms the display. The flag suppresses EVE event types `dns` and `mdns` from Recent Events and Event Counts. It does not delete log records, suppress native security alerts, or disable flow-based scan correlation. The correctly spelled `--suppress-dns` is also accepted.

## Suricata visibility

Check the active capture interface and recent decoder statistics independently:

```bash
grep -nA8 '^af-packet:' /etc/suricata/suricata.yaml
sudo jq -c 'select(.event_type=="stats")' /var/log/suricata/eve.json | tail -1
sudo jq -c 'select(.in_iface!=null)' /var/log/suricata/eve.json | tail
```

The packaged [`suricata_interface_tool.py`](suricata_interface_tool.py) provides a guided interface selector. It backs up the YAML, changes one active AF_PACKET interface entry, validates with `suricata -T`, restores on failure, and can restart the service. It does not change wireless mode.

## Data handling

The dashboard reads the configured EVE file locally. It does not call the OpenAI API. Protect EVE logs because they may contain IP addresses, hostnames, domains, usernames, and other sensitive telemetry.
