# Suri Suite — Example Functional Readout

This is an illustrative walkthrough of the current user-facing tools. Values
and hostnames below are examples; a live readout reflects the selected EVE and
stats logs, local settings, and current traffic. The dashboard, log viewers, and
agent read local Suricata data; only the investigation agent makes live model
API calls.

## Live dashboard: `sdash.py`

Start the dashboard with the system Python; no virtual environment or API key is
needed:

```console
$ python3 sdash.py --log /var/log/suricata/eve.json
```

```text
SURICATA LIVE DASHBOARD v3.5 - PRIZM BUILD
LOG: /var/log/suricata/eve.json
q=quit  p=pause  r=reset  c=clear-native-alerts  e=event-counts  s=side-stats  window=30s
EVENT COUNTS:[off]  SIDE STATS:[off]  threshold=5  light=2

TOP ALERTS

SURICATA ALERTS (native EVE) / SCAN (heuristic)
  10:41:33 [IDS ALERT] sid:1001101 sev:3 192.168.2.7->192.168.2.4 LOCAL SCAN Possible TCP SYN vertical scan rate

RECENT EVENTS
  10:41:48 FLOW  192.168.2.29:29088 -> 192.168.2.4:53 UDP
  10:41:47 DNS   192.168.2.7 -> graph.instagram.com
  10:41:46 TLS   192.168.2.7 -> graph.instagram.com
  10:41:43 FLOW  192.168.2.7:56884 -> 192.168.2.4:53 UDP
```

The DNS line shows the source address followed by the queried name, not the
resolver destination IP. Native EVE alerts and dashboard scan heuristics are
separate: a heuristic is a local observation, not a Suricata signature. Press
`e` for event-type counts, `s` for side statistics, `p` to pause/resume, `c` to
clear only the visible native-alert panel, and `q` to quit. Clearing a panel
does not delete EVE records.

## Stats summary and configurable counters: `suricata_stats.py`

The stats viewer summarizes Suricata's text-format `stats.log` and is separate
from EVE event analysis:

```console
$ python3 suricata_stats.py
```

```text
SURICATA STATS  |  /var/log/suricata/stats.log
Latest snapshot: 09/29/2026 -- 13:42:00 (uptime 3d 04h)

CAPTURE AND DECODER
Kernel packets                   1,245,630  (415.20 pkt/s)
Kernel drops                             12  (0.00 /s)
Decoded packets                   1,245,618
Decoded bytes                  1.42 GiB  (0.48 MiB/s)
IPv4 packets                     1,108,432
IPv6 packets                       137,186
TCP packets                        716,103
UDP packets                        520,004

APPLICATION LAYER
DNS/UDP flows                       24,516
TLS flows                            8,903
SSH flows                               14
...
```

In the TUI, press `c` to open the scrollable counter settings menu. It lists
counters found in the latest complete stats snapshot, along with the built-in
defaults. Use arrows or Page Up/Down to move, Space/Enter to toggle a counter,
`/` to filter, `a` to select all discovered counters, and `s` to save. Press
`r` to immediately restore and save the developer defaults; `d` loads defaults
as an unsaved draft; `q` closes and discards unsaved edits. Saved choices go to
`~/.config/suricata-agent/stats_config.json` (or under `$XDG_CONFIG_HOME`).
Press `r` in the main stats screen to refresh, `/` to search, and `q` to exit.
The same editor can be opened directly with `python3 suricata_stats.py
--configure`; `--reset-config` restores defaults without entering the TUI.

## Browse logs: `slog.py`

```console
$ python3 slog.py
```

The file picker is scrollable and filterable. Use Up/Down, Page Up/Down,
Home/End, `/` to filter, `c` to clear the filter, and Enter to select a log.
The next screen lets you choose a view size; press `b` to return to the file
picker. In the viewer, `n`/Enter and `p` change pages, `g`/`G` jump to the first
or last page, `b` returns to the file list, `q` opens save/next options, `x`
exits after the current view, and `h` displays the controls. DNS records show
the query name and query type; for example:

```text
2026-09-29T12:53:29.283791-0400 | DNS | 192.168.2.8:58340 -> 192.168.2.4:53 | signal-service.pbs.yahoo.com HTTPS
```

## Investigate EVE: `suricata_agent.py`

The agent requires its API dependencies and key, but a virtual environment is
recommended rather than mandatory. Start it with:

```console
$ python3 suricata_agent.py --eve-log /var/log/suricata/eve.json
[startup] Checking EVE source and configured index path...
[startup] SQLite index ready; synchronizing complete EVE records...
[startup] Verifying index schema, source checkpoint, and fidelity...
[ready] Ready for questions: integrity=ok, records=677248, lag=0 bytes
```

The exact progress depends on whether this is a first build, how much EVE data
has been appended, and the index verification state. Startup synchronizes before
the first prompt. After each completed answer, appended records are refreshed
in the background while the user reads; a new search uses the last committed
SQLite snapshot rather than waiting for an active refresh.

### Example: five most recent distinct DNS requests

This example is based on the real transcript saved on 2026-09-29. Identifying
details have been sanitized: the client/resolver addresses and hostnames are
replaced, times are shifted consistently, and record/flow IDs are pseudonyms.
The counts, query types, ordering, and pagination behavior reflect the actual
tool results.

```text
USER: Run an investigation for the most recent DNS requests from [client]. Show
the queried hostname, query type, timestamp, source and destination IP:port,
and flow ID or record ID when available. Return five distinct DNS names, not
duplicate request/response records. Include the resolved time window and
whether results were truncated. Don’t infer intent or label activity suspicious
without supporting evidence. Then report the tool calls and final answer.
```

The agent first gathered a host-level DNS summary, then narrowed to the newest
outbound DNS request endpoints. This kept the broad activity context while
avoiding duplicate request/response rows in the requested five-name view:

```text
TOOL investigate_host {"focus":"dns","ip":"[client]","limit":25,"lookback_minutes":1440,"time_basis":"either"} -> 67762
TOOL search_events {"dest_port":53,"direction":"outbound","duplicates":"group_exact","event_types":["dns"],"limit":5,"sort":"desc","src_ip":"[client]","unique_by":"endpoint","view":"endpoints"} -> 33882
```

Sanitized final answer, following the real response:

```text
## Observed Evidence

The five most recent distinct DNS names requested by [client] in the resolved
window are below. Each row is an outbound DNS request, not a response; repeated
records for the same name are not listed.

| Queried hostname | Query type | Timestamp (local time) | Source → destination | Flow ID | Record ID |
|---|---|---|---|---|---|
| chat.example | HTTPS | 2026-09-29 12:24:40.609256 | 192.0.2.7:64435 → 192.0.2.53:53 | flow-A | record-A |
| cdn.example | AAAA | 2026-09-29 12:24:27.205219 | 192.0.2.7:53452 → 192.0.2.53:53 | flow-B | record-B |
| api.example | AAAA | 2026-09-29 12:24:10.468955 | 192.0.2.7:55882 → 192.0.2.53:53 | flow-C | record-C |
| training.example | AAAA | 2026-09-29 12:23:47.999669 | 192.0.2.7:64671 → 192.0.2.53:53 | flow-D | record-D |
| www.example | A | 2026-09-29 12:23:26.624660 | 192.0.2.7:55324 → 192.0.2.53:53 | flow-E | record-E |

Resolved time window: 2026-09-28 16:24:44.966749 through 2026-09-29
16:24:44.966749 UTC. Results truncated: Yes—the five-name page has more
results available. The endpoint scan itself was not truncated.

## Tool Calls

1. `investigate_host(ip="[client]", focus="dns", lookback_minutes=1440)` —
   verified DNS activity and resolved the time window.
2. `search_events(src_ip="[client]", dest_port=53, event_types=["dns"],
   direction="outbound", sort="desc", view="endpoints",
   unique_by="endpoint", limit=5, ...)` — returned the five newest distinct
   names and their request records.
```

The real tool returned **67,762 DNS records** in the host summary, with
**33,882 outbound** and **33,880 inbound**. The second search returned five
endpoint items from **33,882 matching raw records** (`truncated=true`), while
its distinct endpoint scan was not truncated. This distinction matters: the
tool's `-> 33882` progress count is the total matching records, not the number
of rows sent in the page. For complete request/response chains, use event or
flow views instead of endpoint presentation; sharing a `flow_id` alone does
not make distinct EVE records duplicates.

In actual investigations, preserve tool-returned timestamps, `record_id`,
`flow_id`, tuple, and raw references. Ask for the next page to continue a
bounded result. `/context` saves the conversation and tool trace locally under
`context/context_YYYYMMDD_HHMMSS.txt` (owner-only file permissions); the
repository ignores that directory because transcripts can contain sensitive
network evidence.

The agent distinguishes observations present in EVE, native IDS alerts, and
deterministic correlations. No alert is not evidence of no traffic, and a
zero-result narrow search is broadened/diagnosed before concluding there was no
activity. If records remain absent after broad verification, the response
should state the actual search window and limits. Agent tools are read-only;
they do not block traffic or change Suricata configuration.

Useful commands while the agent is running: `/help` lists controls, `/status`
checks EVE/index health, `/context` saves the retained conversation locally,
and `/quit` performs graceful cleanup. The status bar distinguishes waiting for
the model from running a tool. API usage and approximate tool/context sizes are
reported after completed investigations.

## Configure the agent

```console
$ python3 suricata_agent_config.py
Suricata agent configuration
File: /home/user/.config/suricata-agent/config.json
1. EVE log: /var/log/suricata/eve.json
2. SQLite index: automatic per-log path
3. Debug logging: off
4. Configure source-log access: warn
5. Backup directory: not configured
...
```

Settings are drafted and saved from the menu. Source-log access changes are
separately previewed and require explicit confirmation and `sudo`; applying
them does not restart Suricata or the dashboard. The suite records the prior
permissions so the previous access change can be reviewed or reverted.

## Quick reference

| Program | What it displays | Network/API |
|---|---|---|
| `sdash.py` | Live EVE events, native alerts, and local scan heuristics | None |
| `slog.py` | Selected Suricata logs with scrollable pages | None |
| `suricata_stats.py` | `stats.log` counters and snapshot rates | None |
| `suricata_agent.py` | Evidence-based investigations over indexed EVE | Live model API |
| `suricata_agent_config.py` | Saved agent options and controlled access workflows | Local; sudo only for confirmed system changes |
