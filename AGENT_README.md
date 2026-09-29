# Suricata Agent and Interactive UI

`suricata_agent.py` is the optional investigation interface. It combines a local terminal UI with an OpenAI Responses API request loop and bounded, read-only local Suricata tools.

## Setup

A virtual environment is recommended for dependency isolation, but it is not
required and the agent does not create one automatically. If `requests` and
`python-dotenv` are already installed for the selected Python interpreter, run
the API-key setup and agent directly with `python3`.

Recommended isolated setup:

```bash
python3 -m venv .venv
. .venv/bin/activate
python3 -m pip install -r requirements.txt
python3 setup_openai_env.py
```

No-venv setup on Debian or Ubuntu:

```bash
sudo apt update
sudo apt install python3-requests python3-dotenv
python3 setup_openai_env.py
python3 suricata_agent.py --eve-log /var/log/suricata/eve.json
```

On systems that permit Python user-site package installation, the dependencies
can instead be installed without a virtual environment using:

```bash
python3 -m pip install --user -r requirements.txt
python3 setup_openai_env.py
python3 suricata_agent.py --eve-log /var/log/suricata/eve.json
```

The setup helper prompts without echoing the API key, writes a project-local `.env`, and applies owner-only permissions (`0600`). Do not commit `.env`.
The `.env` API-key file is independent of a `.venv` Python environment and is
loaded automatically when the agent starts.

## Interactive UI

```bash
python3 suricata_agent.py --eve-log /var/log/suricata/eve.json
```

Type an investigation question at the prompt. While a request is running, the UI displays tool activity and waits for the model/tool loop to finish. The UI supports scrolling with arrow keys, Page Up/Page Down, Home, and End.

Interactive commands:

| Command | Action |
|---|---|
| `/help` | Show commands and scrolling help |
| `/clear` | Clear the current in-memory conversation |
| `/history` | Display retained conversation messages |
| `/context` | Save the current conversation to a protected text file |
| `/status` | Display local sensor status from the read-only status tool |
| `/quit` | Run structured cleanup and exit the UI with status 0 |

### Slash-command menu

When the input begins with `/`, the UI displays a command dropdown above the input line. The list narrows as the command is typed. Use the Up/Down arrows to select a command, `Tab` to insert the highlighted command, and Enter to run an exact command. Pressing Enter while the input is only a partial match inserts the highlighted command first; press Enter again to execute it.

### The `/context` feature

`/context` is implemented in `Interface.save_context()` in `suricata_agent.py`.

It creates the `context/` directory beside the agent program if needed, then
saves the transcript there using this filename pattern:

```text
context/context_YYYYMMDD_HHMMSS.txt
```

The file contains:

- A `SURICATA AGENT CONTEXT` header.
- Local save time and selected model.
- Every retained user and assistant message.
- Assistant tool-call records, including JSON tool-call arguments.
- Tool-result messages retained in the conversation history.

The file is written as UTF-8 and changed to mode `0600` so only its owner can read it. The UI prints the exact path after a successful save. The feature saves the in-memory conversation; it is not a database, does not export the entire EVE log, and does not automatically upload the context file.

The one-shot `--ask` mode does not expose slash commands:

```bash
python3 suricata_agent.py --ask "Find recent high-severity alerts"
```

## OpenAI and tool-calling flow

The runtime in `core/agent_runtime.py` calls:

```text
user question -> OpenAI Responses API -> optional function calls
-> local SuricataTools function -> JSON tool result
-> model follow-up with returned reasoning context -> final answer
```

The default model is `gpt-6-sol` with medium reasoning effort; `OPENAI_MODEL` can override it and `OPENAI_REASONING_EFFORT` can tune reasoning effort for supported models. The Responses API lets the runtime preserve returned reasoning items while it chains local tools. Requests use `store: false`; conversation and tool evidence are replayed by the local runtime. The runtime permits up to twelve tool-call iterations for one question. Tool schemas are supplied as Responses function tools with `tool_choice: "auto"`.

Normal `python3 suricata_agent.py` runs still call the live OpenAI API against the configured Suricata evidence. After each answer, the UI reports API input/cached/cache-write/output/reasoning usage and an estimated investigation cost for the default GPT-6 Sol model. `agent.last_metrics` also contains per-request usage, tool-result bytes, estimated tool-result tokens, and replayed/retained context estimates. API `usage` counters are authoritative; local token estimates use a rough four-characters-per-token approximation. Cost is an estimate using published standard GPT-6 Sol text rates, not an invoice; a non-default model has no built-in price estimate.

The model receives a bounded, evidence-referenced flow page by default rather than duplicated `timeline` and `results` arrays. The local tool still builds the full result; original EVE records remain retrievable through the index, `get_event`, and `correlate_flow` pagination. Once an answer completes, the next turn receives structured state (question, answer excerpt, uncertainty, tool scope, exact window, counts, pagination and evidence references) instead of replaying the prior raw tool payload. The two most recent investigations retain detailed state; a bounded catalog keeps older evidence-bearing findings identifiable by cited record IDs, flow IDs, raw references, and page handles. Saved context history remains local and retains the actual model-facing tool exchanges.

Ordinary `python3 -m pytest -q` runs are offline: unexpected model calls fail, and the live integration tests are skipped. To intentionally validate real model behavior against live Suricata data, run `python3 -m pytest -m live_model --live-model tests/live/` with `OPENAI_API_KEY` configured. For the more expensive nine-turn evidence-retention and usage trace, set `SURICATA_LIVE_TRACE=1` and add `-s`; that trace prints answers and tool arguments, which may contain sensitive network evidence. The test-only network guard does not affect normal agent execution. The local `tests/` directory is intentionally ignored by Git.

Relative time phrases such as “last hour”, “80 minutes ago”, and “around 6 AM” are anchored to the agent's runtime clock. The runtime corrects model-supplied absolute dates when they conflict with a relative phrase, while explicit dates written by the user take precedence. Investigative tools return the resolved window so the final answer can cite the exact search period.

If the API returns HTTP 400 with a context-length error, the runtime makes one
recovery attempt: it keeps the current question and active tool-call sequence,
retains a short recap of recent user/assistant messages, and compacts large tool
payloads while keeping counts, timestamps, flow IDs, record IDs, offsets,
truncation state, and pagination cursors where available. The UI displays a
notice when this happens. If the retry still fails, the error includes the
API's returned error message and code when available. Other HTTP 400 responses
are reported without context compression.

Available read-only tools:

- `suricata_status` / `get_sensor_status` — reports EVE readability, freshness, event types, capture interfaces, timestamp handling, index state, and exact-duplicate hints.
- `search_events` — searches every EVE event type with source/destination-or-either filters, ports, protocols, normalized application fields, explicit windows, event/flow/either timestamp basis, aggregates, pagination, and independent result-view, duplicate, and detail policies.
- `search_alerts` — searches IDS alert records without treating zero alerts as proof of no traffic.
- `investigate_host` — aggregates a host's top outbound requests, peers, ports, directions, DNS/mDNS, TLS, HTTP, flows, alerts, packet/byte totals, TCP outcomes, and notable sequences.
- `investigate_pair` / `investigate_service` — investigates a bidirectional host pair or all use of a service port involving one host.
- `events_around` — searches a bounded interval before and after an approximate action time.
- `correlate_flow` / `get_flow` — builds a chronological flow chain while retaining distinct request, response, alert, TLS, HTTP, and flow records; exact copies may be grouped without losing their record references.
- `get_event` — retrieves original raw EVE evidence by `event_id`, `flow_id`, or byte offset.
- `count_raw_eve_matches` — directly scans canonical EVE as a sanity check when a higher-level search returns an implausible zero.
- `compare_host_baseline` — compares current peers and DNS names with an explicit baseline without assigning a threat score.
- `search_related_events` — compatibility entry point that now treats a single supplied IP as source-or-destination and pairs as bidirectional.

Relative-time guards apply only to tools that accept a time window. `suricata_status` is a current global health check, and `correlate_flow` returns the complete indexed chain for a flow ID; neither accepts `lookback_minutes`. If a model supplies an unsupported argument, the runtime omits it and includes `tool_call_adjustment` in the result so the agent can disclose the actual search scope.

Python incrementally indexes newline-complete EVE records in SQLite and returns aggregates plus bounded pages of normalized evidence. Normal startup creates the database when absent, validates agent configuration, and synchronizes the EVE file before the TUI accepts a prompt. After every completed TUI answer, a background refresh uses an isolated SQLite writer connection. WAL mode lets the foreground connection immediately investigate the last committed snapshot while that writer prepares the next one; the writer's final commit makes the complete batch visible atomically. A physical second database is not required, avoiding a second copy of raw evidence and a risky ID/provenance merge. Foreground tool synchronization becomes a non-blocking no-op while the writer is active and reports that its snapshot may lag by the current refresh batch. One-shot `--ask` mode pre-syncs at startup but exits after its answer instead of leaving a background worker running. Source inode, generation, byte offset, and a stable `record_id` preserve provenance across normal rotation. Copy-truncate changes are detected using file size and a protected head fingerprint. Search results expose `total_count`, `returned`, `truncated`, `next_cursor`, timestamps, flow IDs, record IDs, and file offsets.

Search semantics use independent axes instead of one global de-duplication rule:

- `view=events|endpoints|flows|transactions` selects the result unit.
- `duplicates=preserve|annotate|group_exact` controls only canonical exact copies.
- `detail=compact|standard|raw` controls payload size without changing evidence selection.

`group_exact` is lossless: a representative item carries every underlying
`record_id`, source generation, and file offset. It never merges distinct
request, response, alert, application, or flow records merely because they
share a `flow_id`. Endpoint view groups DNS/mDNS by queried hostname, TLS/QUIC
by SNI, HTTP by host, and other records by remote peer/port/protocol. Transaction
view conservatively correlates request/response activity and states its basis.
`total_raw_records`, `returned_items`, `raw_records_covered`, and truncation are
reported separately so a displayed logical item is never mistaken for one raw
record. Exact duplicate records establish only that matching records occur in
canonical EVE; their upstream cause remains unknown without separate evidence.
If a model draft nevertheless attributes duplicates to TCP/IP behavior,
retransmission, generic network behavior, or query characteristics without
supporting evidence, the runtime requests a corrected evidence-bounded answer
before displaying it.

The cursor retains grouping keys already returned so later pages do not repeat them. Cursor
state is held in a bounded in-memory registry instead of embedding the complete
seen-endpoint list in every tool call. The model receives only a constant-size,
random `pg2_...` token, substantially reducing repeated context and token use as
pagination continues. Cursor state expires after two hours, is capped at 256
active pagination chains, and intentionally does not survive an agent restart;
an expired cursor returns an explicit error rather than silently restarting at
the first page. Older self-contained cursors remain readable and are converted
to the compact format on their next page.

Every incremental refresh and direct raw-EVE fallback captures the source byte length at start and stops there. Records appended after that boundary are intentionally deferred to the next refresh. If another answer completes while a refresh is active, one follow-up refresh is coalesced and runs immediately afterward. This prevents a busy, continuously growing `eve.json` from turning one synchronization or raw scan into an unbounded moving-EOF operation without dropping the next requested catch-up pass.

Startup emits line-oriented progress to stderr before opening the TUI. It reports EVE path/readability and size, whether the SQLite index is new or existing, source generation/checkpoint state, bounded ingestion percentages, rotation or copy-truncate detection, commit totals, verification state, schema version, indexed record count, malformed lines, and remaining source lag. Progress is throttled for large logs so it remains readable.

Verification is adaptive so the ever-growing index does not require a database-wide scan on every boot. The database-wide operation is SQLite `PRAGMA quick_check`: it scans database formatting, page linkage, B-tree structure, and freelist consistency. It omits the deeper index-to-table and UNIQUE-constraint validation performed by `integrity_check`, but its runtime still grows with the complete index size. New indexes, indexes without a prior successful check, previously failed checks, invalid verification metadata, and source-checkpoint discontinuities receive a blocking `quick_check`. A clean index with a recent successful check uses constant-time schema, health-metadata, checkpoint, and source-lag validation.

An unclean process exit by itself no longer forces a blocking database-wide scan when a prior successful verification exists. SQLite must first open/recover the WAL, and normal startup must successfully validate the schema, source checkpoint, incremental ingestion, and commit. The TUI can then open using the last committed snapshot while a database-wide `quick_check` starts on an independent connection after a brief idle grace period. The same background policy applies when the last check is at least 24 hours old or 250,000 records have been appended. A failed background check marks the live tool layer unhealthy so subsequent indexed searches stop instead of silently trusting questionable results. Graceful shutdown still records a clean-close marker, and `--verify-index` remains available whenever an operator wants an explicit blocking database-wide check.

`--build-index` continues to perform a blocking database-wide `quick_check` and uses stderr for progress while preserving machine-readable JSON on stdout. The equivalent explicit maintenance command is:

```bash
python3 suricata_agent.py \
  --eve-log /var/log/suricata/eve.json \
  --verify-index
```

It does not require an API key.

`Ctrl+C` is handled as a graceful shutdown during startup, indexing, one-shot questions, and the interactive TUI. After curses restores the terminal, the agent reports each cleanup stage, requests cooperative cancellation at safe model/tool checkpoints, waits up to five seconds for an active investigation or background index refresh, closes SQLite only when worker access has stopped, and exits with the conventional status `130` without a traceback. A second interrupt forces immediate process teardown while still suppressing traceback output. `/quit` follows the same cleanup path after safely dismissing the curses command menu and exits with status `0`; it does not produce a Python traceback.

The default index is a per-EVE-path database under `~/.cache/suricata-agent/`. Override it when needed:

```bash
python3 suricata_agent.py \
  --eve-log /var/log/suricata/eve.json \
  --index-path /secure/local/path/eve-index.sqlite3
```

Agent options can also be saved in an owner-only configuration file. This is optional;
`python3 suricata_agent.py` still runs with built-in defaults when no file exists.
The default config location is `~/.config/suricata-agent/config.json` (or under
`$XDG_CONFIG_HOME`). CLI `--eve-log`, `--index-path`, and `--debug` override saved
options for one run; `--config PATH` selects a different config file.

For an interactive setup menu, run:

```bash
python3 suricata_agent_config.py
```

The menu shows the current EVE path, index location, debug setting, source-log
permission policy, and backup directory. Changes remain a draft until you choose
**Save changes**; Quit offers save, discard, or cancel. It can check the resolved
paths and create an explicit index backup after a confirmation prompt. Saving
ordinary options does not call the model API, start the agent, or change
Suricata's log permissions; the separately confirmed option 10 can change
system permissions through `sudo`.
Restart the agent for saved options to take effect.

For a guided system-level source-log transition, save the agent options first,
then choose menu option **10**. It asks which existing group and local users run
the agent and `sdash`, shows a read-only plan, and requires typing `APPLY` before
it invokes a privileged helper via `sudo`. The helper checks that both users
belong to the group, that `sdash` points to the same EVE file, and that the
configured EVE path matches Suricata's output. It changes only the live EVE
file's group/mode, the Suricata log directory's group/setgid mode (so new EVE
files inherit the group), and the EVE logger's `filemode: 640`. The directory's
other-user permissions are preserved. The existing logrotate `create` directive
is checked but not edited; a bare `create` inherits the prior file owner/group/
mode. The directory group/setgid change can affect group inheritance for other
new Suricata log files, so review the plan before applying. If `sdash` already
has a settings file, its directory/file are also made owner-only and assigned
to the selected dashboard user. This repairs settings accidentally created by
an earlier privileged dashboard run; the previous owner/group/modes are saved
for rollback. The preview warns if this will activate dashboard preferences
that were previously ignored because the dashboard user could not read its
settings file.

Before changing anything, the helper records the original owner/group/mode and
exact Suricata configuration (plus existing dashboard-settings metadata) in a root-only snapshot under
`/var/lib/suricata-agent/log-access/`, then appends an audit entry. Menu option
**11** reverts the previous transition after `REVERT` confirmation; option
**12** shows the audit history. Revert refuses to overwrite independent edits
to the Suricata configuration or unexpected permission changes. Neither action
restarts Suricata, the agent, or `sdash`; restart the readers after a group
membership change and verify access again after the next log rotation. If
`sudo` is unavailable or denied, the menu reports that the system change did
not complete; no agent settings are changed. The helper can also be run
directly with `python3 core/suricata_log_access.py --help`.

For scripts and automation, the equivalent subcommands remain available:

```bash
python3 suricata_agent_config.py init
python3 suricata_agent_config.py show
python3 suricata_agent_config.py set eve_log /var/log/suricata/eve.json
python3 suricata_agent_config.py set index_path /secure/local/path/eve-index.sqlite3
python3 suricata_agent_config.py set security.source_log_permissions require_private
python3 suricata_agent_config.py set security.trusted_log_group suricata-readers
python3 suricata_agent_config.py set security.source_log_permissions trusted_group
python3 suricata_agent_config.py set security.backup_directory /secure/local/backups
python3 suricata_agent_config.py backup-index
```

The default source-log policy is `warn`: startup flags a group/world-readable
`eve.json` but does not change Suricata-managed permissions or stop the agent.
`require_private` rejects a source log readable by group or others before opening
the index. `trusted_group` permits a file with no `other` permissions and
read-only access for the one named `trusted_log_group`; it checks the actual
file group and the agent's group membership. Strict modes reject extended access
ACLs because their recipients cannot be established from mode bits alone.
Choose a strict mode only after arranging appropriate log ownership and agent
access. Index directories and database/WAL/SHM files are always required to be
owner-only; this protection cannot be disabled through config. Existing unsafe
paths fail closed with a permission error instead of being silently changed.

If startup reports `Cannot read EVE source`, follow the printed `namei -l`,
`stat`, and `id -nG` checks. The agent needs read permission on `eve.json` and
search (`x`) permission on every parent directory. For a dedicated-group setup,
give the log that group, add the agent user to it, and ensure the group/mode
survive Suricata restarts and log rotation. Configure the EVE logger's
`filemode: 640` in `suricata.yaml` and make sure its group ownership is the
trusted group; `filemode` sets permissions but does not itself select the group.
Restart the agent's login/session after changing group membership. Do **not**
blindly use `0600` if Suricata writes the log as another owner; that can lock
the agent out. The config UI's path check shows permission failures without
changing system files. [Suricata's EVE file-permission documentation](https://docs.suricata.io/en/suricata-8.0.0/output/eve/eve-json-output.html) describes `filemode`.

`backup-index` is explicit, not automatic. It creates an owner-only backup
directory and a uniquely named `0600` SQLite snapshot that includes committed
WAL data even if the agent is running. It does not remove older backups or index
records. Use `--destination DIR` to override the configured backup directory.
No automatic retention/deletion policy is enabled, because deleting indexed
history can remove evidence that is no longer present in the current EVE log.

For a large existing log, build or refresh the index before starting the agent.
This mode does not require an API key and does not contact OpenAI:

```bash
python3 suricata_agent.py \
  --eve-log /var/log/suricata/eve.json \
  --build-index
```

It prints index location, generation, ingested-record count, indexed offset,
remaining lag, malformed-line count, telemetry freshness, and event-type
coverage. Running it again ingests only newly appended complete records.

The index directory is created with owner-only access, and the database is created with mode `0600`. Existing index and sidecar paths are checked before SQLite opens them. It contains normalized fields and raw EVE JSON, so protect it like the source log. Raw EVE remains canonical; `count_raw_eve_matches` deliberately bypasses the index as a correctness check. The model cannot directly execute shell commands through this agent or modify Suricata configuration.

If an alert or other narrow search returns zero for a host, the runtime first checks broad indexed host activity. When broad activity exists, it verifies one indexed record against the exact canonical EVE file offset; this is proof of at least one raw match, **not** a full raw count. When broad indexed activity is also zero, or the witness cannot be verified, it performs a complete direct raw-EVE scan before allowing a negative conclusion. An explicit-window zero is also retried with a small expanded window when broad and raw checks remain empty. For exact IPv4 addresses, direct scans skip unrelated lines before JSON decoding; IPv6 and shorthand checks still parse every line to preserve canonical/suffix matching. The raw result reports scan completion and whether the source file remained the same generation throughout. This fallback prevents an alert-only query from being summarized as "no traffic."

IPv6 identities are compared canonically, so expanded and compressed forms match. If an exact IPv6 lookup misses, the tools may also recover a full EVE identity from an entered prefix plus at least two trailing hextets, but only when exactly one active identity matches in the selected window. The result exposes `requested_ip`, `resolved_ip`, `status`, candidate counts, confidence, and an explanatory note under `ip_resolution`. Multiple candidates are reported as `ambiguous_suffix` and are never merged. A `not_found` or ambiguous identity is not sufficient evidence that a device was inactive.

For questions such as "top five requests from this host,"
`investigate_host.top_requests` contains observed outbound DNS/mDNS queries and
HTTP host/URL requests. TLS SNI and generic destination flows are reported
separately under `outbound_observations`; they are useful activity evidence but
are not mislabeled as application requests.

Enable diagnostic logging when investigating tool selection or fallback behavior:

```bash
python3 suricata_agent.py --debug --eve-log /var/log/suricata/eve.json
```

Debug output includes interpreted intent, extracted IP text, tool arguments, index-ingestion counts, result counts, truncation, fallback reasons, and broad/raw fallback counts. The TUI status line separately identifies model waits, the active tool, zero-result fallback validation, and background index refresh, so a slow phase is no longer hidden behind a generic model/tools message. It never logs the API key.

## Worked example: alert-to-flow investigation

The abbreviated exchange below shows the intended workflow. The source example used during development is intentionally excluded from public packaging; this README contains the relevant documented workflow.

The system prompt instructs the model to verify broad activity before narrowing, use source-or-destination host matching by default, account for delayed flow timestamps, distinguish alert records from observations, correlate flow IDs and surrounding events, and explain truncation and uncertainty.

### User request

```text
Find the first available Suricata alert, retrieve its related event using the returned flow_id, then summarize the alert and correlated flow timestamp.
```

### First tool call

```json
{
  "name": "search_alerts",
  "arguments": {"limit": 1}
}
```

The local tool returns a native EVE alert, for example:

```json
{
  "timestamp": "2026-09-13T11:10:32.212583-0400",
  "event_type": "alert",
  "flow_id": 68613263252958,
  "src_ip": "192.0.2.7",
  "src_port": 19734,
  "dest_ip": "192.0.2.5",
  "dest_port": 80,
  "proto": "TCP",
  "in_iface": "wlan0",
  "alert": {
    "signature": "LOCAL SCAN Possible TCP SYN vertical scan rate",
    "signature_id": 1001101,
    "severity": 3,
    "category": "Detection of a Network Scan",
    "action": "allowed"
  }
}
```

Because this record exposes a `flow_id` rather than an `event_id`, the correct follow-up is:

```json
{
  "name": "get_event",
  "arguments": {"flow_id": 68613263252958}
}
```

The agent can then use `correlate_flow` with the same flow ID to retrieve the complete retained timeline. Exact flow-ID correlation is not discarded solely because the event is older than the normal wall-clock lookback window.

A factually grounded final response should state that Suricata generated SID `1001101` for TCP SYN activity from `192.0.2.7` to `192.0.2.5:80`, preserve the timestamp and shared flow ID, and explain that `action: "allowed"` means the IDS logged the activity without blocking it. It should not claim that the alert alone proves malicious intent, a unique-port scan, exploitation, or compromise. The model should identify what was observed, what was correlated, what remains uncertain, and what additional read-only investigation is appropriate.

## Evidence boundaries

- Confirmed evidence: fields read from EVE JSON or local configuration by `SuricataTools`.
- Deterministic processing: bounded filtering, timestamp windows, event matching, and compact result construction in Python.
- AI interpretation: the model’s correlation, assessment, uncertainty, and recommendations based on tool results.

The agent is analyst assistance, not an autonomous SOC response system. It does not block traffic, change rules, restart Suricata, or claim that an empty query proves the environment is safe.

## Privacy

The agent sends the user’s question, conversation history, tool-call metadata, and returned security evidence to the configured OpenAI API. Review organizational policy before sending raw security telemetry. The local SQLite index also contains sensitive EVE evidence and must not be shared or committed. Avoid committing context files, indexes, EVE logs, API keys, or other sensitive data.
