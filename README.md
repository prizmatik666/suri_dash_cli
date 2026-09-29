# Suricata Security Analysis Toolkit

A portable terminal dashboard and optional read-only OpenAI tool-calling agent for local Suricata EVE JSON investigations.

This repository contains two separate user interfaces that can read the same Suricata telemetry:

- [`sdash.py`](sdash.py) — fast local dashboard for live events, native alerts, and flow-based scan correlation. See [`SDASH_README.md`](SDASH_README.md).
- [`suricata_agent.py`](suricata_agent.py) — interactive agent/UI that queries local EVE data through bounded read-only tools and asks the OpenAI API to analyze the returned evidence. See [`AGENT_README.md`](AGENT_README.md).

Run user-facing commands from the repository root: `sdash.py`, `sdash_setup.py`,
`slog.py`, `suricata_stats.py`, `suricata_agent.py`, `suricata_agent_config.py`,
`suricata_interface_tool.py`, and `setup_openai_env.py`. Internal modules live
under [`core/`](core/); they are imported by those commands, not run as setup
programs. The repository also includes example local rules.

For Suricata's text-format `stats.log`, use the dedicated summary viewer. In a
terminal it opens a scrollable TUI; arrows and Page Up/Down scroll, Home/End
jump, `/` searches, `c` opens counter settings, `r` refreshes, and `q` exits.
Add `--watch` for automatic refreshes or `--plain` to print a normal text
report:

```bash
python3 suricata_stats.py
python3 suricata_stats.py --watch
python3 suricata_stats.py --all --samples 30
```

It reads only recent snapshot blocks from `stats.log`, reports current counters
and rates between snapshots, and can show every counter in the latest sample.
It does not parse or display EVE event records. Press `c` in the TUI to open the
counter settings menu. The menu lists every counter in the latest stats snapshot;
use Space/Enter to toggle counters, `s` to save, `r` to immediately restore the
developer defaults, and `q` to close and discard unsaved changes. Settings are
saved as owner-only JSON in `~/.config/suricata-agent/stats_config.json` (or
under `$XDG_CONFIG_HOME`). You can open the menu directly with
`python3 suricata_stats.py --configure`, or restore defaults with
`python3 suricata_stats.py --reset-config`.

The dashboard’s guided setup panel is launched separately:

```bash
python3 sdash_setup.py
```

It stores user preferences under `~/.config/sdash/config.json`. The built-in v3.5 PRIZM defaults are hardcoded in `core/sdash_defaults.py` and can always be restored from the setup panel.

## Quick start

```bash
git clone https://www.github.com/prizmatik666/suri_dash_cli.git
cd suri_dash_cli/
```

### Dashboard: no virtual environment required

The dashboard and its local utilities use the Python standard library and the
modules included in this repository. A virtual environment, `pip install`, and
an OpenAI API key are **not required** to run the dashboard.

Run it directly with the system Python:

```bash
python3 sdash.py --log /var/log/suricata/eve.json
# Or use the default log path:
python3 sdash.py
```

Configure an interface interactively, with validation and a timestamped backup:

```bash
sudo python3 suricata_interface_tool.py
```

Browse Suricata log files with the separate log viewer:

```bash
python3 slog.py
```

Its file picker fits the terminal height: use Up/Down, PgUp/PgDn, Home/End,
type a displayed number to jump, `/` to filter filenames, `c` to clear the
filter, and Enter to open a log.
The following size menu has a `b` option to return to the file picker. Use
`python3 slog.py --file eve.json` to skip the picker. Limited views now
read only the requested first lines; tail views keep only the requested last
lines in memory (a tail of a compressed file still scans the file). In the
viewer, `n`/Enter and `p` change pages, `g`/`G` jump to the first/last page,
`b` returns to the file list, `q` opens save/next options, `x` exits after the
current view, and `h` prints the controls again.

### Optional agent: virtual environment recommended, not required

The agent requires an OpenAI API key plus the `requests` and `python-dotenv`
packages from `requirements.txt`. It does not create or activate a virtual
environment when it starts. A virtual environment is recommended to isolate
these packages, but it is **not strictly necessary**. If compatible packages
are already installed for your system Python, the agent can run directly with
`python3`.

Recommended isolated setup:

```bash
python3 -m venv .venv
. .venv/bin/activate
python3 -m pip install -r requirements.txt
python3 setup_openai_env.py
python3 suricata_agent.py --eve-log /var/log/suricata/eve.json
```

Without activating the environment later, the same installation can be used
explicitly:

```bash
.venv/bin/python suricata_agent.py --eve-log /var/log/suricata/eve.json
```

#### Agent setup without a virtual environment

On Debian or Ubuntu, install the dependencies for the system Python through the
OS package manager:

```bash
sudo apt update
sudo apt install python3-requests python3-dotenv
python3 setup_openai_env.py
python3 suricata_agent.py --eve-log /var/log/suricata/eve.json
```

On systems that permit Python user-site installations, this is another
no-venv option:

```bash
python3 -m pip install --user -r requirements.txt
python3 setup_openai_env.py
python3 suricata_agent.py --eve-log /var/log/suricata/eve.json
```

The setup helper stores the API key in the project-local `.env` file. That file
is separate from `.venv` and is loaded automatically whenever the agent starts.
If `requests` and `python-dotenv` are already importable, skip the dependency
installation and run the setup helper and agent directly.

#### Model and API compatibility

The agent uses Python's `requests` library as its HTTP client to call OpenAI's
`/v1/responses` endpoint. It uses the **Responses API**, not the legacy Chat
Completions endpoint. The default model is `gpt-6-sol`; set `OPENAI_MODEL` to
override it. An alternate model must be available to your API account and
support the Responses API's text input/output and function-calling tools. Not
every OpenAI model or endpoint-specific model supports those capabilities; see
the [model catalog](https://developers.openai.com/api/docs/models) and
[Responses API quickstart](https://platform.openai.com/docs/quickstart/make-your-first-api-request).

## Choosing the Agent Model

The agent defaults to `gpt-6-sol`. Its stronger reasoning can be useful for
complex investigations, but it may be cost-intensive. For a lower-cost balance
of capability and price, we recommend `gpt-5.6-terra` as a starting point.

To change the model or reasoning effort, edit the project `.env` file and add
or update these settings:

```dotenv
OPENAI_MODEL=gpt-5.6-terra
OPENAI_REASONING_EFFORT=medium
```

Use the model ID exactly as shown: `gpt-5.6-terra` (with a hyphen between
`5.6` and `terra`). Reasoning-effort options are model-specific; `medium` is a
balanced setting supported by GPT-5.6. Check the selected model's current API
documentation before choosing a different effort. Restart the agent after
editing `.env` for the settings to take effect.

The current cost estimator reports an estimate only for the default
`gpt-6-sol` model. Token-usage reporting continues to work with other models,
but the estimated cost is shown as unavailable until that model is added to
the estimator. The selected model must also be enabled for your OpenAI API
account and support the Responses API and function calling used by this agent.


For example, `gpt-4o-mini` can use the current request format when it is enabled
for your account. The agent does not send a reasoning-effort option for that
model by default:

```bash
OPENAI_MODEL=gpt-4o-mini python3 suricata_agent.py --eve-log /var/log/suricata/eve.json
```

Reasoning-effort support and accepted values vary by model. Currently, the
runtime automatically sends `medium` for model IDs beginning with `gpt-5` or
`gpt-6`; for other model IDs it omits the option unless
`OPENAI_REASONING_EFFORT` is explicitly set. That prefix-based default is not
valid for every model—for example, GPT-5 Pro supports only `high`—so set an
effort accepted by the selected model when needed:

```bash
OPENAI_MODEL=gpt-5-pro OPENAI_REASONING_EFFORT=high python3 suricata_agent.py --eve-log /var/log/suricata/eve.json
```

See OpenAI's [reasoning guide](https://developers.openai.com/api/docs/guides/reasoning)
for current model-specific options. Cost estimation is currently implemented
only for `gpt-6-sol`; it is reported as unavailable for other models. Changing
`OPENAI_MODEL` changes the model, not the investigation tools or their local
evidence sources. Confirm compatibility with a small live query after changing
models; the automated unit/regression suite is offline.

The agent reads local telemetry and uses read-only investigation tools. It does not modify Suricata, block traffic, or perform autonomous response actions.

The investigation layer searches hosts as source **or** destination by default,
matches both EVE record timestamps and `flow.start`/`flow.end`, aggregates broad
host activity before drawing conclusions, correlates flow IDs and nearby events,
classifies TCP outcomes conservatively, and automatically checks raw EVE data
when a narrow search returns zero. Use `--debug` to print tool choices, counts,
and fallback reasons to stderr.

IPv6 searches normalize compressed and expanded forms. When an entered address
is an incomplete device label rather than the full EVE identity, the tools may
recover it only if one active address uniquely matches its prefix and trailing
hextets. That resolution is shown explicitly; ambiguous candidates are never
combined, and an unresolved identity is never treated as proof of inactivity.
Host summaries return bounded `top_requests` for observed outbound DNS/mDNS and
HTTP requests. TLS SNI and generic flow destinations appear separately as
outbound observations.

The agent keeps result selection separate from presentation. Searches can
return events, endpoints, flows, or conservatively correlated transactions;
exact duplicate records can be preserved, annotated, or losslessly grouped.
Grouped copies retain every record ID and file offset. A shared `flow_id` never
causes distinct request, response, alert, TLS, HTTP, or flow records to be
discarded. Explicit raw-record requests remain ungrouped. Endpoint searches
group DNS names, TLS/QUIC SNI, HTTP hosts, or remote network peers as appropriate.

Pagination uses short, constant-size local cursor tokens. Snapshot boundaries,
the resolved time window, raw offset, and previously returned unique endpoints
remain inside the running agent instead of being repeatedly sent through the
model. This keeps “next page” requests stable while preventing cursor text and
token use from growing with every page. Cursors expire after two hours and do
not survive an agent restart.

Agent lookups use an incremental SQLite index under `~/.cache/suricata-agent/`.
Normal agent startup creates the index when needed and synchronizes all existing
newline-complete records before accepting an interactive prompt. After each TUI
answer, the agent refreshes newly appended EVE records through an isolated
SQLite writer connection while the user reads the response. WAL snapshots let
a new question immediately use the last complete commit instead of waiting for
that refresh. Once the bounded batch commits, subsequent tools see it atomically.
Each refresh and raw-EVE fallback stops at the source size captured when it
started, so a rapidly growing live log cannot keep one operation chasing a
moving EOF indefinitely. Overlapping refresh requests are coalesced into one
immediate follow-up pass. Searches retain a non-blocking incremental sync as a
correctness check. Indexed
evidence retains source generation, inode, byte offset, and stable record IDs.
Use `--index-path PATH` to select a different protected location. The original
EVE files remain canonical evidence. Startup prints each log/index check,
bounded ingestion progress, verification state, record count, malformed-line
count, and byte lag to stderr so a large first build does not look hung. New or
unverified indexes and source-checkpoint discontinuities receive a blocking,
database-wide SQLite `quick_check`. After an unclean exit, an index with a prior
successful check uses fast WAL/schema/checkpoint/lag recovery validation and
schedules `quick_check` on a separate connection after a brief idle period.
Checks older than 24 hours or 250,000 records are likewise refreshed in the
background after the TUI opens. Use `--verify-index` to request a blocking check.
Pressing `Ctrl+C` restores the terminal and runs a structured shutdown: active
investigations receive a cancellation request, index workers are allowed to
finish safely, SQLite is closed, and the process exits with status `130`
without printing a Python traceback. Entering `/quit` uses the same cleanup
sequence and exits normally with status `0`.

While a question is active, the status line now identifies whether the agent is
waiting for the model, running a named tool, or validating a zero result. This
makes model/API latency distinguishable from SQLite and raw-log work.
If OpenAI returns a context-length HTTP 400, the agent trims older conversation
and compacts large tool results, preserves the active question and evidence
references, then retries once. It tells the user when that recovery occurs.
Pre-build or refresh a large index without an API call using:

```bash
python3 suricata_agent.py --eve-log /var/log/suricata/eve.json --build-index
```

Force a blocking full integrity check without starting the agent or requiring
an API key:

```bash
python3 suricata_agent.py --eve-log /var/log/suricata/eve.json --verify-index
```

## Important limits

Suricata must actually capture the traffic of interest and produce decodable Ethernet/IP traffic. A Wi-Fi interface in raw monitor mode may produce unsupported 802.11 datalink frames for AF_PACKET and therefore no normal flow/alert events. A normal client interface generally sees that host’s traffic, not all unicast traffic between other wireless clients.

The dashboard’s scan messages are flow-based heuristics. They are distinct from native Suricata `event_type: "alert"` records. The included rules count matching packets/rule matches; they do not calculate unique destination ports or hosts.


## Documentation

- [Dashboard guide](SDASH_README.md)
- [Agent and interactive UI guide](AGENT_README.md)
- [Example local rules](rules/local.rules)

## License

`suri_dash_cli` is source-available for personal, educational, and
noncommercial security-research use.

Commercial use, resale, paid-service integration, and incorporation into
commercial products require prior permission from the copyright holder.

See [LICENSE](LICENSE) for the full terms.
