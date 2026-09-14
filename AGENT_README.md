# Suricata Agent and Interactive UI

`suricata_agent.py` is the optional investigation interface. It combines a local terminal UI with an OpenAI Chat Completions request loop and four bounded, read-only local tools.

## Setup

```bash
python3 -m venv .venv
. .venv/bin/activate
python3 -m pip install -r requirements.txt
python3 setup_openai_env.py
```

The setup helper prompts without echoing the API key, writes a project-local `.env`, and applies owner-only permissions (`0600`). Do not commit `.env`.

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
| `/quit` | Exit the UI |

### Slash-command menu

When the input begins with `/`, the UI displays a command dropdown above the input line. The list narrows as the command is typed. Use the Up/Down arrows to select a command, `Tab` to insert the highlighted command, and Enter to run an exact command. Pressing Enter while the input is only a partial match inserts the highlighted command first; press Enter again to execute it.

### The `/context` feature

`/context` is implemented in `Interface.save_context()` in `suricata_agent.py`.

It creates a file beside the agent program using this filename pattern:

```text
context_YYYYMMDD_HHMMSS.txt
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

The runtime in `agent_runtime.py` calls:

```text
user question -> OpenAI Chat Completions -> optional tool calls
-> local SuricataTools function -> JSON tool result
-> model follow-up -> final answer
```

The default model is `gpt-4o-mini`; `OPENAI_MODEL` can override it. The runtime permits up to eight tool-call iterations for one question. Tool schemas are supplied as function tools with `tool_choice: "auto"`.

Available read-only tools:

- `get_sensor_status` — reports local config/log availability, capture interfaces, and managed-rule information.
- `search_alerts` — searches EVE alert records by source, destination, signature text, SID, severity, and bounded lookback.
- `get_event` — retrieves one event by `event_id` or exact `flow_id`; the latter is important because many Suricata alert records expose a flow ID without an event ID.
- `search_related_events` — correlates nearby records by flow ID or source/destination pair.

Python reads and bounds the local EVE data before returning compact JSON to the model. The model may choose tools and make several calls, but it cannot directly execute shell commands through this agent or modify Suricata configuration. The final answer is model-generated and should be checked against the returned event IDs, timestamps, and raw telemetry.

## Worked example: alert-to-flow investigation

The abbreviated exchange below shows the intended workflow. The source example used during development is intentionally excluded from public packaging; this README contains the relevant documented workflow.

The system prompt instructs the model to gather evidence first, keep queries narrow, distinguish `event_id` from `flow_id`, separate observed evidence from interpretation, and explain the selected time window when a query returns no results.

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

The agent can then use `search_related_events` with the same flow ID to find the alert’s associated flow record. Exact flow-ID correlation is not discarded solely because the event is older than the normal wall-clock lookback window.

A factually grounded final response should state that Suricata generated SID `1001101` for TCP SYN activity from `192.0.2.7` to `192.0.2.5:80`, preserve the timestamp and shared flow ID, and explain that `action: "allowed"` means the IDS logged the activity without blocking it. It should not claim that the alert alone proves malicious intent, a unique-port scan, exploitation, or compromise. The model should identify what was observed, what was correlated, what remains uncertain, and what additional read-only investigation is appropriate.

## Evidence boundaries

- Confirmed evidence: fields read from EVE JSON or local configuration by `SuricataTools`.
- Deterministic processing: bounded filtering, timestamp windows, event matching, and compact result construction in Python.
- AI interpretation: the model’s correlation, assessment, uncertainty, and recommendations based on tool results.

The agent is analyst assistance, not an autonomous SOC response system. It does not block traffic, change rules, restart Suricata, or claim that an empty query proves the environment is safe.

## Privacy

The agent sends the user’s question, conversation history, tool-call metadata, and returned security evidence to the configured OpenAI API. Review organizational policy before sending raw security telemetry. Avoid committing context files, EVE logs, API keys, or other sensitive data.
