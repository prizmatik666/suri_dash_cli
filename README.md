# Suricata Security Analysis Toolkit

A portable terminal dashboard and optional read-only OpenAI tool-calling agent for local Suricata EVE JSON investigations.

This repository contains two separate user interfaces that can read the same Suricata telemetry:

- [`sdash.py`](sdash.py) — fast local dashboard for live events, native alerts, and flow-based scan correlation. See [`SDASH_README.md`](SDASH_README.md).
- [`suricata_agent.py`](suricata_agent.py) — interactive agent/UI that queries local EVE data through bounded read-only tools and asks the OpenAI API to analyze the returned evidence. See [`AGENT_README.md`](AGENT_README.md).

Supporting files include example local rules, an AF_PACKET interface-selection utility, the OpenAI environment setup helper, and the agent’s runtime/tool modules.

The dashboard’s guided setup panel is launched separately:

```bash
python3 sdash_setup.py
```

It stores user preferences under `~/.config/sdash/config.json`. The built-in v3.5 PRIZM defaults are hardcoded in `sdash_defaults.py` and can always be restored from the setup panel.

## Quick start

```bash
git clone https://www.github.com/prizmatik666/suri_dash_cli.git
cd suricata_new
```

Run the dashboard:

```bash
python3 sdash.py --log /var/log/suricata/eve.json
```

Configure an interface interactively, with validation and a timestamped backup:

```bash
sudo python3 suricata_interface_tool.py
```

The optional agent requires an OpenAI API key and Python dependencies:

```bash
python3 -m venv .venv
. .venv/bin/activate
python3 -m pip install -r requirements.txt
python3 setup_openai_env.py
python3 suricata_agent.py --eve-log /var/log/suricata/eve.json
```

The agent reads local telemetry and uses read-only investigation tools. It does not modify Suricata, block traffic, or perform autonomous response actions.

## Important limits

Suricata must actually capture the traffic of interest and produce decodable Ethernet/IP traffic. A Wi-Fi interface in raw monitor mode may produce unsupported 802.11 datalink frames for AF_PACKET and therefore no normal flow/alert events. A normal client interface generally sees that host’s traffic, not all unicast traffic between other wireless clients.

The dashboard’s scan messages are flow-based heuristics. They are distinct from native Suricata `event_type: "alert"` records. The included rules count matching packets/rule matches; they do not calculate unique destination ports or hosts.

Do not commit `.env`, API keys, raw EVE logs, private addresses, credentials, or other sensitive telemetry.

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
