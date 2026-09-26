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

The agent reads local telemetry and uses read-only investigation tools. It does not modify Suricata, block traffic, or perform autonomous response actions.

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
