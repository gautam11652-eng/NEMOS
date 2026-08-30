# NEMOS

NEMOS is an open-source, defensive network monitoring and intrusion-detection platform for systems and networks you own or are authorized to monitor.

## NEMOS

The  deployment build includes local cross-site write protection, bounded Waitress request handling, and capture-state diagnostics.

NEMOS is an open-source, defensive network monitoring and intrusion-detection platform designed for local, explainable security operations.

## Highlights
- Real packet capture with Scapy
- Bounded, stateful detections: port scans, SYN-flood patterns, ICMP floods, network fan-out, DNS bursts, service-connection bursts and ARP mapping changes
- MITRE ATT&CK technique references where the mapping is meaningful
- SQLite WAL + single batched writer thread
- Security headers, request-size limits and token-protected API operations (health remains public)
- Loopback-only default
- Responsive SOC dashboard with a clean light workspace and dark navigation sidebar with one consolidated polling request and guarded 10-second polling
- Tests and a clean source-only distribution; no virtual environment or runtime database is committed

## Requirements
Python 3.10+ is recommended. Packet capture on Linux requires the privileges/capabilities needed by Scapy.

## Quick start
```bash
git clone <your-repository-url>
cd nemos
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt
python main.py
```
Open `http://127.0.0.1:5000`.

For a specific interface:
```bash
NEMOS_INTERFACE=eth0 python main.py
```

If capture fails with a permission error, use the included systemd service so only the packet-capture capability is granted. Do not run the entire web application as root for production deployments. The dashboard reports capture state explicitly.

## Remote dashboard
Do not bind the dashboard to `0.0.0.0` casually. If you deliberately need a remote listener, set a strong token:
```bash
export NEMOS_HOST=0.0.0.0
export NEMOS_API_TOKEN="$(python3 -c 'import secrets; print(secrets.token_urlsafe(32))')"
# Replace with the hostname/IP clients will use in the Host header.
export NEMOS_TRUSTED_HOSTS=192.168.1.50
python main.py
```
Use HTTPS/reverse-proxy protection for any deployment outside a trusted local environment.

## Kali verification

From the extracted project directory, run:
```bash
./scripts/verify-kali.sh
```
This creates the isolated environment, installs the pinned dependencies, checks dependency consistency, compiles the application, checks the dashboard JavaScript when Node.js is available, and runs the full test suite.

## Testing
```bash
python -m unittest discover -s tests -v
python -m compileall -q nemos main.py
```

## API
- `GET /api/health`
- `GET /api/dashboard`
- `GET /api/stats`
- `GET /api/alerts`
- `GET /api/traffic`
- `GET /api/status` — capture and writer health
- `POST /api/packet` — compatibility/test ingestion endpoint
- `POST /api/alerts/<id>/ack` — acknowledge an alert
- `POST /api/alerts/clear` — clear alerts

When `NEMOS_API_TOKEN` is configured, every `/api/*` endpoint except `/api/health` requires `X-NEMOS-Token`. The dashboard prompts for the token and keeps it only in the current browser session storage.

## Security model
NEMOS is a monitoring tool, not a guarantee of security. Detection thresholds are intentionally conservative and should be tuned to the monitored environment. False positives are possible. Keep the host OS, Python runtime and dependencies patched and avoid exposing the development server directly to untrusted networks.

## License
GPL-2.0-only. See `LICENSE` and `THIRD_PARTY_LICENSES.md`. Scapy is GPL-2.0-only, so this distribution uses a GPL-compatible project license.


### SOC command center
NEMOS includes a responsive local SOC interface with a live threat timeline, risk distribution, host triage, ATT&CK technique view, correlated-incident investigation, and a lightweight network connection graph.

## Detection Engine v3

NEMOS combines bounded, deterministic network rules with an explainable per-source behavioural baseline. Reconnaissance findings distinguish TCP SYN scans, UDP port scans, vertical port scans, network fan-out and ICMP sweeps. Alerts include evidence, confidence and an ATT&CK technique only where the observed behaviour supports that mapping. Generic traffic anomalies intentionally remain unmapped rather than being assigned a misleading technique.



## SIH / demonstration

Use `python tools/validate_detection.py` for a safe offline demonstration using synthetic documentation-address telemetry. See `docs/SIH_DEMO.md`, `docs/DEMO_SCRIPT.md` and `docs/SIH_SLIDE_OUTLINE.md`.

## Telegram Alerts

NEMOS can send security alerts and notifications through Telegram.

### Setup

Each user/deployment must use their own Telegram bot and credentials.

1. Open Telegram and start a chat with **@BotFather**.
2. Create a new bot using `/newbot`.
3. Copy the bot token provided by BotFather.
4. Send a message to your new bot.
5. Obtain your Telegram chat ID.
6. Add the following values to your local `.env` file:

```env
TELEGRAM_BOT_TOKEN=your_bot_token
TELEGRAM_CHAT_ID=your_chat_id
```

Keep these credentials private. Do not commit your `.env` file or bot token to Git.

After configuration, NEMOS can use the Telegram integration to deliver security alerts and notifications to the configured chat.
