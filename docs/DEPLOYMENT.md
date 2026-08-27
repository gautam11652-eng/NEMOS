# Deployment

## Local development

NEMOS defaults to `127.0.0.1`, which is the safest mode for a single Kali workstation.

Create an isolated environment, install the pinned dependencies, and run `python main.py`.

Packet capture may require Linux capabilities. Prefer the systemd template for a persistent deployment rather than running the entire application as root.

## systemd deployment

The repository includes `packaging/systemd/nemos.service`.

Recommended layout:

- application: `/opt/nemos`
- database: `/var/lib/nemos/nemos.db`
- environment: `/etc/nemos/nemos.env`
- service account: `nemos`

The service uses only `CAP_NET_RAW` for packet capture and otherwise runs without root privileges. Its systemd sandbox explicitly permits the Linux `AF_PACKET` and `AF_NETLINK` families Scapy needs for raw capture and interface discovery. The dashboard exposes capture state so a missing capability is shown as `CAPTURE BLOCKED` rather than silently presenting zero telemetry.

Do not expose the dashboard remotely without setting `NEMOS_API_TOKEN` and `NEMOS_TRUSTED_HOSTS`.

## Remote deployment

Put NEMOS behind a trusted network boundary or reverse proxy where appropriate. Use a long random API token, restrict the listening address, and restrict firewall access to authorized administrators.

## Security verification

Run:

```bash
python -m compileall -q main.py nemos tests
python -m pytest -q
python -m pip_audit -r requirements.txt
```

`pip-audit` checks Python package dependencies against known vulnerability databases; it is not a substitute for source-code review or network testing.

Waitress is used as the production WSGI server. It is designed as a production-quality WSGI server; do not use Flask's development server for remote deployments.


## One-command Kali installation

From the NEMOS project root:

```bash
sudo ./install.sh
```

The installer creates the `nemos` service account, installs the pinned dependencies into `/opt/nemos/.venv`, creates `/var/lib/nemos` for the SQLite database, installs the systemd unit, enables it at boot, and starts it.

Useful commands:

```bash
sudo systemctl status nemos
sudo journalctl -u nemos -f
sudo systemctl restart nemos
sudo systemctl stop nemos
```

The configuration file is `/etc/nemos/nemos.env`. The default dashboard remains local-only at `http://127.0.0.1:5000`.

## Live smoke test

After the service is running, verify the complete API-to-SQLite-to-dashboard path with:

```bash
sudo NEMOS_REQUIRE_CAPTURE=true ./scripts/smoke-test.sh
```

If the API is exposed with `NEMOS_API_TOKEN`, provide it in the environment:

```bash
sudo NEMOS_API_TOKEN='your-token' NEMOS_REQUIRE_CAPTURE=true ./scripts/smoke-test.sh
```

The smoke test uses RFC 5737 documentation IP addresses and submits one harmless
synthetic TCP telemetry event. It checks health, dashboard access, SQLite telemetry
persistence, status/metrics, capture state (when requested), and the dashboard JS asset.
