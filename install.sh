#!/usr/bin/env bash
set -euo pipefail

# NEMOS installer: installs the current source tree as /opt/nemos and registers
# the least-privilege systemd service. Run from the project root.

INSTALL_DIR="/opt/nemos"
STATE_DIR="/var/lib/nemos"
CONFIG_DIR="/etc/nemos"
SERVICE_FILE="/etc/systemd/system/nemos.service"
SOURCE_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

if [[ "${EUID}" -ne 0 ]]; then
  echo "Run this installer with sudo: sudo ./install.sh" >&2
  exit 1
fi

for cmd in python3 systemctl install cp tar; do
  command -v "$cmd" >/dev/null 2>&1 || {
    echo "Missing required command: $cmd" >&2
    exit 1
  }
done

if ! python3 -c 'import venv' >/dev/null 2>&1; then
  echo "Python venv support is missing. Install python3-venv and rerun." >&2
  exit 1
fi

if ! id nemos >/dev/null 2>&1; then
  useradd --system --home-dir "$STATE_DIR" --create-home --shell /usr/sbin/nologin nemos
fi

install -d -o nemos -g nemos -m 0750 "$STATE_DIR"
install -d -o root -g root -m 0755 "$INSTALL_DIR"
install -d -o root -g root -m 0755 "$CONFIG_DIR"

# Copy source without local virtual environments, caches, databases or git data.
# This keeps reinstallations deterministic and prevents local runtime state from
# becoming part of the installed application.
tar -C "$SOURCE_DIR" \
  --exclude='./.venv' \
  --exclude='./.git' \
  --exclude='./.pytest_cache' \
  --exclude='./__pycache__' \
  --exclude='./data' \
  -cf - . | tar -C "$INSTALL_DIR" -xf -

python3 -m venv "$INSTALL_DIR/.venv"
"$INSTALL_DIR/.venv/bin/python" -m pip install --upgrade pip
"$INSTALL_DIR/.venv/bin/pip" install -r "$INSTALL_DIR/requirements.txt"

install -o root -g root -m 0644 \
  "$INSTALL_DIR/packaging/systemd/nemos.service" "$SERVICE_FILE"

if [[ ! -f "$CONFIG_DIR/nemos.env" ]]; then
  install -o root -g nemos -m 0640 \
    "$INSTALL_DIR/packaging/systemd/nemos.env.example" "$CONFIG_DIR/nemos.env"
fi

# Runtime files belong to the service account. Keep source and configuration
# root-owned so the network-facing process cannot rewrite its own code.
chown -R root:root "$INSTALL_DIR"
chown -R nemos:nemos "$STATE_DIR"
install -d -o nemos -g nemos -m 0700 "$INSTALL_DIR/data"
chmod 0750 "$STATE_DIR"

systemctl daemon-reload
systemctl enable nemos
systemctl restart nemos

if ! systemctl is-active --quiet nemos; then
  echo "NEMOS failed to start. Show the logs with:" >&2
  echo "  sudo journalctl -u nemos -n 100 --no-pager" >&2
  exit 1
fi

echo
 echo "NEMOS installed and running."
echo "Dashboard: http://127.0.0.1:5000"
echo "Status:    sudo systemctl status nemos"
echo "Logs:      sudo journalctl -u nemos -f"
echo "Config:    $CONFIG_DIR/nemos.env"
