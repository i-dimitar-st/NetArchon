#!/bin/bash

set -euo pipefail

if [ -z "${ROOT_PATH:-}" ]; then
  echo "ERROR: ROOT_PATH is not set."
  exit 1
fi

SERVICE_NAME="netarchon"
WORKDIR=$ROOT_PATH
RUNNER=$WORKDIR/run.sh

UNIT_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
USER_NAME="$(whoami)"

echo "systemd at $UNIT_FILE"
sudo bash -c "cat > $UNIT_FILE" <<EOF

[Unit]
Description=NetArchonService
After=network.target

[Service]
Type=simple
User=$USER_NAME
WorkingDirectory=$WORKDIR
ExecStart=$RUNNER
Restart=on-failure
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable "$SERVICE_NAME"
sudo systemctl restart "$SERVICE_NAME"
sudo systemctl status "$SERVICE_NAME" --no-pager
