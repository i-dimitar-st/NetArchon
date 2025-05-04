#!/bin/bash

# Configuration
SERVICE_NAME="netarchon"
WORKDIR="/projects/gitlab/netarchon"
EXEC="$WORKDIR/venv/bin/python"
SCRIPT="$WORKDIR/main.py"
UNIT_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
USER_NAME="$(whoami)"

# Check if Python executable exists
if [[ ! -f "$EXEC" ]]; then
    echo "Python binary not found at $EXEC"
    exit 1

# Create systemd service file
echo "Creating systemd unit at $UNIT_FILE"
sudo bash -c "cat > $UNIT_FILE" <<EOF

[Unit]
Description=NetArchon Service
After=network.target

[Service]
Type=simple
User=$USER_NAME
WorkingDirectory=$WORKDIR
ExecStart=$EXEC $SCRIPT
Restart=on-failure
RestartSec=5
StandardOutput=journal
StandardError=journal

Environment=PYTHONUNBUFFERED=1
Environment=NETARCHON_LOG_LEVEL=debug
Environment=NETARCHON_APP_MODE=production
Environment=NETARCHON_CONFIG_PATH=$WORKDIR/config/settings.json

[Install]
WantedBy=multi-user.target
EOF

# # Set capabilities for low ports or raw sockets if required
# echo "Setting Python capabilities for networking (bind <1024, raw access)"
# sudo setcap cap_net_bind_service,cap_net_admin=eip "$EXEC"

# Reload systemd and enable the service
echo "Reloading systemd and enabling service..."
sudo systemctl daemon-reexec
sudo systemctl daemon-reload
sudo systemctl enable "$SERVICE_NAME"
sudo systemctl restart "$SERVICE_NAME"

# Confirm status
echo "Service '$SERVICE_NAME' setup complete. Status:"
sudo systemctl status "$SERVICE_NAME" --no-pager