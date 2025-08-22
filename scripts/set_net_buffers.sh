#!/bin/bash

# Description: Increase UDP buffer sizes permanently
# Usage: sudo ./increase_udp_buffers.sh

# -euxo x => print command
set -euo pipefail

DEFAULT_SIZE=$((1024 * 1024 * 8))   # 8 MB
MAX_SIZE=$((DEFAULT_SIZE * 2))      # 16 MB

echo "Updating /etc/sysctl.conf with new UDP buffer limits..."

sudo tee -a /etc/sysctl.conf > /dev/null <<EOF

# Default and max read and write buffer sizes
net.core.rmem_max=$MAX_SIZE
net.core.rmem_default=$DEFAULT_SIZE
net.core.wmem_max=$MAX_SIZE
net.core.wmem_default=$DEFAULT_SIZE
EOF

echo "Applying changes with sysctl..."
sudo sysctl -p

echo "Done. New buffer values:"
sysctl net.core.rmem_default
sysctl net.core.rmem_max
sysctl net.core.wmem_default
sysctl net.core.wmem_max
