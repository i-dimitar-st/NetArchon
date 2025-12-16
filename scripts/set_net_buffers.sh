#!/bin/bash

# Description: Optimize Linux network stack for high-throughput UDP/TCP
# Usage: sudo ./network_optimization.sh

set -euo pipefail

# ----------------------------------------
# 1. UDP buffer sizes
# ----------------------------------------
DEFAULT_UDP=$((1024 * 1024 * 8))   # 8 MB
MAX_UDP=$((DEFAULT_UDP * 2))       # 16 MB

echo "Setting UDP buffer sizes..."

# Only append if not already present
grep -q "net.core.rmem_max" /etc/sysctl.conf || sudo tee -a /etc/sysctl.conf > /dev/null <<EOF

# Default and max read and write buffer sizes (UDP)
net.core.rmem_max=$MAX_UDP
net.core.rmem_default=$DEFAULT_UDP
net.core.wmem_max=$MAX_UDP
net.core.wmem_default=$DEFAULT_UDP
EOF

# ----------------------------------------
# 2. TCP socket reuse and TIME_WAIT optimizations
# ----------------------------------------
grep -q "net.ipv4.tcp_tw_reuse" /etc/sysctl.conf || sudo tee -a /etc/sysctl.conf > /dev/null <<EOF

# Allow reuse of TIME_WAIT sockets for outgoing connections
net.ipv4.tcp_tw_reuse=1

# Shorten TCP FIN timeout
net.ipv4.tcp_fin_timeout=30

# Increase max connections in backlog
net.core.somaxconn=65535
net.ipv4.tcp_max_syn_backlog=4096

# Ephemeral port range for high number of outbound connections
net.ipv4.ip_local_port_range=1024 65535

# TCP performance enhancements
net.ipv4.tcp_timestamps=1
net.ipv4.tcp_window_scaling=1
EOF

# ----------------------------------------
# 3. Apply changes
# ----------------------------------------
echo "Applying sysctl settings..."
sudo sysctl -p

# ----------------------------------------
# 4. Display new values
# ----------------------------------------
echo -e "\n=== UDP Buffers ==="
sysctl net.core.rmem_default net.core.rmem_max net.core.wmem_default net.core.wmem_max

echo -e "\n=== TCP Stack ==="
sysctl net.ipv4.tcp_tw_reuse net.ipv4.tcp_fin_timeout net.core.somaxconn net.ipv4.tcp_max_syn_backlog \
       net.ipv4.ip_local_port_range net.ipv4.tcp_timestamps net.ipv4.tcp_window_scaling
