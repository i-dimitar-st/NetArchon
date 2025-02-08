#!/bin/bash

# Variables for IP addresses and network interfaces
MAIN_ROUTER_IP="192.168.x.1"          # Main router IP
GATEWAY_MACHINE_IP="192.168.x.50"     # Gateway machine IP
INTERFACE="eth0"                      # Network interface (change if needed)

# Enable IP forwarding (temporarily)
echo "Enabling IP forwarding..."
sudo sysctl -w net.ipv4.ip_forward=1

# Make IP forwarding permanent
echo "Making IP forwarding permanent..."
echo "net.ipv4.ip_forward=1" | sudo tee -a /etc/sysctl.conf
sudo sysctl -p

# Set the default route to the main router
echo "Setting default route to main router ($MAIN_ROUTER_IP)..."
sudo ip route add default via $MAIN_ROUTER_IP

# Configure NAT using nftables (assuming eth0 is the internet-facing interface)
echo "Configuring NAT..."
sudo nft add table ip nat
sudo nft add chain ip nat POSTROUTING { type nat hook postrouting priority 100 \; }
sudo nft add rule ip nat POSTROUTING oifname $INTERFACE masquerade

# Optional: Add firewall rules (this drops everything except necessary traffic)
echo "Configuring firewall rules..."
# Default to drop all traffic
sudo nft add chain ip filter input { type filter hook input priority 0 \; policy drop \; }
sudo nft add chain ip filter forward { type filter hook forward priority 0 \; policy drop \; }
sudo nft add chain ip filter output { type filter hook output priority 0 \; policy drop \; }

# Allow traffic from the gateway machine itself
sudo nft add rule ip filter input iifname $INTERFACE accept
sudo nft add rule ip filter output oifname $INTERFACE accept
sudo nft add rule ip filter forward ip saddr $GATEWAY_MACHINE_IP accept
sudo nft add rule ip filter forward ip daddr $GATEWAY_MACHINE_IP accept

# Allow traffic from clients to the main router (for internet access)
sudo nft add rule ip filter forward ip saddr 192.168.x.51/25 ip daddr $MAIN_ROUTER_IP accept
sudo nft add rule ip filter forward ip saddr $MAIN_ROUTER_IP ip daddr 192.168.x.51/25 accept

# Allow DNS (optional, if DNS is provided by the gateway)
sudo nft add rule ip filter forward ip daddr $GATEWAY_MACHINE_IP tcp dport 53 accept
sudo nft add rule ip filter forward ip daddr $GATEWAY_MACHINE_IP udp dport 53 accept

# Optionally, allow access to specific services like HTTP/HTTPS from clients to the gateway
# sudo nft add rule ip filter forward ip daddr $GATEWAY_MACHINE_IP tcp dport {80, 443} accept

# Save the nftables configuration (optional)
echo "Saving nftables configuration..."
sudo nft list ruleset > /etc/nftables.conf

# Restart nftables to apply rules
echo "Restarting nftables..."
sudo systemctl restart nftables

# Print success message
echo "Gateway machine configured successfully! All traffic should be routed through $MAIN_ROUTER_IP."
