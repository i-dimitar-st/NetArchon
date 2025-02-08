# IP Address configuration
# Address of the main router (router for all external traffic)
MAIN_ROUTER_IP = "192.168.x.1"
GATEWAY_MACHINE_IP = "192.168.x.50"  # Address of the gateway machine
CLIENT_IP_RANGE_START = "192.168.x.51"  # Start of client IP range
CLIENT_IP_RANGE_END = "192.168.x.126"  # End of client IP range

# Subnet Configuration (/25 subnet)
SUBNET_MASK = "255.255.255.128"  # /25 subnet mask
NETWORK_ADDRESS = "192.168.x.0/25"  # Local network range

# Default Gateway Configuration (for clients)
DEFAULT_GATEWAY = GATEWAY_MACHINE_IP  # Clients use this as the default gateway

# DHCP Configuration
DHCP_CONFIG = {
    'enabled': True,
    'interface': 'eth0',  # Network interface
    'lease_time': 86400,  # Lease time (1 day in seconds)
    'subnet': NETWORK_ADDRESS,  # Subnet for DHCP
    'gateway': GATEWAY_MACHINE_IP,  # Set the gateway for DHCP clients
    'dns': GATEWAY_MACHINE_IP,  # DNS can also point to the gateway for local resolution
}

# NAT Configuration (Network Address Translation)
NAT_CONFIG = {
    'enabled': True,
    'src_network': NETWORK_ADDRESS,  # Local network for NAT
    'dest_network': '0.0.0.0/0',  # Destination for NAT (internet)
    'gateway': MAIN_ROUTER_IP,  # Main router as the destination for outgoing packets
}

# DNS Configuration
DNS_CONFIG = {
    'enabled': True,
    'listen_address': GATEWAY_MACHINE_IP,  # DNS server listening on gateway machine
}

# Firewall Configuration
FIREWALL_CONFIG = {
    'enabled': True,
    'default_policy': 'DROP',  # Default to drop all traffic unless specified
    # Allow traffic to/from router and gateway
    'allowed_ips': [MAIN_ROUTER_IP, GATEWAY_MACHINE_IP],
}

# Access Control Configuration (time-based)
ACCESS_CONTROL_CONFIG = {
    'enabled': True,
    'time_based_access': {
        'allowed_times': [
            ('08:00', '18:00'),  # Example: Allowed access between 8 AM and 6 PM
        ],
    }
}
