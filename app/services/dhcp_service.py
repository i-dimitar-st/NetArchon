from scapy.all import *
from app.config.settings import DHCP_CONFIG


def configure_dhcp():
    if DHCP_CONFIG['enabled']:
        # Implement DHCP server logic with Scapy
        pass  # Actual DHCP handling logic here


def get_status():
    return "Enabled" if DHCP_CONFIG['enabled'] else "Disabled"
