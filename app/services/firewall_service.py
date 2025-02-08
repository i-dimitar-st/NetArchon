import subprocess
from app.config.settings import FIREWALL_CONFIG

def configure_firewall():
    if FIREWALL_CONFIG['enabled']:
        # Setup firewall rules with nftables
        pass  # Actual firewall setup logic here

def get_status():
    return "Enabled" if FIREWALL_CONFIG['enabled'] else "Disabled"
