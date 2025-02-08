import subprocess
from app.config.settings import NAT_CONFIG


def configure_nat():
    if NAT_CONFIG['enabled']:
        # Sample command to enable NAT using nftables
        subprocess.run(['nft', 'add', 'table', 'inet', 'filter'])
        subprocess.run(['nft', 'add', 'chain', 'inet', 'filter',
                       'input', '{ type filter hook input priority 0; }'])
        subprocess.run(['nft', 'add', 'rule', 'inet', 'filter', 'input',
                       'ip saddr {} accept'.format(NAT_CONFIG['src_network'])])


def get_status():
    return "Enabled" if NAT_CONFIG['enabled'] else "Disabled"
