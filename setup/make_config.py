#!/usr/bin/python3

import subprocess
import json
import time
import ipaddress
import json
import os
from datetime import datetime
from pathlib import Path

ROOT_PATH = Path(__file__).resolve().parents[1]
CONFIG_DIR = ROOT_PATH / 'config'
CONFIG_FILE = 'config_generated.json'
CONFIG_FULL_PATH = CONFIG_DIR / CONFIG_FILE

DNS_PORT=53
DNS_SERVER = "9.9.9.9"
DNS_SERVER_LIST = ["1.1.1.3", "9.9.9.9", "185.228.168.9"]
DNS_TTL_CACHE = 300

DHCP_PORT = 67
DHCP_LEASE_TIME = 1209600
DHCP_MTU = 1500
DHCP_NTP_SERVER_URL = "pool.ntp.org"


print("Setting up main config")
time.sleep(0.75)

ip_routes = subprocess.run(['ip', 'route'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
if ip_routes.returncode != 0:
    print(f"Error: {ip_routes.stderr}")
    exit(1)
router_ip = None
for line in ip_routes.stdout.splitlines():
    if line.startswith('default via'):
        router_ip = line.split()[2]
        break

print(f"Main router IP identified at {router_ip}")
time.sleep(0.75)

network_interfaces_raw = subprocess.run(['ip', '-j', 'addr', 'show'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
if network_interfaces_raw.returncode != 0:
    print(f"Ensure command:'ip -j addr show' is supported{network_interfaces_raw.stderr}")
    exit(1)

interfaces = []
for iface in json.loads(network_interfaces_raw.stdout):
    for each in iface['addr_info']:
        interfaces.append({
            'name':iface.get('ifname','N/A'),
            'mac': iface.get('address', 'N/A'),
            'mac_broadcast': iface.get('broadcast', 'N/A'),
            'family': each.get('family', 'N/A'),
            'ip': each.get('local', 'N/A'),
            'ip_broadcast':each.get('broadcast', 'N/A'),
            'cidr': each.get('prefixlen', 'N/A'),
            'mtu':iface.get('mtu', 'N/A')
        })

print("Available network interfaces:")
for _index, _interface in enumerate(interfaces):
    print(f"{_index}:{_interface['name']} {'IPv4' if _interface['family'] == 'inet' else 'NOT SUPPORTED'}")

server = {
    'interface':None,
    'mac':None,
    'mac_broadcast':None,
    'family':None,
    'ip':None,
    'ip_broadcast':None,
    'cidr':None
}
dns = {
        "port": DNS_PORT,
        "server": DNS_SERVER,
        "server_list":DNS_SERVER_LIST,
        "ttl_cache": DNS_TTL_CACHE
    }
dhcp = {
        "router_ip": None,
        "dns_server": None,
        "ntp_server": DHCP_NTP_SERVER_URL,
        "ip_range_start": None,
        "ip_range_end": None,
        "port": DHCP_PORT,
        "lease_time": DHCP_LEASE_TIME,
        "mtu": DHCP_MTU
    }

try:
    user_choice = int(input("Select interface as main: "))
    selected_interface = interfaces[user_choice]
    network = ipaddress.IPv4Network(f"{selected_interface['ip']}/{selected_interface['cidr']}", strict=False)
    
    server['interface'] = selected_interface['name']
    server['mac'] = selected_interface['mac']
    server['mac_broadcast'] = selected_interface['mac_broadcast']
    server['family'] = selected_interface['family']
    server['ip'] = selected_interface['ip']
    server['subnet_mask']=str(network.netmask)
    server['ip_broadcast'] = str(network.broadcast_address)
    server['cidr'] = str(network.prefixlen)

    ip_range_start = network.network_address + 101
    ip_range_end = network.network_address + (network.num_addresses - 2)
    dhcp['ip_range_start'] = str(ip_range_start)
    dhcp['ip_range_end'] = str(ip_range_end)
    
    dhcp['router_ip'] = router_ip
    dhcp['mtu'] = selected_interface['mtu']
    dhcp['dns_server'] = selected_interface['ip']

    
    os.makedirs(CONFIG_DIR, exist_ok=True)
    with open(CONFIG_FULL_PATH,mode='w',encoding='utf-8') as file_handle:
        json.dump({
            'timestamp':datetime.fromtimestamp(time.time()).isoformat(),
            'server':server,
            'dns':dns,
            'dhcp':dhcp
        }, file_handle, ensure_ascii=False, indent=4)
        print(f"Config file saved to disk at {CONFIG_FULL_PATH}")


except Exception as err:
    print(f"Error:{str(err)}")
    exit(1)

print(f"Make config complete, config at:{CONFIG_FULL_PATH} edit if required")
