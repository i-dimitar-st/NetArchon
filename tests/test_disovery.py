from dataclasses import dataclass
from ipaddress import IPv4Network
from typing import Dict

from scapy.layers.inet import ICMP, IP
from scapy.layers.l2 import ARP, Ether
from scapy.sendrecv import sr, srp


@dataclass
class ArpClient:
    ip: str
    mac: str


def discover_live_clients_icmp(
    network: IPv4Network,
    broadcast_mac: str = "ff:ff:ff:ff:ff:ff",
    server_ip: str = "192.168.20.100",
    timeout: float = 2.5,
    inter_delay: float = 0.02,
    iface: str = "enp2s0",
    verbose: bool = False,
):
    """
    Perform ping sweep over the network to discover live clients.

    Args:
        network (IPv4Network): subnet to scan.
        broadcast_mac (str): Typically ff:ff:ff:ff:ff:ff.
        timeout (float): Timeout for each ping request.
        inter_delay (float): Delay between ARP requests.
        iface (str): Network interface to use.
        verbose (bool): Enable/disable verbose output.

    Returns:
        Dict[str, ArpClient]: Mapping of IP addresses to ArpClient instances.
                             MAC is None since ping does not discover MAC.
    """
    if not network:
        raise RuntimeError("Missing network")

    clients: Dict[str, ArpClient] = {}

    _answered_pings, _ = srp(
        [
            Ether(dst=broadcast_mac) / IP(dst=str(_ip)) / ICMP()
            for _ip in network.hosts()
        ],
        timeout=timeout,
        inter=inter_delay,
        verbose=verbose,
        iface=iface,
    )

    print(_answered_pings)

    _answered_arp, _ = srp(
        [
            Ether(dst=broadcast_mac) / ARP(pdst=_ip)
            for _ip in [recv[IP].src for _, recv in _answered_pings]
        ],
        timeout=timeout,
        inter=inter_delay,
        verbose=verbose,
        iface=iface,
        filter="arp",
    )

    for _sent, _recv in _answered_arp:
        clients[_recv[ARP].psrc] = ArpClient(mac=_recv[ARP].hwsrc, ip=_recv[ARP].psrc)

    return clients


if __name__ == "__main__":

    # Define the subnet you want to scan
    subnet = IPv4Network("192.168.20.0/24")

    # Call the discovery function
    results = discover_live_clients_icmp(
        network=subnet,
        server_ip="192.168.20.100",  # Must be bound to iface below
        iface="enp2s0",  # Use the correct interface
        verbose=True,
    )

    # Print results
    print("\nLive clients discovered:")
    for ip, client in results.items():
        print(f"{ip} -> {client.mac}")
