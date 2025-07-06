from scapy.all import ARP, Ether, srp
from ipaddress import IPv4Network


def fresh_arp_scan(iface: str, cidr: str, timeout: float = 2.0):
    network = IPv4Network(cidr, strict=False)
    packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(
        pdst=[str(ip) for ip in network.hosts()]
    )

    answered, _ = srp(packet, timeout=timeout, iface=iface, verbose=False)

    return [(recv.psrc, recv.hwsrc) for _, recv in answered]


if __name__ == "__main__":
    for idx, (ip, mac) in enumerate(
        fresh_arp_scan("enp2s0", "192.168.20.0/24"), start=1
    ):
        print(f"{idx}: {ip} -> {mac}")
