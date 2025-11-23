from ipaddress import (
    IPv4Address,
    IPv4Network,
    IPv6Address,
    IPv6Network,
    ip_address,
    ip_network,
)

from scapy.arch import get_if_list
from scapy.layers.dhcp import DHCP
from scapy.packet import Packet

DEFAULT_HOSTNAME = "unknown"
DEFAULT_VENDOR_CLASS_ID = "unknown"
DEFAULT_DHCP_TYPE = -1


def is_net_interface_valid(iface: str) -> bool:
    """is_net_interface_valid"""
    return iface in get_if_list()


def extract_dhcp_type_from_packet(packet: Packet) -> int:
    """Extract the DHCP message type from the packet."""
    for opt in packet[DHCP].options:
        if opt[0] == "message-type":
            return int(opt[1])
    return DEFAULT_DHCP_TYPE


def extract_req_addr_from_packet(packet: Packet) -> str:
    """Extract the requested IP address from a DHCP packet (Option 50)."""
    for option in packet[DHCP].options:
        if option[0] == "requested_addr":
            return option[1]
    return ""


def extract_server_id_from_dhcp_packet(packet: Packet) -> str:
    """Extract the DHCP Server Identifier from a DHCP packet (Option 54)."""
    for opt in packet[DHCP].options:
        if isinstance(opt, tuple) and opt[0] == "server_id":
            return opt[1]
    return ""


def extract_hostname_from_packet(packet: Packet) -> str:
    for _opt in packet[DHCP].options:
        if isinstance(_opt, tuple) and _opt[0] == "hostname":
            _hostname = _opt[1]
            if isinstance(_hostname, str):
                return _hostname
            if isinstance(_hostname, bytes):
                return _hostname.decode(errors="ignore")
    return DEFAULT_HOSTNAME


def extract_vendor_class_id(packet: Packet) -> str:
    """Extract the DHCP 'vendor_class_id' (option 60) from the packet.
    """
    for option in packet[DHCP].options:
        if isinstance(option, tuple) and option[0] == "vendor_class_id":
            vendor_class_id = option[1]
            if isinstance(vendor_class_id, str):
                return vendor_class_id
            if isinstance(vendor_class_id, bytes):
                return vendor_class_id.decode(errors="ignore")
    return DEFAULT_VENDOR_CLASS_ID


def extract_param_req_list(packet: Packet) -> list[int]:
    """Extracts the 'param_req_list' from the DHCP packet (Option 55)."""
    for _opt in packet[DHCP].options:
        if isinstance(_opt, tuple) and _opt[0] == "param_req_list":
            return _opt[1]
    return []


def convert_binary_to_string(data_to_convert: bytes) -> str:
    """Format a raw MAC address to human-readable format"""
    return data_to_convert.decode("utf-8", errors="ignore")


def is_ip_in_subnet(ip_to_validate: str, subnet: str = "192.168.20.0/24") -> bool:
    """Checks if an IP address is in the specified subnet."""
    if not ip_to_validate:
        return False
    _ip: IPv4Address | IPv6Address = ip_address(ip_to_validate)
    _network: IPv4Network | IPv6Network = ip_network(subnet, strict=False)

    return bool(_ip in _network)
