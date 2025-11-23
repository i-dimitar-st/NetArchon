"""dhcp_utils.py.

Provides helper functions and a class to work with DHCP packets, including:
- Extract DHCP fields (message type, requested IP, server ID, hostname, parameter list)
- Converting binary data to strings
- Checking if an IP is in a subnet
- Validating network interfaces

Uses Scapy for packet parsing and ipaddress for IP/subnet operations.
"""

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
DEFAULT_DHCP_TYPE = -1


def is_net_interface_valid(iface: str) -> bool:
    """is_net_interface_valid."""
    return iface in get_if_list()


class DHCPUtilities:
    """Utility class for parsing and extracting information from DHCP packets.

    Provides static methods to extract common DHCP fields such as:
        - DHCP message type
        - Requested IP address
        - Server Identifier
        - Hostname
        - Parameter Request List
    Also includes helper methods for data conversion and IP subnet validation.
    """

    @staticmethod
    def extract_dhcp_type_from_packet(packet: Packet) -> int:
        """Extract the DHCP message type from the packet."""
        for opt in packet[DHCP].options:
            if opt[0] == "message-type":
                return int(opt[1])
        return DEFAULT_DHCP_TYPE

    @staticmethod
    def extract_req_addr_from_packet(packet: Packet) -> str:
        """Extract the requested IP address from a DHCP packet (Option 50)."""
        for option in packet[DHCP].options:
            if option[0] == "requested_addr":
                return option[1]
        return ""

    @staticmethod
    def extract_server_id_from_dhcp_packet(packet: Packet) -> str:
        """Extract the DHCP Server Identifier from a DHCP packet (Option 54)."""
        for opt in packet[DHCP].options:
            if isinstance(opt, tuple) and opt[0] == "server_id":
                return opt[1]
        return ""

    @staticmethod
    def extract_hostname_from_packet(packet: Packet) -> str:
        """Extract hostname from packet."""
        for option in packet[DHCP].options:
            if option[0] == "hostname":
                return DHCPUtilities.convert_binary_to_string(option[1])
        return DEFAULT_HOSTNAME

    @staticmethod
    def extract_param_req_list(packet: Packet) -> list[int]:
        """Extract the 'param_req_list' from the DHCP packet (Option 55)."""
        for option in packet[DHCP].options:
            if option[0] == "param_req_list":
                return option[1]
        return []

    @staticmethod
    def convert_binary_to_string(data_to_convert: bytes) -> str:
        """Format a raw MAC address to human-readable format."""
        return data_to_convert.decode("utf-8", errors="ignore")

    @staticmethod
    def is_ip_in_subnet(ip_to_validate: str, subnet: str = "192.168.20.0/24") -> bool:
        """Check if an IP address is in the specified subnet."""
        if not ip_to_validate:
            return False
        ip: IPv4Address | IPv6Address = ip_address(ip_to_validate)
        network: IPv4Network | IPv6Network = ip_network(subnet, strict=False)

        return bool(ip in network)
