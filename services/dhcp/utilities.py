import ipaddress
from typing import Optional
from scapy.packet import Packet
from scapy.layers.dhcp import DHCP


class DHCPUtilities:

    @staticmethod
    def convert_dhcp_lease_to_string(dhcpType: int = 1) -> str:
        dhcp_types = {
            1: "discover",
            2: "offer",
            3: "request",
            4: "decline",
            5: "ack",
            6: "nak",
            7: "release",
            8: "inform",
            9: "force_renew",
            10: "lease_query",
            11: "lease_unassigned",
            12: "lease_unknown",
            13: "lease_active",
        }
        return dhcp_types.get(dhcpType, 'unknown')

    @staticmethod
    def extract_dhcp_type_from_packet(packet: Packet) -> int:
        """Extract the DHCP message type from the packet."""
        for opt in packet[DHCP].options:
            if opt[0] == "message-type":
                return int(opt[1])
        return -1

    @staticmethod
    def extract_requested_addr_from_dhcp_packet(packet: Packet) -> str | None:
        """Extract the requested IP address from a DHCP packet."""
        for option in packet[DHCP].options: 
            if option[0] == "requested_addr":
                return option[1]
        return None

    @staticmethod
    def extract_server_id_from_dhcp_packet(packet: Packet) -> Optional[str]:
        for opt in packet[DHCP].options:
            if isinstance(opt, tuple) and opt[0] == 'server_id':
                return opt[1]
        return None

    @staticmethod
    def extract_hostname_from_dhcp_packet(packet: Packet) -> str:
        for option in packet[DHCP].options:
            if option[0] == 'hostname':
                return DHCPUtilities.convert_binary_to_string(option[1])
        return 'unknown'

    @staticmethod
    def extract_client_param_req_list_from_dhcp_packet(packet: Packet) -> str:
        """Extracts the 'param_req_list' from the DHCP packet."""
        for option in packet[DHCP].options:
            if option[0] == "param_req_list":
                return option[1]
        return ''

    @staticmethod
    def convert_binary_to_string(data_to_convert: bytes) -> str:
        """ Format a raw MAC address to human-readable format """
        return data_to_convert.decode('utf-8', errors='ignore')

    @staticmethod
    def is_ip_in_subnet(ip_to_validate: str, subnet: str = "192.168.20.0/24") -> bool:
        """
        Checks if an IP address is in the specified subnet.

        :param ip_to_validate: IP address to check.
        :param subnet: The subnet to check against (e.g., '192.168.1.0/24').
        :return: True if the IP is within the subnet, False otherwise.
        """
        if not ip_to_validate:
            return False
        ip = ipaddress.ip_address(ip_to_validate)
        network = ipaddress.ip_network(subnet, strict=False)

        return bool(ip in network)
