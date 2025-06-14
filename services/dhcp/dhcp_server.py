import time
import json
import ipaddress
import queue
import threading
import time
from pathlib import Path
from threading import RLock
from collections import deque
from typing import Tuple, Optional
import scapy.all as scapy
from scapy.layers.dhcp import DHCP, BOOTP
from scapy.layers.l2 import Ether, ARP
from scapy.layers.inet import IP, UDP
from scapy.packet import Packet
from services.dhcp.dhcp_db import DHCPStorage, DHCPStats
# from services.dhcp.utilities import DHCPUtilities
from services.logger.logger import MainLogger
from services.config.config import config
from models.models import DHCPResponseFactory


ROOT_PATH = Path("/projects/gitlab/netarchon")
DB_PATH = ROOT_PATH / "db"
DB_FILENAME = "dhcp.sqlite3"
DB_FULLPATH = DB_PATH / DB_FILENAME

CONFIG_FULLPATH = ROOT_PATH / "config" / "config.json"

INTERFACE = "enp2s0"
PORT = 67
SERVER_IP = "192.168.20.100"
SERVER_MAC = "18:c0:4d:46:f4:11"
BROADCAST_IP = "255.255.255.255"
BROADCAST_MAC = "ff:ff:ff:ff:ff:ff"
SUBNET_MASK = "255.255.255.0"
ROUTER = "192.168.20.1"
NAME_SERVER = "192.168.20.100"
IP_RANGE_START = "192.168.20.101"
IP_RANGE_END = "192.168.20.254"
LEASE_TIME = 60*60*24*14
REBINDING_TIME = int(LEASE_TIME*0.875)
RENEWAL_TIME = int(LEASE_TIME*0.5)
MTU = 1500

RECEIVED_QUEUE_SIZE = 100
INBOUND_REQUESTS_DEQUE_SIZE = 60
DEDUPLICATION_BUFFER = 10
BOOTP_FLAG_BROADCAST = 0x8000
DHCP_PARAMS = [12, 43, 60, 61, 81]
DB_PERSISTENCE_INTERVAL = 60
STALE_LEASE_REMOVAL = 300

ARP_TIMEOUT = 3
WORKER_GET_TIMEOUT = 0.2
WORKER_SLEEP_TIMEOUT = 0.1


dhcp_logger = MainLogger.get_logger(service_name="DHCP", log_level="debug")


class Services:

    @staticmethod
    def service_db_persistence():
        while True:
            try:
                DHCPStorage.save_to_disk()
                DHCPStats.save_to_disk()
            except Exception as err:
                dhcp_logger.warning(f"Persistence error: {str(err)}")
            time.sleep(DB_PERSISTENCE_INTERVAL)

    @staticmethod
    def service_lease_discovery_and_cleaner():
        while True:
            try:
                DHCPStorage.remove_expired_leases()
                _active_leases = DHCPStorage.get_all_leases()
                _active_leases_macs = {lease[0] for lease in _active_leases}
                _active_clients: dict = DHCPUtilities.discover_clients_via_arp()
                _macs_to_be_removed = set()

                for _active_lease_mac in _active_leases_macs:
                    if _active_lease_mac not in _active_clients:
                        _macs_to_be_removed.add(_active_lease_mac)

                if _macs_to_be_removed:
                    DHCPStorage.remove_leases_by_mac(_macs_to_be_removed)
                    dhcp_logger.info(f"Removed leases for MACs: {_macs_to_be_removed}")

                for _active_client_mac, _active_client_ip in _active_clients.items():
                    if _active_client_mac not in _active_leases_macs:
                        DHCPStorage.add_lease(
                            mac=_active_client_mac,
                            ip=_active_client_ip,
                            lease_type='static'
                        )

            except Exception as e:
                dhcp_logger.error(f"Error during service_lease_discovery_and_cleaner: {str(e)}")

            time.sleep(STALE_LEASE_REMOVAL)

    @staticmethod
    def delete_dns_db_files():

        if not DB_PATH:
            return

        dhcp_logger.debug(f"Deleting DHCP DB files ...")
        for file in DB_PATH.iterdir():
            if file.is_file() and file.name.lower().startswith('dhcp'):
                try:
                    file.unlink()
                    dhcp_logger.debug(f"{file} deleted.")
                except FileNotFoundError:
                    dhcp_logger.warning(f"{file} does not exist.")


class DHCPUtilities:

    @staticmethod
    def convert_dhcp_lease_to_string(dhcpType: int = 1) -> str:
        DHCPTypes = {
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
        return DHCPTypes.get(dhcpType, 'unknown')

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
    def discover_client_via_arp(
        ip: str = '',
        iface: str = INTERFACE,
        source_ip: str = SERVER_IP,
        source_mac: str = SERVER_MAC,
        timeout: float = ARP_TIMEOUT
    ) -> Tuple[bool, Optional[str]]:
        """Send an ARP request to check if the IP is still busy."""

        try:
            _packet = (
                Ether(
                    dst="ff:ff:ff:ff:ff:ff",
                    src=source_mac
                ) / ARP(
                    pdst=ip,
                    psrc=source_ip,
                    op=1
                )
            )
            _answered, _unanswered = scapy.srp(
                _packet,
                timeout=timeout,
                verbose=False,
                iface=iface
            )
            if _answered:
                source_mac_response = _answered[0][1].hwsrc
                return True, source_mac_response
        except Exception as e:
            dhcp_logger.error(f"Unexpected error sending ARP request to {ip}: {e}")
        return False, None

    @staticmethod
    def discover_clients_via_arp() -> dict:
        """Send a broadcast ARP request to discover all active clients on the network."""

        discovered_clients = {}

        try:
            network = ipaddress.IPv4Network(f"{SERVER_IP}/24", strict=False)
            subnet = str(network.network_address) + '/24'

            packet = Ether(
                dst=BROADCAST_MAC,
                src=SERVER_MAC
            ) / ARP(
                pdst=subnet,
                psrc=SERVER_IP, op=1
            )
            answered, unanswered = scapy.srp(
                packet,
                timeout=ARP_TIMEOUT,
                verbose=False,
                iface=INTERFACE
            )

            for sent, received in answered:
                discovered_clients[received.hwsrc] = received.psrc

            return discovered_clients

        except Exception as err:
            dhcp_logger.error(f"Unexpected error during ARP discovery: {str(err)}")
            return {}

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


class Discovery:

    @staticmethod
    def discover_client_via_arp(
        ip: str = '',
        iface: str = INTERFACE,
        source_ip: str = SERVER_IP,
        source_mac: str = SERVER_MAC,
        timeout: float = ARP_TIMEOUT
    ) -> Tuple[bool, Optional[str]]:
        """Send an ARP request to check if the IP is still busy."""
        try:
            _packet = (
                Ether(
                    dst="ff:ff:ff:ff:ff:ff",
                    src=source_mac
                ) / ARP(
                    pdst=ip,
                    psrc=source_ip,
                    op=1
                )
            )
            _answered, _unanswered = scapy.srp(
                _packet,
                timeout=timeout,
                verbose=False,
                iface=iface
            )
            if _answered:
                source_mac_response = _answered[0][1].hwsrc
                return True, source_mac_response
        except Exception as e:
            dhcp_logger.error(f"Unexpected error sending ARP request to {ip}: {e}")
        return False, None

    @staticmethod
    def discover_clients_via_arp() -> dict:
        """Send a broadcast ARP request to discover all active clients on the network."""
        discovered_clients = {}
        try:
            network = ipaddress.IPv4Network(f"{SERVER_IP}/24", strict=False)
            subnet = str(network.network_address) + '/24'
            packet = Ether(
                dst=BROADCAST_MAC,
                src=SERVER_MAC
            ) / ARP(
                pdst=subnet,
                psrc=SERVER_IP, op=1
            )
            
            answered, unanswered = scapy.srp(
                packet,
                timeout=ARP_TIMEOUT,
                verbose=False,
                iface=INTERFACE
            )

            for sent, received in answered:
                discovered_clients[received.hwsrc] = received.psrc
            return discovered_clients

        except Exception as err:
            dhcp_logger.error(f"Unexpected error during ARP discovery: {str(err)}")
            return {}


class DHCPServer:

    def __init__(self) -> None:
        self._running = True
        self._lock = RLock()
        self._denied_ips = {}
        self._offered_ips = {}
        self._threads = {}
        self._inbound_packet_buffer_queue = queue.Queue(maxsize=RECEIVED_QUEUE_SIZE)
        self._inbound_packet_deduplication_queue = deque(maxlen=INBOUND_REQUESTS_DEQUE_SIZE)

    def _init_denied_ips_by_client(self, packet: Packet):
        if packet[Ether].src not in self._denied_ips:
            self._denied_ips[packet[Ether].src] = set()

    def _find_available_ip(self, packet: Packet) -> str:
        """Find the next available IP, avoiding specified exclusions"""

        with self._lock:

            _start_ip = ipaddress.IPv4Address(IP_RANGE_START)
            _end_ip = ipaddress.IPv4Address(IP_RANGE_END)
            _leased_ips = DHCPStorage.get_all_leased_ips()
            _discovered_clients = DHCPUtilities.discover_clients_via_arp()

            for _ip in range(int(_start_ip), int(_end_ip) + 1):
                _proposed_ip = str(ipaddress.IPv4Address(_ip))
                if (
                    _proposed_ip in _leased_ips or
                    _proposed_ip in self._offered_ips or
                    _proposed_ip in self._denied_ips[packet[Ether].src] or
                    _proposed_ip in _discovered_clients.values()
                ):
                    continue

                _is_active, _mac_address = DHCPUtilities.discover_client_via_arp(ip=_proposed_ip)

                if not _is_active:
                    dhcp_logger.debug(f"Scanning for available IP {_proposed_ip} not active, proposing.")
                    return _proposed_ip
                else:
                    dhcp_logger.debug(f"Scanning for available IP {_proposed_ip} active by {_mac_address}.")
                    continue

        dhcp_logger.warning(f"No available IPs found.")
        return ''

    def _handle_decline(self, packet: Packet):
        """Handles DHCP Decline messages (RFC 2131, Section 4.3.2)"""

        source_mac = packet[Ether].src
        transaction_id = packet[BOOTP].xid
        declined_ip = DHCPUtilities.extract_requested_addr_from_dhcp_packet(packet)

        dhcp_logger.info(f"DHCPDECLINE XID:{transaction_id} MAC:{source_mac} Declined IP:{declined_ip}")

        with self._lock:

            existing_lease = DHCPStorage.get_lease_by_mac(source_mac)
            self._denied_ips[source_mac].add(declined_ip)

            # Case 1: The client has a lease and it is for the declined IP
            if existing_lease and existing_lease[1] == declined_ip:
                dhcp_logger.debug(f"Client MAC:{source_mac} declined IP:{declined_ip}, removing lease from database")
                DHCPStorage.remove_lease_by_mac(source_mac)
            else:
                # Case 2: The client declined the IP and doesnt have active lease
                dhcp_logger.debug(f"Client {source_mac} declined IP {declined_ip}, but no lease found")

            response = DHCPResponseFactory().build(
                server_ip=SERVER_IP,
                server_mac=SERVER_MAC,
                port=PORT,
                broadcast_mac=BROADCAST_MAC,
                broadcast_ip=BROADCAST_IP,
                lease_time=LEASE_TIME,
                subnet_mask=SUBNET_MASK,
                router=ROUTER,
                name_server=NAME_SERVER,
                renewal_time=RENEWAL_TIME,
                rebinding_time=REBINDING_TIME,
                mtu=MTU,
                flags=BOOTP_FLAG_BROADCAST,
                dhcp_type=6,
                your_ip="0.0.0.0",
                request_packet=packet
            )

            self._send_response(packet=response)

    def _handle_release(self, packet: Packet):
        """DHCP Release (Section 4.4 of RFC 2131) sent by the client to release an IP address that it no longer needs"""

        source_mac = packet[Ether].src
        transaction_id = packet[BOOTP].xid
        source_ip = packet[IP].src

        dhcp_logger.info(f"DHCPRELEASE XID:{transaction_id} MAC:{source_mac} IP_src:{source_ip}")

        with self._lock:

            self._denied_ips[source_mac] = set()
            DHCPStorage.remove_lease_by_mac(source_mac)

            response = DHCPResponseFactory().build(
                server_ip=SERVER_IP,
                server_mac=SERVER_MAC,
                port=PORT,
                broadcast_mac=BROADCAST_MAC,
                broadcast_ip=BROADCAST_IP,
                lease_time=LEASE_TIME,
                subnet_mask=SUBNET_MASK,
                router=ROUTER,
                name_server=NAME_SERVER,
                renewal_time=RENEWAL_TIME,
                rebinding_time=REBINDING_TIME,
                mtu=MTU,
                flags=BOOTP_FLAG_BROADCAST,
                dhcp_type=5,
                your_ip="0.0.0.0",
                request_packet=packet
            )

            self._send_response(response)

    def _handle_inform(self,  packet: Packet):
        """DHCPINFORM (Section 3.3.2 of RFC 2131)"""

        source_mac = packet[Ether].src
        source_ip = packet[IP].src
        transaction_id = packet[BOOTP].xid
        param_req_list = DHCPUtilities.extract_client_param_req_list_from_dhcp_packet(packet)

        dhcp_logger.info(f"DHCPINFORM MAC:{source_mac} XID:{transaction_id} Requested Parameters:{param_req_list}")

        with self._lock:

            response = DHCPResponseFactory().build(
                server_ip=SERVER_IP,
                server_mac=SERVER_MAC,
                port=PORT,
                broadcast_mac=BROADCAST_MAC,
                broadcast_ip=BROADCAST_IP,
                subnet_mask=SUBNET_MASK,
                router=ROUTER,
                name_server=NAME_SERVER,
                lease_time=LEASE_TIME,
                renewal_time=RENEWAL_TIME,
                rebinding_time=REBINDING_TIME,
                mtu=MTU,
                flags=BOOTP_FLAG_BROADCAST,
                dhcp_type=5,
                your_ip=source_ip,
                request_packet=packet
            )
            self._send_response(response)

    def _handle_request(self, packet: Packet):
        _src_mac = packet[Ether].src
        _xid = packet[BOOTP].xid
        _hostname = DHCPUtilities.extract_hostname_from_dhcp_packet(packet)
        _requested_ip = DHCPUtilities.extract_requested_addr_from_dhcp_packet(packet)
        _client_ip = packet[BOOTP].ciaddr
        _server_id = DHCPUtilities.extract_server_id_from_dhcp_packet(packet)

        dhcp_logger.debug(f"Received REQUEST XID:{_xid}, MAC:{_src_mac}, IP_req:{_requested_ip}, HOSTNAME:{_hostname}.")

        with self._lock:
            dhcp_type = 6  # Default to NAK
            _yiaddr = "0.0.0.0"

            existing_lease = DHCPStorage.get_lease_by_mac(_src_mac)

            # 1) REQUEST following OFFER (SELECTING state)
            if _requested_ip and _server_id and _client_ip == "0.0.0.0":
                offered_ip = self._offered_ips.get(_src_mac)
                if offered_ip == _requested_ip:
                    # IP was offered, now lease it and ACK
                    DHCPStorage.add_lease(_src_mac, _requested_ip, _hostname, LEASE_TIME)
                    dhcp_type, _yiaddr = 5, _requested_ip
                    dhcp_logger.debug(f"REQUEST after OFFER - ACK IP:{_requested_ip}, MAC:{_src_mac}")
                else:
                    dhcp_logger.debug(f"REQUEST after OFFER - NAK (mismatch) Offered:{offered_ip} Requested:{_requested_ip} MAC:{_src_mac}")

            # 2) INIT-REBOOT: Client requests an IP it believes it already owns
            elif _requested_ip and _client_ip == "0.0.0.0":
                if not DHCPUtilities.is_ip_in_subnet(_requested_ip):
                    dhcp_logger.debug(f"INIT-REBOOT - NAK IP outside subnet: {_requested_ip}")
                else:
                    is_active, active_mac = DHCPUtilities.discover_client_via_arp(ip=_requested_ip)
                    if is_active and active_mac != _src_mac:
                        dhcp_logger.debug(f"INIT-REBOOT - NAK IP in use by different MAC: {active_mac}")
                    elif existing_lease and existing_lease[1] == _requested_ip:
                        # Lease exists for this MAC and IP, renew lease and ACK
                        DHCPStorage.add_lease(_src_mac, _requested_ip, _hostname, LEASE_TIME)
                        dhcp_type, _yiaddr = 5, _requested_ip
                        dhcp_logger.debug(f"INIT-REBOOT - ACK IP:{_requested_ip}, MAC:{_src_mac}")
                    else:
                        dhcp_logger.debug(f"INIT-REBOOT - NAK no matching lease for MAC:{_src_mac} IP:{_requested_ip}")

            # 3) RENEW or REBIND: client has valid IP (ciaddr), no requested IP
            elif _client_ip != "0.0.0.0" and not _requested_ip:
                if not DHCPUtilities.is_ip_in_subnet(_client_ip):
                    dhcp_logger.debug(f"RENEW/REBIND - NAK IP outside subnet: {_client_ip}")
                else:
                    is_active, active_mac = DHCPUtilities.discover_client_via_arp(ip=_client_ip)
                    if is_active and active_mac != _src_mac:
                        dhcp_logger.debug(f"RENEW/REBIND - NAK IP in use by different MAC: {active_mac}")
                    elif existing_lease and existing_lease[1] == _client_ip:
                        DHCPStorage.add_lease(_src_mac, _client_ip, _hostname, LEASE_TIME)
                        dhcp_type, _yiaddr = 5, _client_ip
                        dhcp_logger.debug(f"RENEW/REBIND - ACK IP:{_client_ip}, MAC:{_src_mac}")
                    else:
                        dhcp_logger.debug(f"RENEW/REBIND - NAK lease mismatch for MAC:{_src_mac} IP:{_client_ip}")

            # 4) Invalid requests: Requested IP and client IP both set (client trying to change IP without DISCOVER)
            elif _requested_ip and _client_ip != "0.0.0.0":
                dhcp_logger.warning(
                    f"Invalid REQUEST: IP change without DISCOVER, MAC:{_src_mac}, Requested:{_requested_ip}, Current:{_client_ip}")

            else:
                dhcp_logger.debug(f"REQUEST with no valid IP info, NAK MAC:{_src_mac}")

            server_response = DHCPResponseFactory().build(
                server_ip=SERVER_IP,
                server_mac=SERVER_MAC,
                port=PORT,
                broadcast_mac=BROADCAST_MAC,
                broadcast_ip=BROADCAST_IP,
                lease_time=LEASE_TIME,
                subnet_mask=SUBNET_MASK,
                router=ROUTER,
                name_server=NAME_SERVER,
                renewal_time=RENEWAL_TIME,
                rebinding_time=REBINDING_TIME,
                mtu=MTU,
                flags=BOOTP_FLAG_BROADCAST,
                dhcp_type=dhcp_type,
                your_ip=_yiaddr,
                request_packet=packet
            )

            self._send_response(server_response)

    def _handle_discover(self, packet: Packet):
        """Handles DHCPDISCOVER messages (RFC 2131, Section 4.1) sent by clients to discover DHCP servers."""
        with self._lock:

            dhcp_logger.debug(f"Received DISCOVER "
                              f"XID={packet[BOOTP].xid}, "
                              f"MAC={packet[Ether].src}."
                              )
            proposed_ip = self._find_available_ip(packet)
            if not proposed_ip:
                dhcp_logger.warning(f"No available IPs")
                return

            self._offered_ips[packet[Ether].src] = proposed_ip

            response = DHCPResponseFactory().build(
                server_ip=SERVER_IP,
                server_mac=SERVER_MAC,
                port=PORT,
                broadcast_mac=BROADCAST_MAC,
                broadcast_ip=BROADCAST_IP,
                lease_time=LEASE_TIME,
                subnet_mask=SUBNET_MASK,
                router=ROUTER,
                name_server=NAME_SERVER,
                renewal_time=RENEWAL_TIME,
                rebinding_time=REBINDING_TIME,
                mtu=MTU,
                flags=BOOTP_FLAG_BROADCAST,
                dhcp_type=2,
                your_ip=proposed_ip,
                request_packet=packet
            )
            self._send_response(response)

    def _send_response(self, packet: Packet):
        """Send a DHCP packet on the configured interface."""

        self._log_outbound(packet)
        _dhcp_type = DHCPUtilities.extract_dhcp_type_from_packet(packet)
        print("sending:", packet[BOOTP].xid, packet[Ether].src, _dhcp_type)

        dhcp_logger.debug(f"Send: "
                          f"TYPE:{_dhcp_type}, "
                          f"XID:{packet[BOOTP].xid}, "
                          f"CHADDR:{packet[BOOTP].chaddr[:6].hex(':')}, "
                          f"YIADDR:{packet[BOOTP].yiaddr}.")

        scapy.sendp(packet, iface=INTERFACE, verbose=False)

    def _log_inbound(self, packet: Packet):
        """Logs details of a DHCP packet."""

        dhcp_type = DHCPUtilities.extract_dhcp_type_from_packet(packet)
        dhcp_type_string = DHCPUtilities.convert_dhcp_lease_to_string(dhcp_type)

        DHCPStats.increment(key="received_total_valid")
        DHCPStats.increment(key=f"received_{dhcp_type_string}")

    def _log_outbound(self, packet: Packet):
        """Logs details of a DHCP packet."""

        dhcp_type = DHCPUtilities.extract_dhcp_type_from_packet(packet)
        dhcp_type_string = DHCPUtilities.convert_dhcp_lease_to_string(dhcp_type)

        DHCPStats.increment(key="sent_total")
        DHCPStats.increment(key=f"sent_{dhcp_type_string}")

    def listen(self, packet: Packet):
        """Listen and enquire dhsp packages"""

        try:
            if packet[Ether].src.lower() == SERVER_MAC.lower():
                return

            key = (
                packet[Ether].src,
                packet[BOOTP].xid,
                DHCPUtilities.extract_dhcp_type_from_packet(packet)
            )

            if key not in self._inbound_packet_deduplication_queue:
                print("received:", packet[BOOTP].xid, packet[Ether].src, DHCPUtilities.extract_dhcp_type_from_packet(packet))
                DHCPStats.increment(key="received_total")
                self._log_inbound(packet)
                self._inbound_packet_buffer_queue.put(packet)
                self._inbound_packet_deduplication_queue.append(key)

        except queue.Full:
            dhcp_logger.warning(f"Queue full, losing packets.")

        except Exception as err:
            dhcp_logger.exception(f"Couldn't DNS packet: {err}.")

    def service_queue_worker_processor(self):

        while self._running:
            packet = None

            try:
                packet = self._inbound_packet_buffer_queue.get(timeout=WORKER_GET_TIMEOUT)
            except queue.Empty:
                continue

            try:
                if packet:
                    print("processing:", packet[BOOTP].xid, packet[Ether].src)
                    self._init_denied_ips_by_client(packet)

                    dhcp_type: int = DHCPUtilities.extract_dhcp_type_from_packet(packet)
                    if dhcp_type == 1:  # DHCPDISCOVER
                        self._handle_discover(packet)
                    elif dhcp_type == 3:  # DHCPREQUEST
                        self._handle_request(packet)
                    elif dhcp_type == 4:  # DHCPDECLINE
                        self._handle_decline(packet)
                    elif dhcp_type == 7:  # DHCPRELEASE
                        self._handle_release(packet)
                    elif dhcp_type == 8:  # DHCPINFORM
                        self._handle_inform(packet)
                    else:
                        dhcp_logger.warning(f"Unknown DHCP type {dhcp_type} from {packet[Ether].src}.")

            except Exception as err:
                dhcp_logger.exception(f"{threading.current_thread().name} processing DHCP packet as {err}.")

            finally:
                if packet:
                    self._inbound_packet_buffer_queue.task_done()

    def service_traffic_listener(self):
        """ Start sniffing for DHCP packets on the interface """
        scapy.sniff(
            iface=INTERFACE,
            filter=f"ip and udp and port {PORT}",
            prn=self.listen,
            count=0,
            timeout=None,
            store=False,
            session=None
        )

    def start(self):
        """ Start all necessary threads """

        self._running = True

        with self._lock:
            Services.delete_dns_db_files()
            DHCPStorage.init()
            DHCPStats.init()

        traffic_listener = threading.Thread(target=self.service_traffic_listener, name="traffic_listener", daemon=True)
        traffic_listener.start()
        self._threads["traffic_listener"] = traffic_listener

        for _index in range(5):
            queue_worker = threading.Thread(target=self.service_queue_worker_processor, name=f"queue_worker_{_index}", daemon=True)
            queue_worker.start()
            self._threads["queue_worker_{_index}"] = queue_worker

        db_persistence = threading.Thread(target=Services.service_db_persistence, name="service_db_persistence", daemon=True)
        db_persistence.start()
        self._threads["db_persistence"] = db_persistence

        lease_discovery_and_cleaner = threading.Thread(
            target=Services.service_lease_discovery_and_cleaner, name="service_lease_discovery_and_cleaner", daemon=True)
        lease_discovery_and_cleaner.start()
        self._threads["lease_discovery_and_cleaner"] = lease_discovery_and_cleaner

        dhcp_logger.info("Started")

    def stop(self):

        self._running = False
        for thread_name, thread in self._threads.items():
            if thread.is_alive():
                dhcp_logger.info(f"Stopping :{thread_name}")
                thread.join(timeout=1)

        dhcp_logger.info("All threads stopped, stopping the DNS server")


if __name__ == "__main__":

    while True:
        time.sleep(1)


# | Step | Message Type   | Trigger                              | Server Action                              | Client Action                              | State     |
# |------|----------------|--------------------------------------|--------------------------------------------|--------------------------------------------|-----------|
# |  1   | DHCPDISCOVER   | Client starts looking for an IP      | Records request, selects an available IP   | Broadcasts discovery to find a DHCP server | **INIT**  |
# |  2   | DHCPOFFER      | Server offers an IP                  | Assigns an IP from the pool, sends offer   | Waits for offers from servers              | **OFFERED** |
# |  3   | DHCPREQUEST    | Client accepts an offer              | Receives request, verifies availability    | Requests the selected IP                   | **REQUESTED** |
# |  4   | DHCPACK        | Server confirms lease                | Saves lease to database, sends ACK         | Configures IP and starts using it          | **BOUND** |
# |  5   | DHCPNAK        | IP conflict or lease expired         | Rejects request, client must restart       | Receives NAK, restarts process             | **REJECTED** |
# |  6   | DHCPDECLINE    | Client detects conflict              | Marks IP as bad, removes it from pool      | Rejects IP, restarts with DISCOVER         | **DECLINED** |
# |  7   | DHCPRELEASE    | Client leaves network                | Frees up the IP in the pool                | Sends RELEASE, stops using IP              | **RELEASED** |
# |  8   | DHCPINFORM     | Client wants config info             | Provides extra options (e.g., DNS)         | Requests additional DHCP settings          | **INFORMED** |
