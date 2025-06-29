import ipaddress
import queue
import threading
from threading import RLock
from collections import deque
from typing import Optional, List

from scapy.sendrecv import srp, sniff, sendp
from scapy.plist import SndRcvList
from scapy.layers.dhcp import BOOTP
from scapy.layers.l2 import Ether, ARP
from scapy.packet import Packet

from libs.libs import TTLCache
from models.models import DHCPResponseFactory, ArpClient, DhcpMessage, DHCPType, DHCPLeaseType
from services.dhcp.db import DHCPStorage, DHCPStats
from utils.dhcp_utils import DHCPUtilities
from services.logger.logger import MainLogger
from config.config import config


DHCP_CONFIG = config.get("dhcp")

INTERFACE = DHCP_CONFIG.get("interface")
PORT = DHCP_CONFIG.get("port")
SERVER_IP = DHCP_CONFIG.get("ip")
SERVER_MAC = DHCP_CONFIG.get("mac")
BROADCAST_IP = DHCP_CONFIG.get("broadcast_ip")
BROADCAST_MAC = DHCP_CONFIG.get("broadcast_mac")
SUBNET_MASK = DHCP_CONFIG.get("subnet")
ROUTER = DHCP_CONFIG.get("router_ip")
NAME_SERVER = DHCP_CONFIG.get("ntp_server")
IP_RANGE_START = DHCP_CONFIG.get("ip_pool_start")
IP_RANGE_END = DHCP_CONFIG.get("ip_pool_end")
CIDR = DHCP_CONFIG.get("cidr")
LEASE_TIME = DHCP_CONFIG.get("lease_time_seconds")
REBINDING_TIME = int(LEASE_TIME * 0.875)
RENEWAL_TIME = int(LEASE_TIME * 0.5)
MTU = DHCP_CONFIG.get("mtu")

RECEIVED_QUEUE_SIZE = 100
INBOUND_REQUESTS_DEQUE_SIZE = 60
DEDUPLICATION_BUFFER = 10
BOOTP_FLAG_BROADCAST = 0x8000
DHCP_PARAMS = [12, 43, 60, 61, 81]
DB_PERSISTENCE_INTERVAL = 60

DHCP_WORKERS = 10
ARP_TIMEOUT = 1
WORKER_GET_TIMEOUT = 0.2
WORKER_SLEEP_TIMEOUT = 0.1

# WORKFLOW
# | Step | Message Type   | Trigger                              | Server Action                              | Client Action                              | State         |
# |------|----------------|--------------------------------------|--------------------------------------------|--------------------------------------------|---------------|
# |  1   | DHCPDISCOVER   | Client starts looking for an IP      | Records request, selects an available IP   | Broadcasts discovery to find a DHCP server | **INIT**      |
# |  2   | DHCPOFFER      | Server offers an IP                  | Assigns an IP from the pool, sends offer   | Waits for offers from servers              | **OFFERED**   |
# |  3   | DHCPREQUEST    | Client accepts an offer              | Receives request, verifies availability    | Requests the selected IP                   | **REQUESTED** |
# |  4   | DHCPACK        | Server confirms lease                | Saves lease to database, sends ACK         | Configures IP and starts using it          | **BOUND**     |
# |  5   | DHCPNAK        | IP conflict or lease expired         | Rejects request, client must restart       | Receives NAK, restarts process             | **REJECTED**  |
# |  6   | DHCPDECLINE    | Client detects conflict              | Marks IP as bad, removes it from pool      | Rejects IP, restarts with DISCOVER         | **DECLINED**  |
# |  7   | DHCPRELEASE    | Client leaves network                | Frees up the IP in the pool                | Sends RELEASE, stops using IP              | **RELEASED**  |
# |  8   | DHCPINFORM     | Client wants config info             | Provides extra options (e.g., DNS)         | Requests additional DHCP settings          | **INFORMED**  |


dhcp_logger = MainLogger.get_logger(service_name="DHCP", log_level="debug")


class BackgroundServices:
    _stop_event = threading.Event()

    @classmethod
    def start(cls, interval=DB_PERSISTENCE_INTERVAL):
        cls._worker = threading.Thread(target=cls._work, daemon=True)
        cls._interval = interval
        cls._worker.start()

    @classmethod
    def stop(cls):
        cls._stop_event.set()
        cls._worker.join(timeout=1)

    @classmethod
    def _work(cls):
        while not cls._stop_event.is_set():
            try:
                DHCPStorage.save_to_disk()
                DHCPStats.save_to_disk()
                DHCPStorage.remove_expired_leases()
                discovered_clients = ClientDiscovery.discover_clients_via_arp()
                active_leases_macs = {lease[0] for lease in DHCPStorage.get_all_leases()}
                for client in discovered_clients:
                    if client.mac not in active_leases_macs:
                        DHCPStorage.add_lease(mac=client.mac, ip=client.ip, lease_type='static')
            except Exception as err:
                dhcp_logger.warning(f"Maintenance error: {str(err)}")
            cls._stop_event.wait(cls._interval)


class ClientDiscovery:

    _lock = threading.RLock()
    _reserved_ips: set[str] = set()

    @staticmethod
    def discover_client_via_arp(
        ip: str = '',
        iface: str = INTERFACE,
        source_ip: str = SERVER_IP,
        source_mac: str = SERVER_MAC,
        broadcast_mac: str = BROADCAST_MAC,
        timeout: float = ARP_TIMEOUT,
    ) -> Optional[ArpClient]:
        """Send an ARP request to check if the IP is still busy."""
        try:

            _packet = Ether(dst=broadcast_mac, src=source_mac) / ARP(pdst=ip, psrc=source_ip, op=1)

            _answered: SndRcvList
            _answered, _unanswered = srp(_packet, timeout=timeout, verbose=False, iface=iface)

            if _answered:
                _sent, _received = _answered[0]
                return ArpClient(mac=_received[ARP].hwsrc, ip=_received[ARP].psrc)

        except Exception as err:
            dhcp_logger.error(f"Unexpected error sending ARP request to {ip}: {err}")

        return None

    @staticmethod
    def discover_clients_via_arp(
        iface: str = INTERFACE,
        server_ip: str = SERVER_IP,
        server_mac: str = SERVER_MAC,
        broadcast_mac: str = BROADCAST_MAC,
        timeout: float = ARP_TIMEOUT,
        cidr: str = CIDR,
    ) -> List[ArpClient]:
        """Send a broadcast ARP request to discover all active clients on the network."""
        discovered_clients = []
        try:
            _network = ipaddress.IPv4Network(f"{server_ip}/{cidr}", strict=False)
            _subnet = str(_network.network_address) + f"/{cidr}"

            _packet = Ether(dst=broadcast_mac, src=server_mac) / ARP(
                pdst=_subnet, psrc=server_ip, op=1
            )

            _answered: SndRcvList
            _answered, _unanswered = srp(_packet, timeout=timeout, verbose=False, iface=iface)
            discovered_clients = []
            for _sent, _received in _answered:
                discovered_clients.append(
                    ArpClient(mac=_received[ARP].hwsrc, ip=_received[ARP].psrc)
                )
            return discovered_clients

        except Exception as err:
            dhcp_logger.error(f"Unexpected error during ARP discovery: {str(err)}")
            return []

    @classmethod
    def discover_available_ip(cls) -> str:

        _leased_ips = DHCPStorage.get_all_leased_ips()
        _discovered_ips = {client.ip for client in cls.discover_clients_via_arp()}

        _start_int = int(ipaddress.IPv4Address(IP_RANGE_START))
        _end_int = int(ipaddress.IPv4Address(IP_RANGE_END))

        for _ip_int in range(_start_int, _end_int + 1):
            candidate_ip = str(ipaddress.IPv4Address(_ip_int))

            if (
                DHCPReservationCache.get_mac(candidate_ip)
                or candidate_ip in _leased_ips
                or candidate_ip in _discovered_ips
            ):
                continue

            if cls.discover_client_via_arp(ip=candidate_ip):
                continue

            dhcp_logger.debug(f"proposing IP:{candidate_ip}.")
            return candidate_ip

        dhcp_logger.warning("No available IPs found.")
        return ""


class DHCPReservationCache:
    _cache: TTLCache = TTLCache(max_size=100, ttl=60)

    @classmethod
    def reserve(cls, ip: str, mac: str) -> bool:
        """
        Reserve IP for MAC if free or reserved by same MAC.
        Return False if IP reserved by different MAC.
        """
        existing_mac = cls._cache.get(ip)
        if existing_mac and existing_mac != mac:
            return False
        cls._cache.add(ip, mac)
        return True

    @classmethod
    def unreserve(cls, ip: str, mac: str):
        """Release IP reservation if reserved by MAC."""
        if cls._cache.get(ip) == mac:
            cls._cache.remove(ip)

    @classmethod
    def get_mac(cls, ip: str) -> Optional[str]:
        """Return MAC reserved on IP or None."""
        return cls._cache.get(ip)

    @classmethod
    def get_ip(cls, mac: str) -> Optional[str]:
        """Return IP reserved by MAC or None."""
        with cls._cache._lock:
            ip = cls._cache.get_by_value(mac)
            if ip:
                return ip
        return None


class DHCPLogger:

    @staticmethod
    def log_inbound(dhcp_message: DhcpMessage):
        """Logs details of an inbound DHCP packet."""
        DHCPStats.increment(key="received_total_valid")
        DHCPStats.increment(key=f"received_{DHCPLeaseType(dhcp_message.dhcp_type).name.lower()}")

    @staticmethod
    def log_outbound(packet: Packet):
        """Logs details of an outbound DHCP packet."""
        DHCPStats.increment(key="sent_total")
        DHCPStats.increment(
            key=f"sent_{DHCPLeaseType(DHCPUtilities.extract_dhcp_type_from_packet(packet)).name.lower()}"
        )


class DHCPHandler:

    _lock = RLock()

    @classmethod
    def handle_message(cls, dhcp_message: DhcpMessage):
        with cls._lock:
            try:
                match dhcp_message.dhcp_type:
                    case DHCPType.DISCOVER:
                        cls._handle_discover(dhcp_message)
                    case DHCPType.REQUEST:
                        cls._handle_request(dhcp_message)
                    case DHCPType.DECLINE:
                        cls._handle_decline(dhcp_message)
                    case DHCPType.RELEASE:
                        cls._handle_release(dhcp_message)
                    case DHCPType.INFORM:
                        cls._handle_inform(dhcp_message)
                    case _:
                        dhcp_logger.warning(f"DHCP Message {dhcp_message.dhcp_type} unknown.")

            except Exception as err:
                dhcp_logger.exception(f"Error processing DHCP packet as {str(err)}.")

    @classmethod
    def _handle_discover(cls, dhcp_message: DhcpMessage):
        """Handles DHCPDISCOVER messages (RFC 2131, Section 4.1) sent by clients to discover DHCP servers."""
        with cls._lock:
            dhcp_logger.debug(
                "Received DISCOVER XID=%s, MAC=%s.", dhcp_message.xid, dhcp_message.mac
            )

            proposed_ip = ClientDiscovery.discover_available_ip()
            if not proposed_ip:
                dhcp_logger.warning(f"No available IP")
                return

            DHCPReservationCache.reserve(ip=proposed_ip, mac=dhcp_message.mac)
            offer = DHCPResponseFactory.build(
                dhcp_type=DHCPType.OFFER, your_ip=proposed_ip, request_packet=dhcp_message.packet
            )
            cls._send_response(offer)

    @classmethod
    def _handle_request(cls, dhcp_message: DhcpMessage):

        dhcp_logger.debug(
            f"DHCP REQUEST "
            f"XID:{dhcp_message.xid}, "
            f"MAC:{dhcp_message.mac}, "
            f"IP_req:{dhcp_message.requested_ip}, "
            f"HOSTNAME:{dhcp_message.hostname}."
        )

        with cls._lock:
            dhcp_type = DHCPType.NAK
            your_ip = "0.0.0.0"
            lease = DHCPStorage.get_lease_by_mac(dhcp_message.mac)

            # 1) REQUEST after OFFER
            if (
                dhcp_message.requested_ip
                and dhcp_message.server_id
                and dhcp_message.ciaddr == "0.0.0.0"
            ):
                if dhcp_message.server_id == SERVER_IP and DHCPUtilities.is_ip_in_subnet(
                    dhcp_message.requested_ip
                ):
                    offered_ip = DHCPReservationCache.get_ip(dhcp_message.mac)
                    if offered_ip == dhcp_message.requested_ip:
                        DHCPStorage.add_lease(
                            dhcp_message.mac,
                            dhcp_message.requested_ip,
                            dhcp_message.hostname,
                            LEASE_TIME,
                        )
                        DHCPReservationCache.unreserve(dhcp_message.requested_ip, dhcp_message.mac)
                        dhcp_type, your_ip = DHCPType.ACK, dhcp_message.requested_ip
                    else:
                        dhcp_logger.debug("NAK REQUEST after OFFER mismatch")

            # 2) INIT-REBOOT
            elif dhcp_message.requested_ip and dhcp_message.ciaddr == "0.0.0.0":
                if DHCPUtilities.is_ip_in_subnet(dhcp_message.requested_ip):
                    arp_client = ClientDiscovery.discover_client_via_arp(dhcp_message.requested_ip)
                    if not arp_client or arp_client.mac == dhcp_message.mac:
                        if lease and lease[1] == dhcp_message.requested_ip or not arp_client:
                            DHCPStorage.add_lease(
                                dhcp_message.mac,
                                dhcp_message.requested_ip,
                                dhcp_message.hostname,
                                LEASE_TIME,
                            )
                            DHCPReservationCache.unreserve(
                                dhcp_message.requested_ip, dhcp_message.mac
                            )
                            dhcp_type, your_ip = DHCPType.ACK, dhcp_message.requested_ip
                        else:
                            dhcp_logger.debug("NAK INIT-REBOOT no matching lease and IP in use")
                    else:
                        dhcp_logger.debug("NAK INIT-REBOOT: IP used by different MAC")
                else:
                    dhcp_logger.debug("NAK INIT-REBOOT: IP outside subnet")

            # 3) RENEW/REBIND
            elif dhcp_message.ciaddr != "0.0.0.0" and not dhcp_message.requested_ip:
                if DHCPUtilities.is_ip_in_subnet(dhcp_message.ciaddr):
                    arp_client = ClientDiscovery.discover_client_via_arp(dhcp_message.ciaddr)
                    if not arp_client or (lease and lease[1] == dhcp_message.ciaddr):
                        DHCPStorage.add_lease(
                            dhcp_message.mac, dhcp_message.ciaddr, dhcp_message.hostname, LEASE_TIME
                        )
                        DHCPReservationCache.unreserve(dhcp_message.ciaddr, dhcp_message.mac)
                        dhcp_type, your_ip = DHCPType.ACK, dhcp_message.ciaddr
                    else:
                        dhcp_logger.debug("NAK RENEW/REBIND IP in use or lease mismatch")
                else:
                    dhcp_logger.debug("NAK RENEW/REBIND IP outside subnet")

            # 4) Invalid IP change without DISCOVER
            elif dhcp_message.requested_ip and dhcp_message.ciaddr != "0.0.0.0":
                dhcp_logger.warning("Invalid REQUEST: IP change without DISCOVER")
            else:
                dhcp_logger.debug("Invalid REQUEST: Missing valid IP info")

            response = DHCPResponseFactory.build(
                dhcp_type=dhcp_type, your_ip=your_ip, request_packet=dhcp_message.packet
            )
            cls._send_response(response)

    @classmethod
    def _handle_decline(cls, dhcp_message: DhcpMessage):
        """Handles DHCP Decline messages (RFC 2131, Section 4.3.2)"""

        _declined_ip = dhcp_message.requested_ip
        DHCPReservationCache.unreserve(ip=dhcp_message.requested_ip, mac=dhcp_message.mac)
        dhcp_logger.debug(
            f"Received DHCPDECLINE "
            f"XID={dhcp_message.xid}, "
            f"IP={_declined_ip}, "
            f"MAC={dhcp_message.mac}."
        )

        with cls._lock:
            _existing_lease = DHCPStorage.get_lease_by_mac(dhcp_message.mac)
            # Case 1: The client has a lease and it is for the declined IP
            if _existing_lease and _existing_lease[1] == _declined_ip:
                dhcp_logger.debug(
                    f"MAC:{dhcp_message.mac} declined IP:{_declined_ip}, removing lease from database."
                )
                DHCPStorage.remove_lease_by_mac(dhcp_message.mac)
            else:
                # Case 2: The client declined the IP and doesnt have active lease
                dhcp_logger.debug(
                    f"Client {dhcp_message.mac} declined IP {_declined_ip}, but no lease found."
                )

            response = DHCPResponseFactory.build(
                dhcp_type=DHCPType.NAK, your_ip="0.0.0.0", request_packet=dhcp_message.packet
            )

            cls._send_response(response)

    @classmethod
    def _handle_release(cls, dhcp_message: DhcpMessage):
        """DHCP Release (Section 4.4 of RFC 2131) sent by the client to release an IP address that it no longer needs."""

        dhcp_logger.debug(
            f"Received DHCPRELEASE "
            f"XID={dhcp_message.xid}, "
            f"IP={dhcp_message.src_ip}, "
            f"MAC={dhcp_message.mac}."
        )

        with cls._lock:
            DHCPStorage.remove_lease_by_mac(dhcp_message.mac)

    @classmethod
    def _handle_inform(cls, dhcp_message: DhcpMessage):
        """DHCPINFORM (Section 3.3.2 of RFC 2131)"""

        dhcp_logger.debug(
            f"Received DHCPINFORM "
            f"XID={dhcp_message.xid}, "
            f"IP={dhcp_message.src_ip}, "
            f"Requested={dhcp_message.param_req_list}."
        )

        with cls._lock:
            ack = DHCPResponseFactory.build(
                dhcp_type=DHCPType.ACK,
                your_ip=dhcp_message.src_ip,
                request_packet=dhcp_message.packet,
            )
            cls._send_response(ack)

    @classmethod
    def _send_response(cls, packet: Packet):
        """Send a DHCP packet on the configured interface."""
        try:
            DHCPLogger.log_outbound(packet)
            dhcp_logger.debug(
                f"Send: TYPE:{DHCPUtilities.extract_dhcp_type_from_packet(packet)}, "
                f"XID:{packet[BOOTP].xid}, "
                f"CHADDR:{packet[BOOTP].chaddr[:6].hex(':')}, "
                f"YIADDR:{packet[BOOTP].yiaddr}."
            )
            sendp(packet, iface=INTERFACE, verbose=False)
        except Exception as err:
            dhcp_logger.error(f"Failed to send DHCP response: {str(err)}")


class DHCPServer:

    _lock = threading.RLock()
    _initialised = False
    _running = False
    _workers = {}

    @classmethod
    def _init(cls) -> None:

        if cls._initialised:
            raise RuntimeError("Already Init")

        cls._received_queue = queue.Queue(maxsize=RECEIVED_QUEUE_SIZE)
        cls._dedup_queue = deque(maxlen=INBOUND_REQUESTS_DEQUE_SIZE)
        cls._initialised = True

    @classmethod
    def start(cls):
        """Start all necessary threads"""

        if not cls._initialised:
            cls._init()

        if cls._running:
            raise RuntimeError("Server already running.")
        cls._running = True

        with cls._lock:
            DHCPStorage.init()
            DHCPStats.init()
            BackgroundServices.start()
            DHCPResponseFactory.initialize(
                server_ip=SERVER_IP,
                server_mac=SERVER_MAC,
                port=PORT,
                broadcast_mac=BROADCAST_MAC,
                broadcast_ip=BROADCAST_IP,
                flags=BOOTP_FLAG_BROADCAST,
                router=ROUTER,
                subnet_mask=SUBNET_MASK,
                name_server=NAME_SERVER,
                lease_time=LEASE_TIME,
                renewal_time=RENEWAL_TIME,
                rebinding_time=REBINDING_TIME,
                mtu=MTU,
            )

            _traffic_listener = threading.Thread(
                target=cls._traffic_listener, name="dhcp-traffic-listener", daemon=True
            )
            _traffic_listener.start()
            cls._workers["traffic_listener"] = _traffic_listener

            for _index in range(DHCP_WORKERS):
                _worker = threading.Thread(
                    target=cls._processor, name=f"dhcp-worker_{_index}", daemon=True
                )
                _worker.start()
                cls._workers[f"worker_{_index}"] = _worker
            dhcp_logger.info("Started")

    @classmethod
    def _traffic_listener(cls, interface=INTERFACE, port=PORT):
        """Start sniffing for DHCP packets on the interface"""
        sniff(
            iface=interface,
            filter=f"ip and udp and port {port}",
            prn=cls._listen,
            stop_filter=lambda _: not cls._running,
            count=0,
            timeout=None,
            store=False,
            session=None,
        )

    @classmethod
    def _listen(cls, packet: Packet):
        """Callback for sniffed DHCP packets; enqueues into processing queue."""
        try:
            cls._received_queue.put_nowait(packet)
        except queue.Full:
            dhcp_logger.warning(f"Queue full.")
        except Exception as err:
            dhcp_logger.exception(f"Couldn't enqueue DHCP packet:{str(err)}.")

    @classmethod
    def _processor(cls):
        """Main processor function multi threaded."""
        while cls._running:
            dhcp_message = None
            try:
                dhcp_message = DhcpMessage(cls._received_queue.get(timeout=WORKER_GET_TIMEOUT))
                if (
                    dhcp_message.mac.lower() == SERVER_MAC.lower()
                    or dhcp_message.src_ip.lower() == SERVER_IP.lower()
                ):
                    continue

                if dhcp_message.dedup_key in cls._dedup_queue:
                    continue
                cls._dedup_queue.append(dhcp_message.dedup_key)

                DHCPLogger.log_inbound(dhcp_message)
                DHCPStats.increment(key="received_total")
                print(
                    "Received:",
                    dhcp_message.xid,
                    dhcp_message.mac,
                    dhcp_message.dhcp_type,
                    dhcp_message.src_ip,
                )
                DHCPHandler.handle_message(dhcp_message)

            except queue.Empty:
                continue

            except Exception as err:
                dhcp_logger.exception(
                    f"{threading.current_thread().name} processing DHCP packet as {str(err)}."
                )

            finally:
                if dhcp_message:
                    cls._received_queue.task_done()

    @classmethod
    def stop(cls):

        if not cls._running:
            raise RuntimeError("Server not running.")

        with cls._lock:
            cls._running = False
            BackgroundServices.stop()
            for _name, _thread in cls._workers.items():
                if _thread.is_alive():
                    dhcp_logger.info(f"Stopping {_name}.")
                    _thread.join(0.5)
            cls._workers.clear()
            dhcp_logger.info("DHCP server shut.")
