import ipaddress
import queue
import threading
import scapy.all as scapy
from pathlib import Path
from threading import RLock
from collections import deque
from typing import Optional, List
from scapy.plist import SndRcvList, PacketList
from scapy.layers.dhcp import BOOTP
from scapy.layers.l2 import Ether, ARP
from scapy.packet import Packet
from services.dhcp.db import DHCPStorage, DHCPStats
from services.dns.utils import TTLCache
from services.dhcp.utils import DHCPUtilities, delete_files_in_dir
from services.logger.logger import MainLogger
from services.config.config import config
from models.models import DHCPResponseFactory, ArpClient, DhcpMessage, DHCPType


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
CIDR = "24"
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
STALE_LEASE_REMOVAL = 3600
LEASE_DISCOVERY = 300

ARP_TIMEOUT = 3
WORKER_GET_TIMEOUT = 0.2
WORKER_SLEEP_TIMEOUT = 0.1

# WORKFLOW
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


dhcp_logger = MainLogger.get_logger(service_name="DHCP", log_level="debug")


class DbPersistence:
    _interval = None
    _stop_event = threading.Event()
    _worker = None

    @classmethod
    def init(cls, interval=DB_PERSISTENCE_INTERVAL):
        cls._interval = interval
        cls._worker = threading.Thread(target=cls._work, daemon=True)

    @classmethod
    def _work(cls):
        while not cls._stop_event.is_set():
            try:
                DHCPStorage.save_to_disk()
                DHCPStats.save_to_disk()
            except Exception as err:
                dhcp_logger.warning(f"Persistence error: {str(err)}")
            cls._stop_event.wait(cls._interval)

    @classmethod
    def start(cls):
        if cls._worker is None or not cls._worker.is_alive():
            cls._stop_event.clear()
            cls._worker = threading.Thread(target=cls._work, daemon=True)
            cls._worker.start()

    @classmethod
    def stop(cls):
        if cls._stop_event:
            cls._stop_event.set()
        if cls._worker:
            cls._worker.join(timeout=1)


class DbLeaseCleaner:
    _interval = None
    _stop_event = threading.Event()
    _worker = None

    @classmethod
    def init(cls, interval=STALE_LEASE_REMOVAL):
        cls._interval = interval
        cls._worker = threading.Thread(target=cls._work, daemon=True)

    @classmethod
    def _work(cls):
        while not cls._stop_event.is_set():
            try:
                DHCPStorage.remove_expired_leases()
                active_leases_macs = {lease[0] for lease in DHCPStorage.get_all_leases()}
                active_clients = Discovery.discover_clients_via_arp()
                active_clients_macs = {client.mac for client in active_clients}
                to_remove = {mac for mac in active_leases_macs if mac not in active_clients_macs}
                if to_remove:
                    DHCPStorage.remove_leases_by_mac(to_remove)
                    dhcp_logger.info(f"Removed leases for MACs: {to_remove}")
            except Exception as err:
                dhcp_logger.error(f"Error during lease_cleaner: {str(err)}")

            cls._stop_event.wait(cls._interval)

    @classmethod
    def start(cls):
        if cls._worker is None or not cls._worker.is_alive():
            cls._stop_event.clear()
            cls._worker = threading.Thread(target=cls._work, daemon=True)
            cls._worker.start()

    @classmethod
    def stop(cls):
        if cls._stop_event:
            cls._stop_event.set()
        if cls._worker:
            cls._worker.join(timeout=1)


class LeaseDiscovery:
    _interval = None
    _stop_event = threading.Event()

    @classmethod
    def init(cls, interval=LEASE_DISCOVERY):
        cls._interval = interval
        cls._worker = threading.Thread(target=cls._work, daemon=True)

    @classmethod
    def _work(cls):
        while not cls._stop_event.is_set():
            try:
                active_leases_macs = {lease[0] for lease in DHCPStorage.get_all_leases()}
                discovered_clients = Discovery.discover_clients_via_arp()
                for client in discovered_clients:
                    if client.mac not in active_leases_macs:
                        DHCPStorage.add_lease(mac=client.mac, ip=client.ip, lease_type='static')
            except Exception as err:
                dhcp_logger.error(f"Error during lease_discovery: {str(err)}")
            cls._stop_event.wait(cls._interval)

    @classmethod
    def start(cls):
        if cls._worker is None or not cls._worker.is_alive():
            cls._stop_event.clear()
            cls._worker = threading.Thread(target=cls._work, daemon=True)
            cls._worker.start()

    @classmethod
    def stop(cls):
        if cls._stop_event:
            cls._stop_event.set()
        if cls._worker:
            cls._worker.join(timeout=1)


class Discovery:

    _lock = threading.RLock()
    _reserved_ips: set[str] = set()

    @staticmethod
    def discover_client_via_arp(ip: str = '',
                                iface: str = INTERFACE,
                                source_ip: str = SERVER_IP,
                                source_mac: str = SERVER_MAC,
                                broadcast_mac: str = BROADCAST_MAC,
                                timeout: float = ARP_TIMEOUT) -> Optional[ArpClient]:
        """Send an ARP request to check if the IP is still busy."""
        try:

            _packet = (Ether(dst=broadcast_mac, src=source_mac) /
                       ARP(pdst=ip, psrc=source_ip, op=1))

            _answered: SndRcvList
            _answered, _unanswered = scapy.srp(_packet,
                                               timeout=timeout,
                                               verbose=False,
                                               iface=iface)

            if _answered:
                _sent, _received = _answered[0]
                return ArpClient(mac=_received[ARP].hwsrc,
                                 ip=_received[ARP].psrc)

        except Exception as err:
            dhcp_logger.error(f"Unexpected error sending ARP request to {ip}: {err}")

        return None

    @staticmethod
    def discover_clients_via_arp(iface: str = INTERFACE,
                                 server_ip: str = SERVER_IP,
                                 server_mac: str = SERVER_MAC,
                                 broadcast_mac: str = BROADCAST_MAC,
                                 timeout: float = ARP_TIMEOUT,
                                 cidr: str = CIDR) -> List[ArpClient]:
        """Send a broadcast ARP request to discover all active clients on the network."""
        discovered_clients = []
        try:
            _network = ipaddress.IPv4Network(f"{server_ip}/{cidr}", strict=False)
            _subnet = str(_network.network_address) + f"/{cidr}"

            _packet = (Ether(dst=broadcast_mac, src=server_mac) /
                       ARP(pdst=_subnet, psrc=server_ip, op=1))

            _answered: SndRcvList
            _answered, _unanswered = scapy.srp(_packet,
                                               timeout=timeout,
                                               verbose=False,
                                               iface=iface)
            discovered_clients = []
            for _sent, _received in _answered:
                discovered_clients.append(ArpClient(mac=_received[ARP].hwsrc,
                                                    ip=_received[ARP].psrc))
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

            if (DCHPIpProposalCache.get_mac(candidate_ip) or
                candidate_ip in _leased_ips or
                    candidate_ip in _discovered_ips):
                continue

            if cls.discover_client_via_arp(ip=candidate_ip):
                continue

            dhcp_logger.debug(f"proposing IP:{candidate_ip}.")
            return candidate_ip

        dhcp_logger.warning("No available IPs found.")
        return ""


class DCHPIpProposalCache:
    _cache: TTLCache = TTLCache(max_size=100, ttl=60)

    @classmethod
    def mark(cls, ip: str, mac: str) -> bool:
        """
        Reserve IP for MAC if free or reserved by same MAC.
        Return False if IP reserved by different MAC.
        """
        existing_mac = cls._cache.get((ip,))
        if existing_mac and existing_mac != mac:
            return False
        cls._cache.add((ip,), mac)
        return True

    @classmethod
    def unmark(cls, ip: str, mac: str):
        """Release IP reservation if reserved by MAC."""
        if cls._cache.get((ip,)) == mac:
            cls._cache.remove((ip,))

    @classmethod
    def get_mac(cls, ip: str) -> Optional[str]:
        """Return MAC reserved on IP or None."""
        return cls._cache.get((ip,))

    @classmethod
    def get_ip(cls, mac: str) -> Optional[str]:
        """
        Return IP reserved by MAC or None.
        Scans all cached entries, O(n).
        """
        with cls._cache._lock:
            for ip_key, (stored_mac, _) in cls._cache._cache.items():
                if stored_mac == mac:
                    return ip_key[0]
        return None


class DHCPLogger:

    @staticmethod
    def log_inbound(dhcp_message: DhcpMessage):
        """Logs details of an inbound DHCP packet."""
        DHCPStats.increment(key="received_total_valid")
        DHCPStats.increment(key=f"received_{DHCPUtilities.convert_dhcp_lease_to_string(dhcp_message.dhcp_type)}")

    @staticmethod
    def log_outbound(packet: Packet):
        """Logs details of an outbound DHCP packet."""
        DHCPStats.increment(key="sent_total")
        DHCPStats.increment(key=f"sent_{DHCPUtilities.convert_dhcp_lease_to_string(DHCPUtilities.extract_dhcp_type_from_packet(packet))}")


class DHCPServer:

    def __init__(self) -> None:
        self._running = True
        self._lock = RLock()
        self._offered_ips: dict[str, str] = {}
        self._threads = {}
        self._received_queue = queue.Queue(maxsize=RECEIVED_QUEUE_SIZE)
        self._dedup_queue = deque(maxlen=INBOUND_REQUESTS_DEQUE_SIZE)
        DHCPResponseFactory.initialize(server_ip=SERVER_IP,
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
                                       mtu=MTU)

    def start(self):
        """ Start all necessary threads """
        self._running = True
        with self._lock:
            delete_files_in_dir(path=str(DB_PATH), starts_with="dhcp")
            DHCPStorage.init()
            DHCPStats.init()
            DbPersistence.init()
            LeaseDiscovery.init()
            DbLeaseCleaner.init()

            DbPersistence.start()
            LeaseDiscovery.start()
            DbLeaseCleaner.start()

            _listener = threading.Thread(target=self._traffic_listener,
                                         name="dhcp-traffic-listener",
                                         daemon=True)
            _listener.start()
            self._threads["listener"] = _listener
            for _index in range(5):
                _worker = threading.Thread(target=self._processor,
                                           name=f"dhcp-worker_{_index}",
                                           daemon=True)
                _worker.start()
                self._threads[f"worker_{_index}"] = _worker

            dhcp_logger.info("Started")

    def stop(self):
        self._running = False
        with self._lock:
            DbPersistence.stop()
            LeaseDiscovery.stop()
            DbLeaseCleaner.stop()
            for thread_name, thread in self._threads.items():
                if thread.is_alive():
                    dhcp_logger.info(f"Stopping {thread_name}.")
                    thread.join(timeout=1)
            dhcp_logger.info("DHCP server shut.")

    def _traffic_listener(self, interface=INTERFACE, port=PORT):
        """ Start sniffing for DHCP packets on the interface """
        scapy.sniff(iface=interface,
                    filter=f"ip and udp and port {port}",
                    prn=self._listen,
                    count=0,
                    timeout=None,
                    store=False,
                    session=None)

    def _listen(self, packet: Packet):
        """Listen and enquire dhsp packages"""

        try:
            self._received_queue.put_nowait(packet)

        except queue.Full:
            dhcp_logger.warning(f"Queue full.")

        except Exception as err:
            dhcp_logger.exception(f"Couldn't enqueue DNS packet:{str(err)}.")

    def _processor(self):
        """Main processor function multi threaded."""
        while self._running:
            dhcp_message = None
            try:
                dhcp_message = DhcpMessage(self._received_queue.get(timeout=WORKER_GET_TIMEOUT))
                if (dhcp_message.mac.lower() == SERVER_MAC.lower() or
                        dhcp_message.src_ip.lower() == SERVER_IP.lower()):
                    continue
                if dhcp_message.dedup_key in self._dedup_queue:
                    continue
                self._dedup_queue.append(dhcp_message.dedup_key)

                DHCPLogger.log_inbound(dhcp_message)
                DHCPStats.increment(key="received_total")
                print("Received:", dhcp_message.xid, dhcp_message.mac, dhcp_message.dhcp_type, dhcp_message.src_ip)

                match dhcp_message.dhcp_type:
                    case DHCPType.DISCOVER:
                        self._handle_discover(dhcp_message)
                    case DHCPType.REQUEST:
                        self._handle_request(dhcp_message)
                    case DHCPType.DECLINE:
                        self._handle_decline(dhcp_message)
                    case DHCPType.RELEASE:
                        self._handle_release(dhcp_message)
                    case DHCPType.INFORM:
                        self._handle_inform(dhcp_message)
                    case _:
                        dhcp_logger.warning(f"DHCP Message {dhcp_message.dhcp_type} unknown.")

            except queue.Empty:
                continue

            except Exception as err:
                print(err)
                dhcp_logger.exception(f"{threading.current_thread().name} processing DHCP packet as {str(err)}.")

            finally:
                if dhcp_message:
                    self._received_queue.task_done()

    def _handle_discover(self, dhcp_message: DhcpMessage):
        """Handles DHCPDISCOVER messages (RFC 2131, Section 4.1) sent by clients to discover DHCP servers."""
        with self._lock:

            dhcp_logger.debug(f"Received DISCOVER "
                              f"XID={dhcp_message.xid}, "
                              f"MAC={dhcp_message.mac}.")

            proposed_ip = Discovery.discover_available_ip()
            if not proposed_ip:
                dhcp_logger.warning(f"No available IP")
                return

            DCHPIpProposalCache.mark(ip=proposed_ip, mac=dhcp_message.mac)
            offer = DHCPResponseFactory.build(dhcp_type=DHCPType.OFFER,
                                              your_ip=proposed_ip,
                                              request_packet=dhcp_message.packet)
            self._send_response(offer)

    def _handle_request(self, dhcp_message: DhcpMessage):

        dhcp_logger.debug(f"DHCP REQUEST "
                          f"XID:{dhcp_message.xid}, "
                          f"MAC:{dhcp_message.mac}, "
                          f"IP_req:{dhcp_message.requested_ip}, "
                          f"HOSTNAME:{dhcp_message.hostname}.")

        with self._lock:
            dhcp_type = DHCPType.NAK
            your_ip = "0.0.0.0"
            lease = DHCPStorage.get_lease_by_mac(dhcp_message.mac)

            # 1) REQUEST after OFFER
            if dhcp_message.requested_ip and dhcp_message.server_id and dhcp_message.ciaddr == "0.0.0.0":
                if dhcp_message.server_id == SERVER_IP and DHCPUtilities.is_ip_in_subnet(dhcp_message.requested_ip):
                    offered_ip = DCHPIpProposalCache.get_ip(dhcp_message.mac)
                    if offered_ip == dhcp_message.requested_ip:
                        DHCPStorage.add_lease(dhcp_message.mac, dhcp_message.requested_ip, dhcp_message.hostname, LEASE_TIME)
                        DCHPIpProposalCache.unmark(dhcp_message.requested_ip, dhcp_message.mac)
                        dhcp_type, your_ip = DHCPType.ACK, dhcp_message.requested_ip
                    else:
                        dhcp_logger.debug("NAK REQUEST after OFFER mismatch")

            # 2) INIT-REBOOT
            elif dhcp_message.requested_ip and dhcp_message.ciaddr == "0.0.0.0":
                if DHCPUtilities.is_ip_in_subnet(dhcp_message.requested_ip):
                    arp_client = Discovery.discover_client_via_arp(dhcp_message.requested_ip)
                    if not arp_client or arp_client.mac == dhcp_message.mac:
                        if lease and lease[1] == dhcp_message.requested_ip or not arp_client:
                            DHCPStorage.add_lease(dhcp_message.mac, dhcp_message.requested_ip, dhcp_message.hostname, LEASE_TIME)
                            DCHPIpProposalCache.unmark(dhcp_message.requested_ip, dhcp_message.mac)
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
                    arp_client = Discovery.discover_client_via_arp(dhcp_message.ciaddr)
                    if not arp_client or (lease and lease[1] == dhcp_message.ciaddr):
                        DHCPStorage.add_lease(dhcp_message.mac, dhcp_message.ciaddr, dhcp_message.hostname, LEASE_TIME)
                        DCHPIpProposalCache.unmark(dhcp_message.ciaddr, dhcp_message.mac)
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

            response = DHCPResponseFactory.build(dhcp_type=dhcp_type, your_ip=your_ip, request_packet=dhcp_message.packet)
            self._send_response(response)

    def _handle_decline(self, dhcp_message: DhcpMessage):
        """Handles DHCP Decline messages (RFC 2131, Section 4.3.2)"""

        _declined_ip = dhcp_message.requested_ip
        DCHPIpProposalCache.unmark(ip=dhcp_message.requested_ip, mac=dhcp_message.mac)
        dhcp_logger.debug(f"Received DHCPDECLINE "
                          f"XID={dhcp_message.xid}, "
                          f"IP={_declined_ip}, "
                          f"MAC={dhcp_message.mac}.")

        with self._lock:
            _existing_lease = DHCPStorage.get_lease_by_mac(dhcp_message.mac)
            # Case 1: The client has a lease and it is for the declined IP
            if _existing_lease and _existing_lease[1] == _declined_ip:
                dhcp_logger.debug(f"Client MAC:{dhcp_message.mac} declined IP:{_declined_ip}, removing lease from database")
                DHCPStorage.remove_lease_by_mac(dhcp_message.mac)
            else:
                # Case 2: The client declined the IP and doesnt have active lease
                dhcp_logger.debug(f"Client {dhcp_message.mac} declined IP {_declined_ip}, but no lease found")

            response = DHCPResponseFactory.build(dhcp_type=DHCPType.NAK,
                                                 your_ip="0.0.0.0",
                                                 request_packet=dhcp_message.packet)

            self._send_response(packet=response)

    def _handle_release(self, dhcp_message: DhcpMessage):
        """DHCP Release (Section 4.4 of RFC 2131) sent by the client to release an IP address that it no longer needs."""

        dhcp_logger.debug(f"Received DHCPRELEASE "
                          f"XID={dhcp_message.xid}, "
                          f"IP={dhcp_message.src_ip}, "
                          f"MAC={dhcp_message.mac}.")

        with self._lock:
            DHCPStorage.remove_lease_by_mac(dhcp_message.mac)

    def _handle_inform(self,  dhcp_message: DhcpMessage):
        """DHCPINFORM (Section 3.3.2 of RFC 2131)"""

        dhcp_logger.debug(f"Received DHCPINFORM "
                          f"XID={dhcp_message.xid}, "
                          f"IP={dhcp_message.src_ip}, "
                          f"Requested={dhcp_message.param_req_list}.")

        with self._lock:
            ack = DHCPResponseFactory.build(dhcp_type=DHCPType.ACK,
                                            your_ip=dhcp_message.src_ip,
                                            request_packet=dhcp_message.packet)
            self._send_response(ack)

    def _send_response(self, packet: Packet):
        """Send a DHCP packet on the configured interface."""
        try:
            DHCPLogger.log_outbound(packet)
            dhcp_logger.debug(f"Send: TYPE:{DHCPUtilities.extract_dhcp_type_from_packet(packet)}, "
                              f"XID:{packet[BOOTP].xid}, "
                              f"CHADDR:{packet[BOOTP].chaddr[:6].hex(':')}, "
                              f"YIADDR:{packet[BOOTP].yiaddr}")
            scapy.sendp(packet, iface=INTERFACE, verbose=False)
        except Exception as err:
            dhcp_logger.error(f"Failed to send DHCP response: {str(err)}")
