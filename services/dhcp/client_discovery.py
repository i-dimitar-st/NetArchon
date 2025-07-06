from ipaddress import IPv4Address, IPv4Network, AddressValueError
from threading import RLock, Event, Thread
from collections import Counter
from typing import Optional, List
from functools import wraps
from time import sleep
from copy import deepcopy
from logging import Logger

from scapy.sendrecv import srp
from scapy.layers.l2 import Ether, ARP
from scapy.packet import Packet

from models.models import ArpClient
from services.dhcp.db_core import DHCPStorage
from config.config import config

DHCP_CONFIG = config.get("dhcp")

INTERFACE = DHCP_CONFIG.get("interface")
SERVER_IP = DHCP_CONFIG.get("ip")
SERVER_MAC = DHCP_CONFIG.get("mac")
BROADCAST_IP = DHCP_CONFIG.get("broadcast_ip")
BROADCAST_MAC = DHCP_CONFIG.get("broadcast_mac")
IP_RANGE_START = DHCP_CONFIG.get("ip_pool_start")
IP_RANGE_END = DHCP_CONFIG.get("ip_pool_end")

CIDR = DHCP_CONFIG.get("cidr")
ARP_TIMEOUT_SUBNET = 2
ARP_TIMEOUT_SINGLE = 1
ARP_RETRIES = 3
ARP_RETRIES_DELAY = 0.5
APR_INTER_DELAY = 0.005

WORKER_GET_TIMEOUT = 0.2
WORKER_SLEEP_TIMEOUT = 0.1
WORKER_JOIN_TIMEOUT = 0.5
ARP_REQUEST = 1

CLIENT_DISCOVERY_INTERVAL = 30


def is_init(func):
    @wraps(func)
    def wrapper(cls, *args, **kwargs):
        if getattr(cls, "initialized", False) == False:
            raise RuntimeError("Not init")
        return func(cls, *args, **kwargs)

    return wrapper


def is_running(func):
    @wraps(func)
    def wrapper(cls, *args, **kwargs):
        if getattr(cls, "running", False) == False:
            raise RuntimeError("Not running")
        return func(cls, *args, **kwargs)

    return wrapper


def is_not_running(func):
    @wraps(func)
    def wrapper(cls, *args, **kwargs):
        if getattr(cls, "running", False) == True:
            raise RuntimeError("Already running")
        return func(cls, *args, **kwargs)

    return wrapper


class ClientDiscoveryService:
    _lock = RLock()
    _stop_event: Optional[Event] = None
    _worker: Optional[Thread] = None
    initialized = False
    running = False

    # Config
    _ip_range_start: Optional[IPv4Address] = None
    _ip_range_end: Optional[IPv4Address] = None
    _network: Optional[IPv4Network] = None
    _live_clients: List[ArpClient] = []

    # Configurable system parameters
    _server_ip: str
    _iface: str
    _server_mac: str
    _broadcast_mac: str
    _arp_request_type: int
    _arp_timeout_subnet: float
    _arp_timeout_single: float
    _arp_retries: int

    @classmethod
    def init(
        cls,
        logger: Logger,
        server_ip: str = SERVER_IP,
        cidr: str = CIDR,
        ip_range_start: str = IP_RANGE_START,
        ip_range_end: str = IP_RANGE_END,
        iface: str = INTERFACE,
        server_mac: str = SERVER_MAC,
        broadcast_mac: str = BROADCAST_MAC,
        arp_request_type: int = ARP_REQUEST,
        arp_timeout_subnet: float = ARP_TIMEOUT_SUBNET,
        arp_timeout_single: float = ARP_TIMEOUT_SINGLE,
    ):
        with cls._lock:
            cls._network = IPv4Network(f"{server_ip}/{cidr}", strict=False)
            cls._ip_range_start = IPv4Address(ip_range_start)
            cls._ip_range_end = IPv4Address(ip_range_end)

            cls._server_ip = server_ip
            cls._iface = iface
            cls._server_mac = server_mac
            cls._broadcast_mac = broadcast_mac
            cls._arp_request_type = arp_request_type
            cls._arp_timeout_subnet = arp_timeout_subnet
            cls._arp_timeout_single = arp_timeout_single
            cls._live_clients = []
            cls._stop_event = Event()
            cls.logger: Logger = logger
            cls.initialized = True

    @classmethod
    @is_init
    @is_not_running
    def start(cls):
        with cls._lock:
            cls.running = True
            cls._worker = Thread(target=cls._work, daemon=True)
            cls._worker.start()
            cls.logger.debug("%s started.", cls.__name__)

    @classmethod
    @is_init
    @is_running
    def stop(cls):
        with cls._lock:
            if cls._stop_event:
                cls._stop_event.set()
            _worker = cls._worker

        if _worker:
            _worker.join(timeout=1)
            if _worker.is_alive():
                cls.logger.warning("%s did not stop after timeout.", cls.__name__)
                return
            else:
                cls.logger.debug("%s Stopped.", cls.__name__)

    @classmethod
    @is_init
    @is_running
    def _work(
        cls,
        interval=CLIENT_DISCOVERY_INTERVAL,
        retry_cont=ARP_RETRIES,
        retry_delay=ARP_RETRIES_DELAY,
    ):
        if cls._stop_event is None:
            raise RuntimeError("mising top event, wrong init")
        while not cls._stop_event.is_set():
            try:
                _scanned_clients = dict()
                _counts = Counter()
                for _ in range(retry_cont):
                    for _current_scan_client in cls._discover_live_clients():
                        _counts[_current_scan_client.mac] += 1
                        _scanned_clients[_current_scan_client.mac] = (
                            _current_scan_client
                        )

                    sleep(retry_delay)

                with cls._lock:
                    cls._live_clients = [
                        _scanned_clients[_mac]
                        for _mac, _count in _counts.items()
                        if _count >= retry_cont
                    ]
                    cls.logger.debug("Discovered %s clients.", len(cls._live_clients))

            except Exception as _err:
                cls.logger.warning("Error discovering clients: %s", _err)

            cls._stop_event.wait(interval)

        with cls._lock:
            cls.running = False

    @classmethod
    def _discover_live_clients(cls) -> List[ArpClient]:
        if not cls._network:
            raise RuntimeError("missing network wrong init")
        try:
            _arp_req_pcks: List[Packet] = [
                Ether(dst=cls._broadcast_mac, src=cls._server_mac)
                / ARP(pdst=str(ip), psrc=cls._server_ip, op=cls._arp_request_type)
                for ip in cls._network.hosts()
            ]

            _answered_arp_req_pcks, _ = srp(
                _arp_req_pcks,
                timeout=cls._arp_timeout_subnet,
                verbose=False,
                inter=APR_INTER_DELAY,
                iface=cls._iface,
            )

            _seen = set()
            return [
                ArpClient(mac=_pkt[ARP].hwsrc, ip=_pkt[ARP].psrc)
                for _, _pkt in _answered_arp_req_pcks
                if _pkt[ARP].hwsrc not in _seen
                and _seen.add(_pkt[ARP].hwsrc)
                is None  # _seen.add(pkt[ARP].hwsrc) returns None when successfull
            ]

        except Exception as err:
            cls.logger.error("Error during ARP discovery: %s", err)
            return []

    @classmethod
    def _probe_ip(cls, ip: str) -> Optional[ArpClient]:
        try:
            IPv4Address(ip)

            arp_request: Packet = Ether(
                dst=cls._broadcast_mac, src=cls._server_mac
            ) / ARP(pdst=ip, psrc=cls._server_ip, op=cls._arp_request_type)

            answered, _ = srp(
                arp_request,
                timeout=cls._arp_timeout_single,
                verbose=False,
                iface=cls._iface,
            )

            if len(answered) == 1:
                _, recv_pck = answered[0]
                return ArpClient(mac=recv_pck[ARP].hwsrc, ip=recv_pck[ARP].psrc)

            if len(answered) > 1:
                cls.logger.warning("Multiple ARP responses received for IP %s", ip)

        except AddressValueError:
            cls.logger.error("Invalid IP _probe_ip: %s", ip)

        except Exception as err:
            cls.logger.error("Error sending ARP to %s: %s", ip, err)

        return None

    @classmethod
    @is_init
    @is_running
    def get_live_clients(cls) -> List[ArpClient]:
        with cls._lock:
            return deepcopy(cls._live_clients)

    @classmethod
    @is_init
    @is_running
    def get_live_client_by_ip(cls, ip: str) -> Optional[ArpClient]:
        with cls._lock:
            for client in cls._live_clients:
                if client.ip == ip:
                    return ArpClient(mac=client.mac, ip=client.ip)
        return None

    @classmethod
    @is_init
    @is_running
    def get_available_ip(cls) -> str:
        if cls._ip_range_start is None or cls._ip_range_end is None:
            raise RuntimeError("Not initialized.")

        with cls._lock:
            discovered_ips = {client.ip for client in cls._live_clients}
            leased_ips = DHCPStorage.get_all_leased_ips()

        for ip_int in range(int(cls._ip_range_start), int(cls._ip_range_end) + 1):
            candidate_ip = str(IPv4Address(ip_int))
            if candidate_ip in leased_ips or candidate_ip in discovered_ips:
                continue

            if cls._probe_ip(candidate_ip):
                continue

            cls.logger.debug("Proposing IP: %s", candidate_ip)
            return candidate_ip

        cls.logger.warning("No available IPs found.")
        return ""
