from ipaddress import IPv4Address, IPv4Network
from threading import RLock, Event, Thread
from typing import Optional, List, Set, Dict
from functools import wraps
from time import sleep
from logging import Logger

from scapy.sendrecv import srp
from scapy.layers.l2 import Ether, ARP

from utils.dhcp_utils import is_net_interface_valid
from models.models import ArpClient
from services.dhcp.db_core import DHCPStorage
from config.config import config

DHCP_CONFIG = config.get("dhcp")

INTERFACE = str(DHCP_CONFIG.get("interface"))
SERVER_IP = str(DHCP_CONFIG.get("ip"))
SERVER_MAC = str(DHCP_CONFIG.get("mac"))
BROADCAST_IP = str(DHCP_CONFIG.get("broadcast_ip"))
BROADCAST_MAC = str(DHCP_CONFIG.get("broadcast_mac"))
IP_RANGE_START = str(DHCP_CONFIG.get("ip_pool_start"))
IP_RANGE_END = str(DHCP_CONFIG.get("ip_pool_end"))
CIDR = str(DHCP_CONFIG.get("cidr"))

CLIENT_DISCOVERY = DHCP_CONFIG.get("client_discovery")
DISCOVERY_TIMEOUTS = CLIENT_DISCOVERY.get("timeouts")
DISCOVERY_WORKERS = int(CLIENT_DISCOVERY.get("workers"))
DISCOVERY_INTERVAL = int(CLIENT_DISCOVERY.get("interval"))

ARP_RETRIES = int(CLIENT_DISCOVERY.get("retries"))

ARP_TIMEOUT_SUBNET = float(DISCOVERY_TIMEOUTS.get("subnet"))
ARP_TIMEOUT_SINGLE = float(DISCOVERY_TIMEOUTS.get("single"))
ARP_RETRIES_DELAY = float(DISCOVERY_TIMEOUTS.get("retry_delay"))
APR_INTER_DELAY = float(DISCOVERY_TIMEOUTS.get("inter_delay"))
WORKER_JOIN_TIMEOUT = float(DISCOVERY_TIMEOUTS.get("worker_join"))


def discover_live_clients(
    network: IPv4Network,
    broadcast_mac: str = BROADCAST_MAC,
    timeout: float = ARP_TIMEOUT_SUBNET,
    inter_delay: float = APR_INTER_DELAY,
    retry_delay: float = ARP_RETRIES_DELAY,
    retries: int = ARP_RETRIES,
    iface: str = INTERFACE,
    verbose: bool = False
) -> Dict[str, ArpClient]:
    """
    Perform an ARP scan over the network to discover live clients.
    Args:
        network (IPv4Network): Target subnet to scan.
        broadcast_mac (str): Broadcast MAC address.
        timeout (float): Timeout for each ARP request.
        inter_delay (float): Delay between ARP requests.
        retry_delay (float): Delay between sunseqient scan cycles.
        retry_delay (int): Scan cycles.
        iface (str): Network interface to use.
        verbose (bool): Enable scapy verbose output.
    Raises:
        RuntimeError: If the network is not initialized.
    Returns:
        Dict[str, ArpClient]: Mapping of IP addresses to ArpClient instances.
                             Returns empty dict if no clients found or on error.
    """
    if not network:
        raise RuntimeError("Missing nerwork")

    clients: Dict[str, ArpClient] = {}

    for _ in range(retries):

        _answered, _ = srp(
            [Ether(dst=broadcast_mac) / ARP(pdst=str(ip)) for ip in network.hosts()],
            timeout=timeout,
            inter=inter_delay,
            filter="arp",
            verbose=verbose,
            iface=iface,
        )

        for _, _resp in _answered:

            if _resp[ARP].psrc not in clients:
                clients[_resp[ARP].psrc] = ArpClient(
                    mac=_resp[ARP].hwsrc, ip=_resp[ARP].psrc
                )

        sleep(retry_delay)

    return clients


def send_arp_request(
    ip: IPv4Address,
    iface: str = INTERFACE,
    timeout: float = ARP_TIMEOUT_SINGLE,
    broadcast_mac: str = BROADCAST_MAC,
) -> ArpClient | None:
    """
    Send an ARP request to a single IP address on a given interface.
    Args:
        ip (IPv4Address): The target IP address to query.
        iface (str, optional): Network interface to send the request on. Defaults to INTERFACE.
        timeout (float, optional): Timeout in seconds to wait for a response. Defaults to ARP_TIMEOUT_SINGLE.
    Returns:
        ArpClient | None: An ArpClient object if a device responds, None if no response.
                         Raises RuntimeError if more than one device responds.
    """
    _answered, _ = srp(
        Ether(dst=broadcast_mac) / ARP(pdst=str(ip)),
        timeout=timeout,
        iface=iface,
        verbose=False,
        filter="arp",
    )

    if _answered:
        if len(_answered) == 1:
            _, _recv = _answered[0]
            return ArpClient(mac=_recv[ARP].hwsrc, ip=_recv[ARP].psrc)
        if len(_answered) > 1:
            raise RuntimeError("More than 1 device")

    return None


def client_disc_is_init(func):
    @wraps(func)
    def wrapper(cls, *args, **kwargs):
        if getattr(cls, "initialized", False) is False:
            raise RuntimeError("Not init")
        return func(cls, *args, **kwargs)

    return wrapper


def client_disc_is_running(func):
    @wraps(func)
    def wrapper(cls, *args, **kwargs):
        if getattr(cls, "running", False) is False:
            raise RuntimeError("Not running")
        return func(cls, *args, **kwargs)

    return wrapper


def client_disc_is_not_running(func):
    @wraps(func)
    def wrapper(cls, *args, **kwargs):
        if getattr(cls, "running", False) is True:
            raise RuntimeError("Already running")
        return func(cls, *args, **kwargs)

    return wrapper


class ClientDiscoveryService:
    """
    Discovers live clients on a local IPv4 network using ARP scans.
    Maintains a list of active devices and helps find available IPs for DHCP allocation.

    ### Main Features:
    - Periodically scans the subnet using ARP.
    - Tracks discovered clients in a thread-safe list.
    - Returns available IPs not currently leased or in use.
    - Supports clean start/stop lifecycle.

    ### Key Dependencies:
    - `scapy` for ARP scanning.
    - `DHCPStorage` for tracking leased IPs.
    - `ArpClient` to represent discovered devices.
    - `config["dhcp"]` for network setup.
    - `logger` passed during init for diagnostics.

    ### Lifecycle:
    - Call `init(logger)` to configure.
    - Use `start()` to begin scanning.
    - Use `stop()` to halt discovery.
    - Call `get_available_ip()` to fetch a usable IP.
    """

    _lock = RLock()
    _stop_event = Event()
    _worker: Optional[Thread] = None
    initialized = False
    running = False

    _ip_range_start: Optional[IPv4Address] = None
    _ip_range_end: Optional[IPv4Address] = None
    network: Optional[IPv4Network] = None
    _live_clients: Dict[str, ArpClient]

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
        arp_timeout_subnet: float = ARP_TIMEOUT_SUBNET,
        arp_timeout_single: float = ARP_TIMEOUT_SINGLE,
        client_discovery_interval: int = DISCOVERY_INTERVAL,
    ):
        with cls._lock:

            if not is_net_interface_valid(iface):
                raise RuntimeError("Invalid Interface")

            cls.network = IPv4Network(f"{server_ip}/{cidr}", strict=False)
            cls._ip_range_start = IPv4Address(ip_range_start)
            cls._ip_range_end = IPv4Address(ip_range_end)

            cls._client_discovery_interval = client_discovery_interval

            cls._server_ip = server_ip
            cls._iface = iface
            cls._server_mac = server_mac
            cls._broadcast_mac = broadcast_mac
            cls._arp_timeout_subnet = arp_timeout_subnet
            cls._arp_timeout_single = arp_timeout_single
            cls._live_clients: Dict[str, ArpClient] = {}

            cls.logger = logger
            cls.initialized = True

    @classmethod
    @client_disc_is_init
    @client_disc_is_not_running
    def start(cls):
        with cls._lock:
            cls.running = True
            cls._worker = Thread(target=cls._work, daemon=True)
            cls._worker.start()
            cls.logger.debug("%s started.", cls.__name__)

    @classmethod
    @client_disc_is_init
    @client_disc_is_running
    def stop(cls):
        with cls._lock:
            cls._stop_event.set()
            if cls._worker:
                cls._worker.join(timeout=WORKER_JOIN_TIMEOUT)
                cls._worker = None
            cls.running = False
            cls._stop_event.clear()
        cls.logger.debug("%s Stopped.", cls.__name__)

    @classmethod
    @client_disc_is_init
    @client_disc_is_running
    def _work(cls):

        if cls._stop_event is None:
            raise RuntimeError("missing stop event, wrong init")

        if cls.network is None:
            raise RuntimeError("Network not init")

        while not cls._stop_event.is_set():
            try:
                with cls._lock:
                    cls._live_clients = discover_live_clients(network=cls.network)
                    # cls._live_clients = run_arp_scan(network=cls.network)
                    cls.logger.debug("Discovered %s clients.", len(cls._live_clients))
            except Exception as _err:
                cls.logger.warning("Error discovering clients: %s", _err)
            cls._stop_event.wait(cls._client_discovery_interval)
        with cls._lock:
            cls.running = False

    @classmethod
    @client_disc_is_init
    @client_disc_is_running
    def get_live_clients(cls) -> List[ArpClient]:
        """
        Currently discovered live clients.
        Returns:
            List[ArpClient]: Deep copy of the active clients detected via ARP scanning.
        """
        with cls._lock:
            return list(cls._live_clients.values())

    @classmethod
    @client_disc_is_init
    @client_disc_is_running
    def get_live_client_by_ip(cls, ip: str) -> ArpClient | None:
        """
        Get a discovered client by its IP address.
        Args:
            ip (str): The IP address to look up.
        Returns:
            ArpClient | None: Matching client if found, otherwise None.
        """
        with cls._lock:
            return cls._live_clients.get(ip)

    @classmethod
    @client_disc_is_init
    @client_disc_is_running
    def get_available_ip(cls) -> IPv4Address | None:
        """
        Find the next available IP address in the configured range.
        Skips:
            - IPs outside the configured pool.
            - IPs currently leased by DHCP.
            - IPs discovered via ARP.
            - IPs responding to a fresh ARP probe.
        Returns:
            IPv4Address | None: An unused IP address or None if none are available.
        """
        if cls._ip_range_start is None or cls._ip_range_end is None:
            raise RuntimeError("Not initialized.")
        if cls.network is None:
            raise RuntimeError("Network not init")

        with cls._lock:

            _discovered_ips: Set[str] = set(cls._live_clients.keys())
            _leased_ips: Set[str] = DHCPStorage.get_all_leased_ips()

            for _ip in cls.network.hosts():

                if cls._ip_range_start <= _ip <= cls._ip_range_end:
                    continue
                if str(_ip) in _leased_ips or str(_ip) in _discovered_ips:
                    continue
                if send_arp_request(ip=_ip):
                    continue

                cls.logger.debug("Proposing IP: %s", _ip)
                return _ip

            cls.logger.warning("No available IPs found.")
            return None
