from copy import deepcopy
from functools import wraps
from ipaddress import IPv4Address, IPv4Network
from threading import Event, RLock, Thread

from scapy.layers.l2 import ARP, Ether
from scapy.sendrecv import srp

from app.config.config import config, dhcp_static_config
from app.services.dhcp.db_dhcp_leases import DHCPStorage
from app.services.dhcp.live_clients import LiveClients
from app.services.dhcp.models import ClientDiscoveryConfig, DHCPArpClient

DHCP = config.get("dhcp")

DHCP_CONFIG = DHCP.get("config")
INTERFACE = str(DHCP_CONFIG.get("interface"))
SERVER_IP = IPv4Address(DHCP_CONFIG.get("ip"))
SERVER_MAC = str(DHCP_CONFIG.get("mac"))
BROADCAST_IP = str(DHCP_CONFIG.get("broadcast_ip"))
BROADCAST_MAC = str(DHCP_CONFIG.get("broadcast_mac"))
IP_RANGE_START = IPv4Address(DHCP_CONFIG.get("ip_pool_start"))
IP_RANGE_END = IPv4Address(DHCP_CONFIG.get("ip_pool_end"))
CIDR = int(DHCP_CONFIG.get("cidr"))
MIN_CIDR = int(DHCP_CONFIG.get("min_cidr"))
MAX_CIDR = int(DHCP_CONFIG.get("max_cidr"))

CLIENT_DISCOVERY = DHCP.get("client_discovery")
DISCOVERY_TIMEOUTS = CLIENT_DISCOVERY.get("timeouts")
DISCOVERY_WORKERS = int(CLIENT_DISCOVERY.get("workers"))
DISCOVERY_INTERVAL = int(CLIENT_DISCOVERY.get("interval"))
ARP_DISCOVERY_TIMEOUT = float(DISCOVERY_TIMEOUTS.get("arp_discovery"))
INTERNAL_DELAY_TIMEOUT = float(DISCOVERY_TIMEOUTS.get("inter_delay"))
WORKER_JOIN_TIMEOUT = float(DISCOVERY_TIMEOUTS.get("worker_join"))

LIVE_CLIENTS = DHCP.get("live_clients")
MIN_CTR = int(LIVE_CLIENTS.get("min_ctr"))
MAX_CTR = int(LIVE_CLIENTS.get("max_ctr"))


def _get_network(
    ip: IPv4Address, cidr: int, min_cidr: int = MIN_CIDR, max_cidr: int = MAX_CIDR
) -> IPv4Network:
    if not (min_cidr <= cidr <= max_cidr):
        raise ValueError(f"CIDR must be 24 <= AND <= 31, got {cidr}")
    return IPv4Network((ip, cidr), strict=False)


def discover_live_clients(
    network: IPv4Network,
    broadcast_mac: str,
    timeout: float,
    inter_timeout: float,
    iface: str,
    verbose: bool = False,
    filter: str = "arp",
) -> set[DHCPArpClient] | set:
    """
    Perform an ARP scan over the network to discover live clients.
    In srp filter is hardwired to 'arp' as this is an ARP scan.

    Args:
        network (IPv4Network): subnet to scan.
        broadcast_mac (str): Typically ff:ff:ff:ff:ff:ff.
        timeout (float): Timeout for ARP request.
        inter_delay (float): Delay between ARP requests.
        iface (str): Network interface to use.
        verbose (bool): Disable scapy verbose output.
    """

    if not network or not isinstance(network, IPv4Network):
        raise RuntimeError("Missing network")

    _answered, _ = srp(
        [Ether(dst=broadcast_mac) / ARP(pdst=str(ip)) for ip in network.hosts()],
        timeout=timeout,
        inter=inter_timeout,
        filter=filter,
        verbose=verbose,
        iface=iface,
    )
    clients = set()
    for _, _resp in _answered:
        clients.add(DHCPArpClient(mac=_resp[ARP].hwsrc, ip=_resp[ARP].psrc))

    return clients


def discover_live_client(
    ip: IPv4Address,
    iface: str,
    timeout: float,
    broadcast_mac: str,
) -> DHCPArpClient | None:
    """
    Send an ARP request to a single IP address on a given interface.
    Args:
        ip (IPv4Address): The target IP address to query.
        iface (str, optional): Network interface to use, def to INTERFACE.
        timeout (float, optional): Timeout in seconds. Defaults to ARP_TIMEOUT.
    """
    _answered, _ = srp(
        Ether(dst=broadcast_mac) / ARP(pdst=str(ip)),
        timeout=timeout,
        iface=iface,
        filter="arp",
        verbose=False,
    )

    if _answered:
        if len(_answered) == 1:
            _, _recv = _answered[0]
            return DHCPArpClient(mac=_recv[ARP].hwsrc, ip=_recv[ARP].psrc)
        if len(_answered) > 1:
            raise RuntimeError("More than 1 device")

    return None


def client_disc_is_init(func):
    """Ensure the client discovery is initialized calling."""

    @wraps(func)
    def wrapper(cls, *args, **kwargs):
        if getattr(cls, "initialized", False) is False:
            raise RuntimeError("Not init")
        return func(cls, *args, **kwargs)

    return wrapper


def client_disc_is_running(func):
    """Decorator to check is running before calling."""

    @wraps(func)
    def wrapper(cls, *args, **kwargs):
        if getattr(cls, "running", False) is False:
            raise RuntimeError("Not running")
        return func(cls, *args, **kwargs)

    return wrapper


def client_disc_is_not_running(func):
    """Decorator to check is not running before calling."""

    @wraps(func)
    def wrapper(cls, *args, **kwargs):
        if getattr(cls, "running", False) is True:
            raise RuntimeError("Already running")
        return func(cls, *args, **kwargs)

    return wrapper


class ClientDiscoveryService:
    """
    Discovers live clients on a local IPv4 network using ARP/ICMP scans.
    Maintains a list of active devices and helps find available IPs for DHCP allocation.

    Purpose:
    - Periodically scans the subnet using ARP.
    - Tracks discovered clients in a thread-safe list.
    - Returns available IPs not currently leased or in use.
    - Supports clean start/stop lifecycle.

    Dependencies:
    - scapy for ARP scanning.
    - DHCPStorage for tracking leased IPs.
    - ArpClient to represent discovered devices.
    - config["dhcp"] for network setup.
    - logger passed during init for diagnostics.

    Usage:
    - Call init(logger) to configure.
    - Use start() to begin scanning.
    - Use stop() to halt discovery.
    - Call get_available_ip() to fetch a usable IP.
    """

    _lock = RLock()
    _stop_event = Event()
    _worker: Thread | None = None

    config: ClientDiscoveryConfig
    live_clients: LiveClients

    initialized = False
    running = False

    @classmethod
    def init(cls, logger):
        with cls._lock:
            cls.config = ClientDiscoveryConfig(
                interface=INTERFACE,
                broadcast_mac=BROADCAST_MAC,
                network=_get_network(SERVER_IP, CIDR),
                ip_range_start=IP_RANGE_START,
                ip_range_end=IP_RANGE_END,
                timeout=ARP_DISCOVERY_TIMEOUT,
                inter_timeout=INTERNAL_DELAY_TIMEOUT,
                min_counter=MIN_CTR,
                max_counter=MAX_CTR,
                discovery_interval=DISCOVERY_INTERVAL,
            )

            cls.live_clients = LiveClients(
                max_ctr=cls.config.max_counter, min_ctr=cls.config.min_counter
            )

            cls.logger = logger
            cls.initialized = True

    @classmethod
    @client_disc_is_init
    @client_disc_is_not_running
    def start(cls):
        """
        Start client discovery process in a background thread.
        """
        with cls._lock:
            cls.running = True
            cls._worker = Thread(target=cls._work, daemon=True)
            cls._worker.start()
            cls.logger.debug("%s started.", cls.__name__)

    @classmethod
    @client_disc_is_init
    @client_disc_is_running
    def stop(cls, timeout: float = WORKER_JOIN_TIMEOUT):
        """
        Stop the client discovery process and wait for the worker thread to finish.
        """
        with cls._lock:
            cls._stop_event.set()
            if cls._worker:
                cls._worker.join(timeout=timeout)
                cls._worker = None
            cls.running = False
            cls._stop_event.clear()
        cls.logger.debug("%s Stopped.", cls.__name__)

    @classmethod
    @client_disc_is_init
    @client_disc_is_running
    def _work(cls):
        while not cls._stop_event.is_set():
            try:
                scan_clients: set[DHCPArpClient] = discover_live_clients(
                    network=cls.config.network,
                    broadcast_mac=cls.config.broadcast_mac,
                    timeout=cls.config.timeout,
                    inter_timeout=cls.config.inter_timeout,
                    iface=cls.config.interface,
                )
                with cls._lock:

                    # We found a new device add it immedaitely
                    for arp_client_live in scan_clients:
                        cls.live_clients.increase(arp_client_live)

                    # If live client not in live clients, it went offline reduce it
                    for client in cls.live_clients.get_tracked_clients():
                        if client not in scan_clients:
                            cls.live_clients.decrease(client)

            except RuntimeError as err:
                cls.logger.warning("Error discovering clients: %s", err)

            cls._stop_event.wait(cls.config.discovery_interval)

        with cls._lock:
            cls.running = False

    @classmethod
    @client_disc_is_init
    @client_disc_is_running
    def get_live_clients(cls) -> set[DHCPArpClient]:
        """
        Currently discovered live clients.
        """
        with cls._lock:
            return deepcopy(cls.live_clients.get_tracked_clients())

    @classmethod
    @client_disc_is_init
    @client_disc_is_running
    def get_live_client_by_ip(cls, ip: str) -> DHCPArpClient | None:
        """
        Get a discovered client by its IP address.

        Args:
            ip (str): The IP address to look up.
        """
        with cls._lock:
            return cls.live_clients.get_client_by_ip(ip)

    @classmethod
    @client_disc_is_init
    @client_disc_is_running
    def get_available_ip(cls, mac: str = "") -> IPv4Address | None:
        """
        Find the next available IP address in the configured range.
        Also handles IP in DHCP static mapping.

        Skips:
            - IPs outside the configured pool.
            - IPs currently leased by DHCP.
            - IPs discovered via ARP.
            - IPs responding to a fresh ARP probe.
        """

        with cls._lock:

            static_ip = dhcp_static_config.get_config().get(mac.upper(), None)
            if static_ip:
                return IPv4Address(static_ip)

            _leased_ips: set[str] = DHCPStorage.get_all_leased_ips()
            candidates: list[IPv4Address] = [
                _ip
                for _ip in cls.config.network.hosts()
                if cls.config.ip_range_start <= _ip <= cls.config.ip_range_end
                and str(_ip) not in _leased_ips
                and not cls.live_clients.get_client_by_ip(str(_ip))
            ]

        # Expensive but ensures client is free (no ARP responses)
        for ip in candidates:
            _liveClient: DHCPArpClient | None = discover_live_client(
                ip=ip,
                iface=cls.config.interface,
                timeout=cls.config.timeout,
                broadcast_mac=cls.config.broadcast_mac,
            )
            if not _liveClient:
                cls.logger.debug("Proposing IP: %s", ip)
                return ip

        cls.logger.warning("No available IPs found.")
        return None
