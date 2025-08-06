from copy import deepcopy
from functools import wraps
from ipaddress import IPv4Address, IPv4Network
from threading import Event, RLock, Thread

from scapy.layers.l2 import ARP, Ether
from scapy.sendrecv import srp

from app.config.config import config, dhcp_static_config
from app.services.dhcp.db_dhcp_leases import DHCPStorage
from app.services.dhcp.live_clients import LiveClients
from app.services.dhcp.models import DHCPArpClient

DHCP_CONFIG = config.get("dhcp")

INTERFACE = str(DHCP_CONFIG.get("interface"))
SERVER_IP = str(DHCP_CONFIG.get("ip"))
SERVER_MAC = str(DHCP_CONFIG.get("mac"))
BROADCAST_IP = str(DHCP_CONFIG.get("broadcast_ip"))
BROADCAST_MAC = str(DHCP_CONFIG.get("broadcast_mac"))
IP_RANGE_START = str(DHCP_CONFIG.get("ip_pool_start"))
IP_RANGE_END = str(DHCP_CONFIG.get("ip_pool_end"))
CIDR = int(DHCP_CONFIG.get("cidr"))

CLIENT_DISCOVERY = DHCP_CONFIG.get("client_discovery")
DISCOVERY_TIMEOUTS = CLIENT_DISCOVERY.get("timeouts")
DISCOVERY_WORKERS = int(CLIENT_DISCOVERY.get("workers"))
DISCOVERY_INTERVAL = int(CLIENT_DISCOVERY.get("interval"))

ARP_TIMEOUT = float(DISCOVERY_TIMEOUTS.get("arp_discovery"))
ARP_INTER_DELAY = float(DISCOVERY_TIMEOUTS.get("inter_delay"))
WORKER_JOIN_TIMEOUT = float(DISCOVERY_TIMEOUTS.get("worker_join"))

MIN_CTR = int(CLIENT_DISCOVERY.get("min_ctr"))
MAX_CTR = int(CLIENT_DISCOVERY.get("max_ctr"))


def _get_default_config() -> dict:
    return {
        "server_ip": SERVER_IP,
        "cidr": CIDR,
        "ip_range_start": IP_RANGE_START,
        "ip_range_end": IP_RANGE_END,
        "interface": INTERFACE,
        "server_mac": SERVER_MAC,
        "broadcast_mac": BROADCAST_MAC,
        "arp_timeout": ARP_TIMEOUT,
        "discovery_interval": DISCOVERY_INTERVAL,
        "min_ctr": MIN_CTR,
        "max_ctr": MAX_CTR,
        "inter_delay": ARP_INTER_DELAY,
    }.copy()


def discover_live_clients(
    network: IPv4Network,
    cidr: int = CIDR,
    broadcast_mac: str = BROADCAST_MAC,
    timeout: float = ARP_TIMEOUT,
    inter_delay: float = ARP_INTER_DELAY,
    iface: str = INTERFACE,
    verbose: bool = False,
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

    if network.prefixlen < cidr:
        raise RuntimeError("Subnet too wide reduce subnet")

    _answered, _ = srp(
        [Ether(dst=broadcast_mac) / ARP(pdst=str(ip)) for ip in network.hosts()],
        timeout=timeout,
        inter=inter_delay,
        filter="arp",
        verbose=verbose,
        iface=iface,
    )
    clients = set()
    for _, _resp in _answered:
        clients.add(DHCPArpClient(mac=_resp[ARP].hwsrc, ip=_resp[ARP].psrc))

    return clients


def discover_live_client(
    ip: IPv4Address,
    iface: str = INTERFACE,
    timeout: float = ARP_TIMEOUT,
    broadcast_mac: str = BROADCAST_MAC,
) -> DHCPArpClient | None:
    """
    Send an ARP request to a single IP address on a given interface.
    Args:
        ip (IPv4Address): The target IP address to query.
        iface (str, optional): Network interface to send the request on. Defaults to INTERFACE.
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
    _config = {}

    initialized = False
    running = False
    live_clients: LiveClients

    network: IPv4Network | None = None
    ip_range_start: IPv4Address | None = None
    ip_range_end: IPv4Address | None = None

    @classmethod
    def init(cls, logger, **kwargs):
        with cls._lock:

            cls._config = _get_default_config()
            cls._config.update(kwargs)

            cls.network = IPv4Network(
                f"{cls._config.get('server_ip')}/{cls._config.get('cidr')}",
                strict=False,
            )
            cls.ip_range_start = IPv4Address(cls._config.get("ip_range_start"))
            cls.ip_range_end = IPv4Address(cls._config.get("ip_range_end"))

            cls.live_clients = LiveClients(
                max_ctr=cls._config["max_ctr"], min_ctr=cls._config["min_ctr"]
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
    def stop(cls):
        """
        Stop the client discovery process and wait for the worker thread to finish.
        """
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
            raise AttributeError("missing stop event, wrong init")

        if cls.network is None:
            raise AttributeError("Network not init")

        while not cls._stop_event.is_set():
            try:

                _scan_clients: set[DHCPArpClient] = discover_live_clients(
                    network=cls.network
                )
                with cls._lock:

                    # We found a new device add it immedaitely
                    for _arp_client_live in _scan_clients:
                        cls.live_clients.increase(_arp_client_live)

                    # If live clients not in live clients, it went offline reduce it
                    for client in cls.live_clients.get_tracked_clients():
                        if client not in _scan_clients:
                            cls.live_clients.decrease(client)

            except RuntimeError as err:
                cls.logger.warning("Error discovering clients: %s", err)

            cls._stop_event.wait(cls._config["discovery_interval"])

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

        if cls.ip_range_start is None or cls.ip_range_end is None:
            raise RuntimeError("Not initialized.")
        if cls.network is None:
            raise RuntimeError("Network not init")

        with cls._lock:

            static_ip = dhcp_static_config.get_config().get(mac.upper(), None)
            if static_ip:
                return IPv4Address(static_ip)

            _leased_ips: set[str] = DHCPStorage.get_all_leased_ips()
            _candidates: list[IPv4Address] = [
                _ip
                for _ip in cls.network.hosts()
                if cls.ip_range_start <= _ip <= cls.ip_range_end
                and str(_ip) not in _leased_ips
                and not cls.live_clients.get_client_by_ip(str(_ip))
            ]

        # This is a bit expensive but ensures the client is free ie no ARP response comes
        for ip in _candidates:
            if not discover_live_client(ip=ip):
                cls.logger.debug("Proposing IP: %s", ip)
                return ip

        cls.logger.warning("No available IPs found.")
        return None
