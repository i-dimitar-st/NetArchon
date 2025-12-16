from concurrent.futures import Future, ThreadPoolExecutor, as_completed
from ipaddress import IPv4Address
from itertools import cycle
from pathlib import Path
from socket import AF_INET, SOCK_DGRAM, socket
from socket import timeout as socketTimeout
from threading import RLock
from time import monotonic

from dnslib import DNSRecord

from src.config.config import config
from src.services.dns.metrics import dns_per_server_metrics

PATHS = config.get("paths")
ROOT_PATH = Path(PATHS.get("root"))
DB_PATH = ROOT_PATH / PATHS.get("database")

DNS_CONFIG = config.get("dns").get("config")
DNS_HOST = DNS_CONFIG.get("host")
DNS_PORT = DNS_CONFIG.get("port")
DNS_UDP_PACKET_MAX_SIZE = int(DNS_CONFIG.get("udp_max_size", 1232))
EXTERNAL_DNS_SERVERS = list(DNS_CONFIG.get("external_dns_servers"))
WORKERS_CONFIG = config.get("dns").get("worker_config")
EXTERNAL_WORKERS = int(WORKERS_CONFIG.get("external", 400))

TIMEOUTS = config.get("dns").get("timeouts")
EXTERNAL_TIMEOUT = float(TIMEOUTS.get("external_socket", 15))
EXTERNAL_TIMEOUT_BUFFER = float(TIMEOUTS.get("external_socket_buffer", 2))


class ExternalResolverService:
    """Resolves DNS queries by concurrently querying multiple external DNS servers.

    Features:
    - Manages a thread pool to send parallel UDP DNS requests.
    - Returns the first successful DNS response.
    - Handles timeouts, retries, and errors per upstream server.
    - Supports start, stop, and restart of its thread pool executor.
    - Ensures thread-safe initialization and shutdown.

    Usage:
    1. Call init() to configure servers, timeouts, and start the thread pool.
    2. Call resolve_external() to perform parallel external DNS lookups.
    3. Call stop() or restart() to manage the executor lifecycle.
    """

    _lock = RLock()
    _port: int = DNS_PORT
    _max_msg_size: int = DNS_UDP_PACKET_MAX_SIZE
    _dns_servers: list[IPv4Address] | None = None
    _timeout: float = EXTERNAL_TIMEOUT
    _timeout_buffer: float = EXTERNAL_TIMEOUT_BUFFER
    _executor: ThreadPoolExecutor | None = None

    @classmethod
    def init(
        cls,
        logger,
        port: int = DNS_PORT,
        timeout: float = EXTERNAL_TIMEOUT,
        timeout_buffer: float = EXTERNAL_TIMEOUT_BUFFER,
        dns_servers: list[IPv4Address] = EXTERNAL_DNS_SERVERS,
        max_msg_size: int = DNS_UDP_PACKET_MAX_SIZE
    ) -> None:
        """Initialize the resolver with configuration and start thread pool.
        """
        with cls._lock:
            if cls._executor is not None:
                raise RuntimeError("Already initialized")
            cls._dns_servers = [IPv4Address(ip) for ip in dns_servers]
            cls._dns_cycle: cycle[IPv4Address] = cycle(cls._dns_servers)
            cls._port = int(port)
            cls._max_msg_size = int(max_msg_size)
            cls._timeout = float(timeout)
            cls._timeout_buffer = float(timeout_buffer)
            cls._timeout_w_buffer = cls._timeout + cls._timeout_buffer
            cls.logger = logger
            cls.logger.info("%s init.", cls.__name__)

    @classmethod
    def start(cls):
        """Start thread pool executor."""
        with cls._lock:
            if cls._executor:
                raise RuntimeError("Already started")
            if not cls._dns_servers:
                raise ValueError("Invalid dns servers list")
            cls._executor = ThreadPoolExecutor(
                max_workers=EXTERNAL_WORKERS,
                thread_name_prefix="external_dns_resolver_"
            )
            cls.logger.info("%s started.", cls.__name__)

    @classmethod
    def stop(cls):
        """Stop and clean up the thread pool executor."""
        with cls._lock:
            if cls._executor:
                cls._executor.shutdown(wait=True, cancel_futures=True)
                cls._executor = None
                cls.logger.info("%s stopped.", cls.__name__)

    @classmethod
    def restart(cls, max_workers: int = EXTERNAL_WORKERS):
        """Restart the thread pool executor with new worker count."""
        cls.stop()
        with cls._lock:
            cls._executor = ThreadPoolExecutor(max_workers=max_workers,thread_name_prefix="external_dns_resolver_")
            cls.logger.info(f"{cls.__name__} restarted.")


    @classmethod
    def resolve_external(cls, dns_request: DNSRecord) -> DNSRecord | None:
        """Sends DNS query to external servers in parallel
        Return first successful reply.
        """
        if not cls._executor:
            raise RuntimeError("Not started")
        if cls._dns_servers is None:
            raise RuntimeError("No DNS Servers")
        with cls._lock:
            _executor: ThreadPoolExecutor = cls._executor

        # next uses cycle to get round robing approach
        _futures = {}
        for _ in range(len(cls._dns_servers)):
            dns_server_ip: IPv4Address = next(cls._dns_cycle)
            _future: Future[tuple[DNSRecord,float]] = _executor.submit(
                cls._query_external_dns_server,
                dns_request,
                dns_server_ip,
                cls._timeout,
                cls._port,
                cls._max_msg_size
            )
            _futures[_future] = dns_server_ip

        try:
            for _future in as_completed(_futures, timeout=cls._timeout_w_buffer):
                try:
                    # _futures[_future] => dns_server_ip
                    reply,delay  = _future.result()
                    dns_per_server_metrics[_futures[_future]].add_sample(delay)
                    return reply
                except:
                    continue
        except TimeoutError:
            pass

        return None

    @classmethod
    def _query_external_dns_server(
            cls,
            request: DNSRecord,
            dns_server: IPv4Address,
            timeout:float,
            port:int,
            max_msg_size:int
        ) -> tuple[DNSRecord,float]:
        """Send a DNS query to a single upstream DNS server and return the response.

        Args:
            request (DNSRecord): The DNS query to send.
            dns_server (IPv4Address): The IPv4 address of the upstream DNS server.

        Returns:
            DNSRecord: The DNS response received from the server.

        Raises:
            ValueError: If `request` or `dns_server` is missing.
            TimeoutError: If the DNS server does not respond within the configured timeout.
            RuntimeError: For any other socket or network errors.

        """
        if not request or not dns_server:
            raise ValueError("Missing data or upstream DNS server.")

        # Create a UDP IPv4 socket
        with socket(AF_INET, SOCK_DGRAM) as _dns_socket:
            _start = monotonic()
            try:
                _dns_socket.settimeout(timeout)
                _dns_socket.sendto(request.pack(),(str(dns_server), int(port)))
                return DNSRecord.parse(packet=_dns_socket.recvfrom(max_msg_size)[0]),(monotonic()-_start)*1000

            except socketTimeout as err:
                raise TimeoutError(f"{dns_server} timedout.") from err

            except Exception as err:
                raise RuntimeError(f"Error {dns_server}: {str(err)}.") from err
