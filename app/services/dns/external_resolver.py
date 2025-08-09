from concurrent.futures import Future, ThreadPoolExecutor, as_completed
from ipaddress import IPv4Address
from pathlib import Path
from random import sample
from socket import (
    AF_INET,
    SOCK_DGRAM,
    socket,
    timeout as socketTimeout,
)
from threading import RLock
from typing import Any

from dnslib import DNSRecord

from app.config.config import config

PATHS = config.get("paths")
ROOT_PATH = Path(PATHS.get("root"))
DB_PATH = ROOT_PATH / PATHS.get("database")

DNS_CONFIG = config.get("dns").get("config")
DNS_HOST = DNS_CONFIG.get("host")
DNS_PORT = DNS_CONFIG.get("port")
DNS_UDP_PACKET_MAX_SIZE = int(DNS_CONFIG.get("udp_max_size", 1232))
EXTERNAL_DNS_SERVERS = list(DNS_CONFIG.get("external_dns_servers"))
WORKERS_CONFIG = config.get("dns").get("worker_config")
EXTERNAL_WORKERS = int(WORKERS_CONFIG.get("external", 300))

TIMEOUTS = config.get("dns").get("timeouts")
EXTERNAL_TIMEOUT = float(TIMEOUTS.get("external_socket", 15))
EXTERNAL_TIMEOUT_BUFFER = float(TIMEOUTS.get("external_socket_buffer", 2))


class ExternalResolverService:
    """
    Resolves DNS queries by concurrently querying multiple external DNS servers.

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
    _timeout: float = EXTERNAL_TIMEOUT
    _timeout_buffer: float = EXTERNAL_TIMEOUT_BUFFER
    _max_workers: int = EXTERNAL_WORKERS
    _executor: ThreadPoolExecutor | None = None
    _dns_servers: list[IPv4Address] | None = None

    @classmethod
    def init(
        cls,
        logger,
        port: int = DNS_PORT,
        timeout: float = EXTERNAL_TIMEOUT,
        timeout_buffer: float = EXTERNAL_TIMEOUT_BUFFER,
        dns_servers: list[IPv4Address] = EXTERNAL_DNS_SERVERS,
        max_msg_size: int = DNS_UDP_PACKET_MAX_SIZE,
        max_workers: int = EXTERNAL_WORKERS,
    ):
        """
        Initialize the resolver with configuration and start thread pool.
        """

        with cls._lock:
            if cls._executor is not None:
                raise RuntimeError("Already initialized")
            cls._dns_servers = [IPv4Address(ip) for ip in dns_servers]
            cls._port = port
            cls._max_msg_size = max_msg_size
            cls._timeout = timeout
            cls._timeout_buffer = timeout_buffer
            cls._max_workers = max_workers
            cls.logger = logger
            cls.logger.info("%s init.", cls.__name__)

    @classmethod
    def start(cls):
        """Start thread pool executor."""
        with cls._lock:
            if cls._executor:
                raise RuntimeError("Already started")
            cls._executor = ThreadPoolExecutor(max_workers=cls._max_workers)
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
            cls._executor = ThreadPoolExecutor(max_workers=max_workers)
            cls.logger.info("%s restarted.", cls.__name__)

    @classmethod
    def resolve_external(cls, dns_request: DNSRecord) -> DNSRecord | None:
        """
        Sends DNS query to external servers in parallel
        Return first successful reply.
        """
        with cls._lock:
            if not cls._executor:
                raise RuntimeError("Not started")
            if cls._dns_servers is None:
                raise RuntimeError("No DNS Servers")
            _executor = cls._executor
            _dns_servers = sample(cls._dns_servers, k=len(cls._dns_servers))
            _timeout = cls._timeout + cls._timeout_buffer

        # Randomize to distribute requests across DNS servers evenly per thread
        futures = {}
        for dns_server_ip in _dns_servers:
            future: Future[DNSRecord] = _executor.submit(
                cls._query_external_dns_server, dns_request, dns_server_ip
            )
            futures[future] = dns_server_ip

        try:
            # As completed return first completed so we want that and cancel rest
            for _completed in as_completed(futures, timeout=_timeout):
                _dns_server_ip: str = futures[_completed]
                try:
                    # Get first resut but cancel other futures to avoid zombies.
                    reply: Any = _completed.result()
                    for _still_pending in futures:
                        if _still_pending != _completed:
                            _still_pending.cancel()
                    return reply

                except Exception as err:
                    cls.logger.error("Error with ip %s : %s.", _dns_server_ip, err)

        except Exception as err:
            cls.logger.error("Error with DNS futures :%s.", err)

        # All failed
        return None

    @classmethod
    def _query_external_dns_server(
        cls, request: DNSRecord, dns_server: IPv4Address
    ) -> DNSRecord:
        """Send DNS query to a single upstream DNS server and return the response."""

        if not request or not dns_server:
            raise ValueError("Missing data or upstream DNS server.")

        # Create a UDP IPv4 socket
        with socket(AF_INET, SOCK_DGRAM) as _dns_socket:
            try:
                _dns_socket.settimeout(cls._timeout)
                _dns_socket.sendto(request.pack(), (str(dns_server), int(cls._port)))

                _reply_raw, _addr = _dns_socket.recvfrom(cls._max_msg_size)
                _reply: DNSRecord = DNSRecord.parse(_reply_raw)

                if _reply.header.id != request.header.id:
                    raise ValueError(f"DNS ID mismatch {dns_server}.")

                return _reply

            except socketTimeout as _err:
                raise TimeoutError(f"{dns_server} timedout.") from _err

            except Exception as _err:
                raise RuntimeError(f"Error {dns_server}: {str(_err)}.") from _err
