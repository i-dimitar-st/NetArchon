# -*- coding: utf-8 -*-
"""Module to perform concurrent DNS queries using multiple external DNS servers.

Features:
- Parallel DNS queries with ThreadPoolExecutor.
- Returns the first successful DNS response.
- Handles timeouts, retries, and errors per upstream server.
- Tracks per-server and global DNS metrics.

Usage:
1. Initialize with ExternalResolverService.init(logger, ...).
2. Start the resolver with ExternalResolverService.start().
3. Resolve DNS queries using ExternalResolverService.resolve_external(dns_request).
4. Stop the resolver with ExternalResolverService.stop() or restart with restart().
"""

from concurrent.futures import Future, ThreadPoolExecutor, as_completed
from ipaddress import IPv4Address
from itertools import cycle
from os import cpu_count
from pathlib import Path
from socket import AF_INET, SOCK_DGRAM, socket
from threading import RLock
from time import monotonic

from dnslib import DNSRecord

from src.config.config import config
from src.services.dns.metrics import dns_metrics_external, dns_per_server_metrics

PATHS = config.get("paths")
ROOT_PATH = Path(PATHS.get("root"))
DB_PATH = ROOT_PATH / PATHS.get("database")

DNS_CONFIG = config.get("dns").get("config")
DNS_HOST = DNS_CONFIG.get("host")
DNS_PORT = DNS_CONFIG.get("port")
DNS_UDP_PACKET_MAX_SIZE = int(DNS_CONFIG.get("udp_max_size", 1232))
EXTERNAL_DNS_SERVERS = [
    IPv4Address(ip)
    for ip in list(DNS_CONFIG.get("external_dns_servers"))
]
WORKERS_CONFIG = config.get("dns").get("worker_config")
EXTERNAL_WORKERS = int(cpu_count() or 4)*2

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
    _port: int
    _max_msg_size: int
    _workers: int
    _dns_servers: list[IPv4Address]
    # _dns_cycle: cycle
    _timeout: float
    _timeout_buffer: float
    _timeout_w_buffer: float
    _server_sockets: dict[IPv4Address, socket]
    _executor: ThreadPoolExecutor | None = None

    @classmethod
    def init(
            cls,
            logger,
            port: int = DNS_PORT,
            timeout: float = EXTERNAL_TIMEOUT,
            timeout_buffer: float = EXTERNAL_TIMEOUT_BUFFER,
            dns_servers: list[IPv4Address] = EXTERNAL_DNS_SERVERS,
            workers: int = EXTERNAL_WORKERS,
            max_msg_size: int = DNS_UDP_PACKET_MAX_SIZE
        ) -> None:
        """Initialize the resolver with configuration and start thread pool."""
        with cls._lock:
            if cls._executor is not None:
                raise RuntimeError("Already initialized")
            cls._dns_servers = dns_servers
            cls._dns_cycle: cycle[IPv4Address] = cycle(cls._dns_servers)
            cls._port = port
            cls._max_msg_size = max_msg_size
            cls._workers = workers
            cls._timeout = timeout
            cls._timeout_buffer = timeout_buffer
            cls._timeout_w_buffer = cls._timeout + cls._timeout_buffer
            cls.logger = logger
            cls.logger.info(f"{cls.__name__} init.")

    @classmethod
    def start(cls):
        """Start thread pool executor & initialize UDP sockets for all DNS servers.

        This method sets up:
        1. A ThreadPoolExecutor with the configured number of workers for handling
        concurrent DNS queries.
        2. A UDP socket per DNS server, stored in `_server_sockets`, with the
        configured timeout. These sockets are reused for all queries until `stop()`.

        The method is safe to call programmatically to restart the resolver after
        a `stop()`. Raises:
            - RuntimeError: if the executor is already started.
            - ValueError: if `_dns_servers` is empty or invalid.
        """
        with cls._lock:
            if cls._executor:
                raise RuntimeError("Already started")
            if not cls._dns_servers:
                raise ValueError("Invalid dns servers list")
            cls._executor = ThreadPoolExecutor(
                max_workers=cls._workers,
                thread_name_prefix="external_dns_resolver_"
            )
            cls._server_sockets: dict[IPv4Address, socket] = {
                server: (
                    lambda sock: (sock.settimeout(cls._timeout), sock)[1]
                    )(socket(AF_INET, SOCK_DGRAM))
                for server in cls._dns_servers
            }
            cls.logger.info(f"{cls.__name__} started.")

    @classmethod
    def stop(cls):
        """Stop the thread pool executor and clean up all resources.

        This method performs the following:
        1. Shuts down the ThreadPoolExecutor, optionally canceling pending futures.
        2. Closes all UDP sockets stored in `_server_sockets`.
        3. Clears internal executor and socket references for safe restart.

        After calling this method, the resolver can be restarted by calling `start()`.

        Thread-safe: acquires `_lock` to prevent concurrent start/stop conflicts.
        """
        with cls._lock:
            if cls._executor:
                cls._executor.shutdown(wait=True, cancel_futures=True)
                cls._executor = None
                cls.logger.info(f"{cls.__name__} stopped.")
            for _socket in cls._server_sockets.values():
                _socket.close()
            cls._server_sockets = {}

    @classmethod
    def restart(cls):
        """Restart the thread pool executor with new worker count."""
        with cls._lock:
            cls.stop()
            cls.start()
            cls.logger.info(f"{cls.__name__} restarted.")

    @staticmethod
    def _submit_dns_requests(
        executor: ThreadPoolExecutor,
        servers: list[IPv4Address],
        server_sockets: dict[IPv4Address, socket],
        dns_request,
        query_fn,
        dns_cycle,
        timeout: float,
        port: int,
        max_msg_size: int
    ) -> dict[Future, IPv4Address]:
        """Submit DNS queries concurrently to multiple external servers.

        Each DNS query is submitted as a future to the provided ThreadPoolExecutor,
        using the next server from `dns_cycle` in a round-robin fashion. Each future
        is associated with its corresponding server IP.

        Args:
            executor: ThreadPoolExecutor used to run DNS query tasks.
            servers: List of DNS server IPs.
            server_sockets: Mapping of server IPs to pre-created UDP sockets.
            dns_request: The DNSRecord query to send.
            query_fn: Function that sends the DNS request and returns the response.
            dns_cycle: Cycle iterator over server IPs for round-robin selection.
            timeout: Timeout for each DNS request in seconds.
            port: UDP port to send the DNS request to.
            max_msg_size: Maximum size of UDP response packet.

        Returns:
            dict[Future, IPv4Address]: Mapping of submitted Future to the server IP
            it was sent to.

        """
        server_ip: IPv4Address = next(dns_cycle)
        return {
        executor.submit(
            query_fn,
            dns_request,
            server_ip,
            server_sockets[server_ip],
            timeout,
            port,
            max_msg_size
        ): server_ip
        for _ in range(len(servers))
    }

    @classmethod
    def resolve_external(cls, dns_request: DNSRecord) -> DNSRecord | None:
        """Send a DNS query concurrently to external servers.
        Return the first successful response.

        This method:
        1. Submits the DNS query to all configured external servers in parallel using
        the thread pool executor.
        2. Waits for futures to complete with a timeout of `_timeout + _timeout_buffer`.
        3. Returns the first successful DNSRecord response.
        4. Updates per-server and global DNS metrics on success.
        5. Cancels remaining/pending futures (success, failure, or timeout).

        Args:
            dns_request (DNSRecord): The DNS query to send to external servers.

        Returns:
            DNSRecord | None: The first successful response received, or None if
            all requests failed or timed out.

        Raises:
            RuntimeError: If resolver has not been started.

        """
        if not cls._executor:
            raise RuntimeError("Not started")
        if cls._dns_servers is None:
            raise RuntimeError("No DNS Servers")
        if not cls._server_sockets:
            raise RuntimeError("No DNS Socket")

        _start = monotonic()
        _futures = cls._submit_dns_requests(
            cls._executor,
            cls._dns_servers,
            cls._server_sockets,
            dns_request,
            cls._query_external_dns_server,
            cls._dns_cycle,
            cls._timeout,
            cls._port,
            cls._max_msg_size
        )
        try:
            for future in as_completed(fs=_futures, timeout=cls._timeout_w_buffer):
                try:
                    result:DNSRecord = future.result()
                except: # noqa: S722 E722 S112
                    continue
                 # futures[_future] => dns_server_ip as its dict
                duration = (monotonic() - _start) * 1000
                dns_per_server_metrics[_futures[future]].add_sample(duration)
                dns_metrics_external.add_sample(duration)
                return result

        except TimeoutError:
            return None

        finally:
            for f in _futures:
                if not f.done():
                    f.cancel()

    @staticmethod
    def _query_external_dns_server(
            request: DNSRecord,
            dns_server: IPv4Address,
            socket: socket,
            timeout:float,
            port:int,
            max_msg_size:int
        ) -> DNSRecord:
        """Send a DNS query to a single upstream DNS server and return the response.

        Args:
            request (DNSRecord): The DNS query to send.
            dns_server (IPv4Address): The IPv4 address of the upstream DNS server.
            socket (socket): Socket that will be used to fire request.
            timeout (float): Not used current as timeout as is at init.
            port (int): port used to fire request.
            max_msg_size(int): max Mesasge size in bytes expected.

        Returns:
            DNSRecord: The DNS response received from the server.

        """
        socket.sendto(request.pack(), (str(dns_server), port))
        return DNSRecord.parse(packet=socket.recvfrom(max_msg_size)[0])
