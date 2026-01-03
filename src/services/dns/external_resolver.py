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

import concurrent.futures
import os
import pathlib
import socket
import threading

from src.config.config import config
from src.services.dns.models import DNSReqMsg

PATHS = config.get("paths")
ROOT_PATH = pathlib.Path(PATHS.get("root"))
DB_PATH = ROOT_PATH / PATHS.get("database")

DNS_CONFIG = config.get("dns").get("config")
DNS_HOST = DNS_CONFIG.get("host")
DNS_PORT = DNS_CONFIG.get("port")
DNS_UDP_PACKET_MAX_SIZE = int(DNS_CONFIG.get("udp_max_size", 1232))
EXTERNAL_DNS_SERVERS = [
    str(ip)
    for ip in list(DNS_CONFIG.get("external_dns_servers"))
]
WORKERS_CONFIG = config.get("dns").get("worker_config")
EXTERNAL_WORKERS = int(((os.cpu_count() or 4) + 4) * 4)

TIMEOUTS = config.get("dns").get("timeouts")
TIMEOUT = float(TIMEOUTS.get("external_socket", 5.0))


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

    _lock = threading.RLock()
    _port: int
    _max_msg_size: int
    _workers: int
    _dns_servers: list[str]

    _timeout_socket: float
    _timeout: float
    _executor: concurrent.futures.ThreadPoolExecutor | None = None

    @classmethod
    def init(
            cls,
            logger,
            port: int = DNS_PORT,
            timeout: float = TIMEOUT,
            dns_servers: list[str] = EXTERNAL_DNS_SERVERS,
            workers: int = EXTERNAL_WORKERS,
            max_msg_size: int = DNS_UDP_PACKET_MAX_SIZE
        ) -> None:
        """Initialize the resolver with configuration and start thread pool."""
        with cls._lock:
            if cls._executor is not None:
                raise RuntimeError("Already initialized")

            __class__._validate_input(
                port=port,
                timeout=timeout,
                dns_servers=dns_servers,
                workers=workers,
                max_msg_size=max_msg_size,
            )

            cls._port = port
            cls._max_msg_size = max_msg_size
            cls._dns_servers = dns_servers
            cls._workers = workers
            cls._timeout = timeout

            cls.logger = logger
            cls.logger.info(f"{cls.__name__} init.")

    @staticmethod
    def _validate_input(
            port: int,
            timeout: float,
            dns_servers: list[str],
            workers: int,
            max_msg_size: int
        ) -> None:

            if not isinstance(port, int) or not (0 < port < 65536):
                raise ValueError(f"Invalid port: {port}")

            if not isinstance(timeout, (float, int)) or not (0 < timeout < 30.0):
                raise ValueError(f"Invalid timeout_socket: {timeout}")

            if not isinstance(workers, int) or not (0 < workers <= 1000):
                raise ValueError(f"Invalid workers count: {workers}")

            if not isinstance(dns_servers, list) or not all(isinstance(s, str) for s in dns_servers):
                raise ValueError(f"Invalid dns_servers list: {dns_servers}")

            if not isinstance(max_msg_size, int) or not (0 < max_msg_size <= 1500):
                raise ValueError(f"Invalid max_msg_size: {max_msg_size}")


    @classmethod
    def start(cls) -> None:
        """Start thread pool executor & initialize UDP sockets for all DNS servers."""
        with cls._lock:
            if cls._executor:
                raise RuntimeError("Already started")
            if not cls._dns_servers:
                raise ValueError("Invalid dns servers list")
            cls._executor = concurrent.futures.ThreadPoolExecutor(max_workers=cls._workers)
            cls.logger.info(f"{cls.__name__} started.")

    @classmethod
    def stop(cls) -> None:
        """Stop the thread pool executor and clean up all resources."""
        with cls._lock:
            if cls._executor:
                cls._executor.shutdown(wait=True, cancel_futures=True)
                cls._executor = None
                cls.logger.info(f"{cls.__name__} stopped.")

    @classmethod
    def restart(cls) -> None:
        """Restart the thread pool executor with new worker count."""
        with cls._lock:
            cls.stop()
            cls.start()
            cls.logger.info(f"{cls.__name__} restarted.")

    @classmethod
    def _query_external_dns_server(
            cls,
            request: bytes,
            dns_server: str,
            port: int,
            timeout: float,
            max_msg_size: int
        ) -> bytes:
        """Send a DNS query to a single upstream DNS server.

        Args:
            request (bytes): Raw DNS query bytes.
            dns_server (str): Upstream DNS server IP.
            port (int): Destination port.
            timeout (float): Socket timeout in seconds.
            max_msg_size (int): Maximum response size in bytes.

        Returns:
            bytes: Raw DNS response.

        """
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as _sock:
            _sock.settimeout(timeout)
            _sock.sendto(request, (dns_server, port))
            data, _addr = _sock.recvfrom(max_msg_size)
            if dns_server != _addr[0]:
                raise ValueError(f"Address: {_addr[0]} answered instead of DNS Server: {dns_server}.")
            return data

    @classmethod
    def _helper_create_and_submit_tasks(cls,dns_request: DNSReqMsg) -> dict[concurrent.futures.Future[bytes], str]:
        """Submit DNS query tasks to all configured external DNS servers.

        Args:
            dns_request (DNSReqMsg): Incoming DNS request message.

        Returns:
            dict[concurrent.futures.Future[bytes], str]: Mapping of submitted
            futures to the DNS server address they were sent to.

        """
        return {
            cls._executor.submit( # type: ignore
                cls._query_external_dns_server,
                dns_request.raw,
                server,
                cls._port,
                cls._timeout,
                cls._max_msg_size
            ): server
            for server in cls._dns_servers
        }

    @staticmethod
    def _resolve_all_tasks_get_first(
            futures: dict[concurrent.futures.Future[bytes], str],
            timeout:float
    ) -> tuple[bytes | None, str | None]:
        """Wait for the first completed DNS query task and return its result.

        Cancels all remaining pending tasks once the first successful result
        is obtained or the timeout is reached.

        Args:
            futures (dict[Future[bytes], str]): Mapping of futures to DNS server
                addresses.
            timeout (float): Maximum time to wait for a task to complete.

        Returns:
            tuple[bytes | None, str | None]: The DNS response bytes and the server
            address that returned it, or (None, None) if none succeed.

        """
        try:
            for future in concurrent.futures.as_completed(futures, timeout=timeout+1.0):
                try:
                    return future.result(), futures[future]
                except Exception:
                    continue
        except concurrent.futures.TimeoutError:
            pass
        finally:
            for future in futures:
                future.cancel()
        return None, None

    @classmethod
    def resolve(cls, dns_request: DNSReqMsg) -> tuple[bytes | None, str | None]:
        """Resolve a DNS request using external DNS servers.

        Submits the DNS query to all configured servers and returns the first
        successful response.

        Args:
            dns_request (DNSReqMsg): Incoming DNS request message.

        Returns:
            tuple[bytes | None, str | None]: The DNS response bytes and the server
            address that returned it, or (None, None) if resolution fails.

        """
        return cls._resolve_all_tasks_get_first(
            futures=cls._helper_create_and_submit_tasks(dns_request),
            timeout=cls._timeout
        )
