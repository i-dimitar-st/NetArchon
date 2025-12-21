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

from asyncio import (
    FIRST_COMPLETED,
    AbstractEventLoop,
    Task,
    create_task,
    new_event_loop,
    set_event_loop,
    wait,
    wait_for,
)
from collections import deque
from ipaddress import IPv4Address
from pathlib import Path
from socket import AF_INET, SOCK_DGRAM, socket
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

TIMEOUTS = config.get("dns").get("timeouts")
EXTERNAL_TIMEOUT = float(TIMEOUTS.get("external_socket", 15))
EXTERNAL_TIMEOUT_BUFFER = float(TIMEOUTS.get("external_socket_buffer", 2))


class AsyncExternalResolverService:
    """Async Resolver."""

    dns_servers: deque[IPv4Address]
    port: int
    max_msg_size: int
    timeout: float
    timeout_w_buffer: float
    logger = None

    @classmethod
    def init(
        cls,
        logger,
        port: int = DNS_PORT,
        timeout: float = EXTERNAL_TIMEOUT,
        timeout_buffer: float = EXTERNAL_TIMEOUT_BUFFER,
        dns_servers: list[IPv4Address] = EXTERNAL_DNS_SERVERS,
        max_msg_size: int = DNS_UDP_PACKET_MAX_SIZE
    ):
        """Initialize Service.

        Args:
            logger(logger): logger to use
            port(int): port to use
            timeout(float): base timeout
            timeout_buffer(float): timeout buffer
            dns_servers(deque): dns servers to use
            max_msg_size(int): max socket byte size

        """
        cls.logger = logger
        cls.dns_servers = deque(dns_servers)
        cls.port = port
        cls.timeout = timeout
        cls.timeout_w_buffer = timeout + timeout_buffer
        cls.max_msg_size = max_msg_size
        cls.logger.info(f"{cls.__name__} initialized.")

    @staticmethod
    async def _query_external_dns_server(
        request: DNSRecord,
        dns_server: IPv4Address,
        timeout: float,
        port: int,
        max_msg_size: int,
        loop: AbstractEventLoop
    ) -> tuple[DNSRecord, IPv4Address]:
        """Send a DNS query over UDP using a fresh non-blocking socket."""
        sock = socket(AF_INET, SOCK_DGRAM)
        sock.setblocking(False)
        try:
            await loop.sock_sendto(
                sock=sock,
                data=request.pack(),
                address=(str(dns_server), port)
            )
            return DNSRecord.parse(
                await wait_for(
                    fut=loop.sock_recv(sock, max_msg_size),
                    timeout=timeout
                )),dns_server
        finally:
            sock.close()

    @staticmethod
    def _helper_create_tasks(
        dns_request:DNSRecord,
        dns_servers:deque,
        timeout:float,
        port:int,
        max_msg_size:int,
        loop: AbstractEventLoop
    ) -> list[Task[tuple[DNSRecord, IPv4Address]]]:
        return [
                create_task(
                    AsyncExternalResolverService._query_external_dns_server(
                        request=dns_request,
                        dns_server=dns_server,
                        timeout=timeout,
                        port=port,
                        max_msg_size=max_msg_size,
                        loop=loop
                    )
                )
                for dns_server in dns_servers
        ]

    @staticmethod
    def _helper_cancel_pending_tasks(tasks:list[Task]) -> None:
        for task in tasks:
            if not task.done():
                task.cancel()

    @staticmethod
    def _helper_extract_res_from_done(done:set[Task]) -> tuple[DNSRecord, IPv4Address] | None: # noqa: E501
        for task in done:
            try:
                return task.result()
            except: # noqa: E722 S112
                continue
        return None

    @staticmethod
    async def resolve_async(
        dns_request:DNSRecord,
        dns_servers:deque,
        timeout:float,
        port:int,
        max_msg_size:int,
        timeout_w_buffer:float,
        loop: AbstractEventLoop
    ) -> tuple[DNSRecord, IPv4Address] | None:

        tasks = AsyncExternalResolverService._helper_create_tasks(
            dns_request=dns_request,
            dns_servers=dns_servers,
            timeout=timeout,
            port=port,
            max_msg_size=max_msg_size,
            loop=loop
        )

        try:
            done, pending = await wait(
                fs=tasks,
                timeout=timeout_w_buffer,
                return_when=FIRST_COMPLETED
            )

            return AsyncExternalResolverService._helper_extract_res_from_done(done)

        finally:
            AsyncExternalResolverService._helper_cancel_pending_tasks(tasks)

    @classmethod
    async def resolve_external_async(cls,dns_request:DNSRecord, loop: AbstractEventLoop) -> DNSRecord | None:
        cls.dns_servers.rotate(-1)
        start = monotonic()
        result = await cls.resolve_async(
            dns_request=dns_request,
            dns_servers=cls.dns_servers,
            timeout=cls.timeout,
            port=cls.port,
            max_msg_size=cls.max_msg_size,
            timeout_w_buffer=cls.timeout_w_buffer,
            loop=loop
        )
        delay: float = (monotonic() - start)*1000
        dns_metrics_external.add_sample(delay)
        if not result:
            return None
        dns_per_server_metrics[result[1]].add_sample(delay)
        return result[0]

    @classmethod
    def resolve_external(cls, dns_request: DNSRecord) -> DNSRecord | None:
        """Resolve DNS using a fresh event loop for each request."""
        cls.dns_servers.rotate(-1)
        start = monotonic()

        loop: AbstractEventLoop = new_event_loop()
        set_event_loop(loop)

        try:
            result = loop.run_until_complete(
                cls.resolve_async(
                    dns_request=dns_request,
                    dns_servers=cls.dns_servers,
                    port=cls.port,
                    max_msg_size=cls.max_msg_size,
                    timeout=cls.timeout,
                    timeout_w_buffer=cls.timeout_w_buffer,
                    loop=loop
                )
            )
        finally:
            loop.close()

        if not result:
            return None

        delay: float = (monotonic() - start)*1000
        # DNSResponse, server = result
        dns_per_server_metrics[result[1]].add_sample(delay)
        dns_metrics_external.add_sample(delay)
        return result[0]
