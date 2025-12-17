import asyncio
from ipaddress import IPv4Address
from itertools import cycle
from pathlib import Path
from socket import AF_INET, SOCK_DGRAM, socket
from time import monotonic
from typing import Iterator

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
EXTERNAL_DNS_SERVERS = [IPv4Address(ip) for ip in list(DNS_CONFIG.get("external_dns_servers"))]

TIMEOUTS = config.get("dns").get("timeouts")
EXTERNAL_TIMEOUT = float(TIMEOUTS.get("external_socket", 15))
EXTERNAL_TIMEOUT_BUFFER = float(TIMEOUTS.get("external_socket_buffer", 2))

class AsyncExternalResolverService:
    _dns_servers: list[IPv4Address]
    _dns_cycle: Iterator[IPv4Address]
    _port: int
    _max_msg_size: int
    _timeout: float
    _timeout_w_buffer: float
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
        cls.logger = logger
        cls._dns_servers = dns_servers
        cls._dns_cycle = cycle(cls._dns_servers)
        cls._port = port
        cls._timeout = timeout
        cls._timeout_w_buffer = timeout + timeout_buffer
        cls._max_msg_size = max_msg_size
        cls.logger.info(f"{cls.__name__} initialized.")

    @staticmethod
    async def _resolve_async(dns_request, dns_servers, dns_cycle, timeout, port, max_msg_size, timeout_w_buffer):
        tasks = [
            asyncio.create_task(
                AsyncExternalResolverService._query_external_dns_server(
                    dns_request, next(dns_cycle), timeout, port, max_msg_size
                )
            )
            for _ in dns_servers
        ]

        done, pending = await asyncio.wait(tasks, timeout=timeout_w_buffer, return_when=asyncio.FIRST_COMPLETED)

        for task in done:
            try:
                return task.result()
            except Exception:
                continue

        return None

    @classmethod
    def resolve_external(cls, dns_request: DNSRecord):
        """Run each request in its own loop."""
        result = asyncio.run(
            cls._resolve_async(
                dns_request, cls._dns_servers, cls._dns_cycle,
                cls._timeout, cls._port, cls._max_msg_size, cls._timeout_w_buffer
            )
        )

        if result is None:
            return None

        reply, delay, server_ip = result
        dns_per_server_metrics[server_ip].add_sample(delay)
        dns_metrics_external.add_sample(delay)
        return reply

    @staticmethod
    async def _query_external_dns_server(
        request: DNSRecord,
        dns_server: IPv4Address,
        timeout: float,
        port: int,
        max_msg_size: int,
    ):
        loop = asyncio.get_running_loop()
        sock = socket(AF_INET, SOCK_DGRAM)
        sock.setblocking(False)
        try:
            start = monotonic()
            await loop.sock_sendto(sock, request.pack(), (str(dns_server), port))
            return DNSRecord.parse(await asyncio.wait_for(loop.sock_recv(sock, max_msg_size), timeout)), (monotonic() - start) * 1000, dns_server
        finally:
            sock.close()
