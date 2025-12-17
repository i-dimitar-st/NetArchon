# Native
from pathlib import Path
from queue import Empty, Full, Queue
from select import select
from socket import (
    AF_INET,
    SO_RCVBUF,
    SO_REUSEADDR,
    SOCK_DGRAM,
    SOL_SOCKET,
    socket,
)
from threading import Event, RLock, Thread
from typing import Any, Optional

from cachetools import TTLCache

# 3rd party
from dnslib import QTYPE, RR, A, DNSRecord

# Local
from src.config.config import config
from src.libs.libs import MRUCache, measure_latency_decorator
from src.models.models import DNSReqMessage, DNSResponseCode
from src.services.dns.blacklist_service import BlacklistService
from src.services.dns.db import DnsQueryHistoryDb, DnsStatsDb
from src.services.dns.external_resolver import ExternalResolverService

# from src.services.dns.external_resolver_async import AsyncExternalResolverService
from src.services.dns.metrics import dns_metrics
from src.services.dns.utils import is_dns_query, is_valid_domain
from src.utils.dns_utils import DNSUtils

PATHS = config.get("paths")
ROOT_PATH = Path(PATHS.get("root"))
DB_PATH = ROOT_PATH / PATHS.get("database")

DNS_CONFIG = config.get("dns").get("config")
DNS_HOST = DNS_CONFIG.get("host")
DNS_PORT = DNS_CONFIG.get("port")
DNS_CACHE_TTL = int(DNS_CONFIG.get("cache_ttl", 1200))
DNS_UDP_PACKET_MAX_SIZE = int(DNS_CONFIG.get("udp_max_size", 1232))
DNS_SOCKET_OS_BUFFER_SIZE = int(DNS_CONFIG.get("os_buffer_size", 4194304))

WORKERS_CONFIG = config.get("dns").get("worker_config")
PROCESS_WORKERS = WORKERS_CONFIG.get("processors", 100)

TIMEOUTS = config.get("dns").get("timeouts")
DNS_SOCKET_TIMEOUT = float(TIMEOUTS.get("local_socket", 0.1))
QUEUE_GET_TIMEOUT = float(TIMEOUTS.get("local_queue_get", 0.5))
WORKER_JOIN_TIMEOUT = float(TIMEOUTS.get("worker_join", 1))

DNS_STATIC_ZONES = config.get("dns").get("static_zones")

RESOURCE_LIMITS = config.get("dns").get("resource_limits")
LOC_RECV_QUEUE_SIZE = RESOURCE_LIMITS.get("receive_queue_size", 100)
DEDUP_CACHE_SIZE = RESOURCE_LIMITS.get("deduplication_cache_size", 100)
REPLY_CACHE_SIZE = RESOURCE_LIMITS.get("reply_cache_size", 100)


class ResolverService:
    """DNS Resolver service.

    Responsibilities:
    - Initialize and manage UDP socket for DNS queries.
    - Listen for incoming DNS requests asynchronously.
    - Process requests
    - Uses workers (cache, blacklist ...).
    - Cache responses with TTL.
    - Track metrics and query history.
    - Clean shutdown with thread and socket management.
    """

    _is_init = False
    _recv_thread = None
    _req_worker_threads = []
    _dns_socket_lock = RLock()
    _dedup_cache = MRUCache(max_size=DEDUP_CACHE_SIZE)
    _dns_cache = TTLCache(maxsize=REPLY_CACHE_SIZE, ttl=DNS_CACHE_TTL)
    _stop_event = Event()

    @classmethod
    def init(
        cls,
        logger,
        port: int = DNS_PORT,
        host: str = DNS_HOST,
        msg_size: int = DNS_UDP_PACKET_MAX_SIZE,
        queue_get_timeout: float = QUEUE_GET_TIMEOUT,
        max_workers: int = PROCESS_WORKERS,
    ):
        """Initialize the local DNS resolver service.

        Binds UDP socket specified host+port to receiving DNS requests.
        Configures socket options like packet size, timeouts, and worker count.
        Initializes the request queue for incoming DNS packets.
        """
        if cls._is_init:
            raise RuntimeError("Already init")

        cls.logger = logger
        cls._host: str = host
        cls._port: int = port
        cls._msg_size: int = msg_size
        cls._queue_get_timeout: float = queue_get_timeout
        cls._max_workers: int = max_workers
        cls._dns_socket = socket(AF_INET, SOCK_DGRAM)
        cls._dns_socket.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
        cls._dns_socket.setsockopt(SOL_SOCKET, SO_RCVBUF, DNS_SOCKET_OS_BUFFER_SIZE)
        cls._dns_socket.setblocking(False)
        cls._dns_socket.bind((cls._host, cls._port))
        cls._recv_queue = Queue(maxsize=LOC_RECV_QUEUE_SIZE)
        cls._is_init = True

    @classmethod
    @measure_latency_decorator(metrics=dns_metrics)
    def _handle_blacklist(cls, dns_req_message: DNSReqMessage) -> bool:
        """Check if the domain is blacklisted and send a refusal reply if so."""
        if BlacklistService.is_blacklisted(dns_req_message.domain):
            reply: DNSRecord = dns_req_message.dns_message.reply()
            reply.header.rcode = DNSResponseCode.REFUSED
            cls._send_reply(dns_req_message, reply)
            return True

        return False

    @classmethod
    @measure_latency_decorator(metrics=dns_metrics)
    def _handle_local(cls,dns_req_message: DNSReqMessage,zones: dict = DNS_STATIC_ZONES) -> bool:
        """Check if the requested domain matches any local DNS zone and respond with the
        corresponding IP address if found.
        """
        try:
            _hostname_ip = None
            for _zone in zones.keys():
                if not DNSUtils.is_local_query(dns_req_message.domain, _zone.lower()):
                    continue

                if dns_req_message.domain.endswith(_zone.lower()):
                    _hostname: str = DNSUtils.extract_hostname(
                        dns_req_message.domain, _zone
                    )
                    _hostname_ip: Any = zones[_zone].get(_hostname)
                    if _hostname_ip:
                        break

            if _hostname_ip:
                reply = dns_req_message.dns_message.reply()
                reply.header.rcode = DNSResponseCode.NO_ERROR
                reply.add_answer(
                    RR(
                        rname=dns_req_message.dns_message.q.qname,
                        rtype=QTYPE.A,
                        rclass=1,
                        ttl=DNS_CACHE_TTL,
                        rdata=A(_hostname_ip),
                    )
                )
                cls._send_reply(dns_req_message, reply)
                return True

        except Exception as err:
            cls.logger.error("Failed to handle local query %s.", err)

        return False

    @classmethod
    @measure_latency_decorator(metrics=dns_metrics)
    def _handle_cache_hit(cls, dns_req_message: DNSReqMessage) -> bool:
        """Is DNS query result cached and send the cached reply if found.
        """
        _cached_reply: Optional[DNSRecord] = cls._dns_cache.get(dns_req_message.cache_key)
        if _cached_reply:
            cls._send_reply(dns_req_message, _cached_reply)
            return True

        return False

    @classmethod
    def _handle_external(cls, dns_req_message: DNSReqMessage) -> bool:
        """Forward DNS query externally and send the reply if successful.

        Args:
            dns_req_message(DNSReqMessage): DNS request.

        Returns:
            bool: True if the external resolution and reply sending succeeded.

        """
        try:
            dns_res_message: Optional[DNSRecord] = ExternalResolverService.resolve_external(dns_req_message.dns_message)
            if dns_res_message:
                cls._dns_cache[dns_req_message.cache_key] = dns_res_message
                cls._send_reply(dns_req_message, dns_res_message)
                return True

        except Exception as err:
            cls.logger.error("External resolution failed: %s", err)

        return False

    @classmethod
    @measure_latency_decorator(metrics=dns_metrics)
    def _handle_server_fail(cls, dns_req_message: DNSReqMessage) -> bool:
        """Send a SERVFAIL response to the client for the given DNS message.
        Returns True if reply sent successfully, False otherwise.
        """
        try:
            reply: DNSRecord = dns_req_message.dns_message.reply()
            reply.header.rcode = DNSResponseCode.SERVER_FAILURE
            cls._send_reply(dns_req_message, reply)
            return True
        except Exception as _err:
            cls.logger.error(f"Failed to send SERVFAIL:{str(_err)}.")
            return False

    @classmethod
    def _send_reply(
        cls,
        dns_req_message: DNSReqMessage,
        dns_res_message: DNSRecord,
    ):
        """Send DNS response to the message holder."""
        try:
            DnsStatsDb.increment(key="response_total")
            dns_res_message.header.id = dns_req_message.dns_message.header.id
            with cls._dns_socket_lock:
                if cls._dns_socket:
                    cls._dns_socket.sendto(
                        dns_res_message.pack(),
                        dns_req_message.addr,
                    )

        except Exception as _err:
            cls.logger.error(
                "Failed sending reply to %s %s.",
                dns_req_message.addr,
                _err,
            )

    @classmethod
    def _work_listen_traffic(cls, timeout: float = DNS_SOCKET_TIMEOUT):
        """Receive UDP packets and enqueue requests.

        Args:
            timeout(float): Socker timeout

        """
        if cls._dns_socket is None:
            cls.logger.error("DNS socket not init.")
            return

        while not cls._stop_event.is_set():
            try:
                # Is socket ready basically
                if cls._dns_socket in select([cls._dns_socket], [], [], timeout)[0]:  # _rlist, _wlist, _xlist = select([cls._dns_socket], [], [], timeout)
                    cls._recv_queue.put_nowait(DNSReqMessage(*cls._dns_socket.recvfrom(cls._msg_size)))
            except Full:
                cls.logger.warning("Receive queue full.")
            except Exception as err:
                cls.logger.error(f"Error reading from DNS socket:{str(err)}.")

    @classmethod
    def _work_process_dns_packet(cls):
        """Worker: dequeue and process DNS requests until sentinel or stop event."""
        while not cls._stop_event.is_set():
            try:
                _dns_req_message: DNSReqMessage | None = cls._recv_queue.get(timeout=cls._queue_get_timeout)
            except Empty:
                continue

            if _dns_req_message is None:
                break

            try:
                DnsStatsDb.increment(key="request_total")
                if not is_dns_query(_dns_req_message.dns_message) or not is_valid_domain(_dns_req_message.domain):
                    continue

                if cls._dedup_cache.is_present(_dns_req_message.dedup_key):
                    continue
                cls._dedup_cache.add(_dns_req_message.dedup_key)

                DnsStatsDb.increment(key="request_valid")

                if cls._handle_blacklist(_dns_req_message):
                    DnsStatsDb.increment(key="request_blacklisted")
                    continue

                DnsQueryHistoryDb.add_query(_dns_req_message.domain)

                if cls._handle_cache_hit(_dns_req_message):
                    DnsStatsDb.increment(key="request_cache_hit")
                    continue

                DnsStatsDb.increment(key="request_cache_miss")

                # if cls._handle_local(_dns_req_message, DNS_STATIC_ZONES):
                #     DnsStatsDb.increment(key="request_local")
                #     continue

                if cls._handle_external(_dns_req_message):
                    DnsStatsDb.increment("request_external")
                    continue

                DnsStatsDb.increment("request_external_failed")
                cls._handle_server_fail(_dns_req_message)

            except Exception as err:
                cls.logger.error(f"Processing error: {str(err)}.")

            finally:
                cls._recv_queue.task_done()

    @classmethod
    def start(cls):
        """Start listening and processing threads."""
        if not cls._is_init:
            raise RuntimeError("Must init")
        cls._stop_event.clear()
        cls._recv_thread = Thread(target=cls._work_listen_traffic, daemon=True)
        cls._recv_thread.start()
        for _ in range(cls._max_workers):
            _worker_thread = Thread(target=cls._work_process_dns_packet, daemon=True)
            _worker_thread.start()
            cls._req_worker_threads.append(_worker_thread)

    @classmethod
    def stop(cls):
        """Stop service, close socket, send sentinel to workers, wait for shutdown."""
        if not cls._is_init:
            raise RuntimeError("Not init.")
        cls._stop_event.set()
        with cls._dns_socket_lock:
            if cls._dns_socket:
                cls._dns_socket.close()
            cls._dns_socket = None

        # Unblock worker threads waiting on the queue by pushing none values
        for _ in range(cls._max_workers):
            cls._recv_queue.put_nowait(None)

        if cls._recv_thread:
            cls._recv_thread.join(timeout=WORKER_JOIN_TIMEOUT)
        for _worker in cls._req_worker_threads:
            _worker.join(timeout=WORKER_JOIN_TIMEOUT)
        cls._req_worker_threads.clear()
        cls._is_init = False
        cls.logger.info("DNSResolver stopped.")
