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

# 3rd party
from dnslib import QTYPE, RR, A, DNSRecord

from app.config.config import config
from app.libs.libs import MRUCache, TTLCache, measure_latency_decorator

# Local
from app.models.models import DNSReqMessage, DNSResponseCode
from app.services.dns.blacklist_service import BlacklistService
from app.services.dns.db import DnsQueryHistoryDb, DnsStatsDb
from app.services.dns.db_persistance import DbPersistanceService
from app.services.dns.external_resolver import ExternalResolverService
from app.services.dns.metrics import dns_metrics
from app.services.logger.logger import MainLogger
from app.utils.dns_utils import DNSUtils

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
LOC_RECV_QUEUE_SIZE = RESOURCE_LIMITS.get("queues").get("receive", 100)
METRICS_BUFFER_SIZE = RESOURCE_LIMITS.get("caches").get(
    "metrics_sample_buffer_size", 100
)
DEDUP_CACHE_SIZE = RESOURCE_LIMITS.get("caches").get("deduplication_cache_size", 100)
REPLY_CACHE_SIZE = RESOURCE_LIMITS.get("caches").get("reply_cache_size", 100)


dns_logger = MainLogger.get_logger(service_name="DNS", log_level="debug")


class LocalResolverService:
    """
    Local DNS Resolver service.

    Responsibilities:
    - Initialize and manage UDP socket for DNS queries.
    - Listen for incoming DNS requests asynchronously.
    - Process requests
    - Uses workers (cache, blacklist ...).
    - Cache responses with TTL.
    - Track metrics and query history.
    - Clean shutdown with thread and socket management.

    Usage:
    1. Call init() once to configure and bind socket.
    2. Call start() to begin listening and processing.
    3. Call stop() to gracefully shutdown.
    """

    _is_init = False
    _recv_thread = None
    _req_worker_threads = []
    _dns_socket_lock = RLock()
    _dedup_cache = MRUCache(max_size=DEDUP_CACHE_SIZE)
    _dns_cache = TTLCache(max_size=REPLY_CACHE_SIZE, ttl=DNS_CACHE_TTL)
    _stop_event = Event()

    @classmethod
    def init(
        cls,
        port: int = DNS_PORT,
        host: str = DNS_HOST,
        msg_size: int = DNS_UDP_PACKET_MAX_SIZE,
        queue_get_timeout: float = QUEUE_GET_TIMEOUT,
        max_workers: int = PROCESS_WORKERS,
    ):
        """
        Initialize the local DNS resolver service.

        Binds UDP socket specified host+port to receiving DNS requests.
        Configures socket options like packet size, timeouts, and worker count.
        Initializes the request queue for incoming DNS packets.
        """
        if cls._is_init:
            raise RuntimeError("Already init")

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
            DnsStatsDb.increment(key="request_blacklisted")
            reply: DNSRecord = dns_req_message.dns_message.reply()
            reply.header.rcode = DNSResponseCode.REFUSED
            cls._send_reply(dns_req_message, reply)
            return True

        return False

    @classmethod
    @measure_latency_decorator(metrics=dns_metrics)
    def _handle_local(
        cls, dns_req_message: DNSReqMessage, zones: dict = DNS_STATIC_ZONES
    ) -> bool:
        """
        Check if the requested domain matches any local DNS zone and respond with the
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
                DnsStatsDb.increment(key="request_local")
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
            dns_logger.error("Failed to handle local query %s.", err)

        return False

    @classmethod
    @measure_latency_decorator(metrics=dns_metrics)
    def _handle_cache_hit(cls, dns_req_message: DNSReqMessage) -> bool:
        """
        Is DNS query result cached and send the cached reply if found.
        """

        _cached_reply: Optional[DNSRecord] = cls._dns_cache.get(
            dns_req_message.cache_key
        )
        if _cached_reply:
            DnsStatsDb.increment(key="request_cache_hit")
            cls._send_reply(dns_req_message, _cached_reply)
            return True

        DnsStatsDb.increment(key="request_cache_miss")
        return False

    @classmethod
    @measure_latency_decorator(metrics=dns_metrics)
    def _handle_external(cls, dns_req_message: DNSReqMessage) -> bool:
        """
        Forward DNS query externally and send the reply if successful.
        Args:
            dns_req_message(DNSReqMessage): DNS request.
        Returns:
            bool: True if the external resolution and reply sending succeeded.
        """

        try:
            dns_res_message: Optional[DNSRecord] = (
                ExternalResolverService.resolve_external(dns_req_message.dns_message)
            )
            if dns_res_message:
                DnsStatsDb.increment("request_external")
                _ttl: int = DNSUtils.extract_ttl(dns_res_message)
                cls._dns_cache.add(
                    key=dns_req_message.cache_key,
                    ttl=_ttl if _ttl > DNS_CACHE_TTL else DNS_CACHE_TTL,
                    value=dns_res_message,
                )
                cls._send_reply(dns_req_message, dns_res_message)
                return True

        except Exception as err:
            dns_logger.error("External resolution failed: %s", err)
            DnsStatsDb.increment("request_external_failed")

        return False

    @classmethod
    @measure_latency_decorator(metrics=dns_metrics)
    def _handle_server_fail(cls, dns_req_message: DNSReqMessage) -> bool:
        """
        Send a SERVFAIL response to the client for the given DNS message.
        Returns True if reply sent successfully, False otherwise.
        """
        try:
            reply: DNSRecord = dns_req_message.dns_message.reply()
            reply.header.rcode = DNSResponseCode.SERVER_FAILURE
            cls._send_reply(dns_req_message, reply)
            return True
        except Exception as _err:
            dns_logger.error(f"Failed to send SERVFAIL:{str(_err)}.")
            return False

    @classmethod
    def _send_reply(cls, dns_req_message: DNSReqMessage, dns_res_message: DNSRecord):
        """Send DNS response to the message holder."""

        try:
            DnsStatsDb.increment(key="response_total")
            dns_res_message.header.id = dns_req_message.dns_message.header.id
            with cls._dns_socket_lock:
                if cls._dns_socket:
                    cls._dns_socket.sendto(dns_res_message.pack(), dns_req_message.addr)

        except Exception as _err:
            dns_logger.error(
                "Failed sending reply to %s %s.", dns_req_message.addr, _err
            )

    @classmethod
    def _listen_traffic(cls, timeout: float = DNS_SOCKET_TIMEOUT):
        """Receive UDP packets and enqueue requests."""
        while not cls._stop_event.is_set():
            try:
                # Wait socket to be readable (data ready to recv) + w  timeout
                # OS level select()
                if cls._dns_socket:
                    _rlist, _wlist, _xlist = select([cls._dns_socket], [], [], timeout)
                    if cls._dns_socket in _rlist:
                        data, addr = cls._dns_socket.recvfrom(cls._msg_size)
                        cls._recv_queue.put_nowait(DNSReqMessage(data, addr))
            except Full:
                dns_logger.warning("Receive queue full.")
            except Exception as err:
                dns_logger.error(f"Error reading from DNS socket:{str(err)}.")

    @classmethod
    def _process_dns_req_packets(cls):
        """Worker: dequeue and process DNS requests until sentinel or stop event."""
        while not cls._stop_event.is_set():
            try:
                _dns_req_message: DNSReqMessage | None = cls._recv_queue.get(
                    timeout=cls._queue_get_timeout
                )
                # We hit the sentinel is shutdown hence we exit the loop
                if _dns_req_message is None:
                    break
            except Empty:
                continue

            try:
                if (
                    not _dns_req_message.is_query
                    or not _dns_req_message.is_domain_valid
                    or cls._dedup_cache.is_present(_dns_req_message.dedup_key)
                ):
                    continue
                DnsStatsDb.increment(key="request_total")
                if cls._handle_blacklist(_dns_req_message):
                    continue

                cls._dedup_cache.add(_dns_req_message.dedup_key)
                DnsQueryHistoryDb.add_query(_dns_req_message.domain)
                DnsStatsDb.increment(key="request_valid")

                if cls._handle_cache_hit(_dns_req_message):
                    continue
                if cls._handle_local(_dns_req_message, DNS_STATIC_ZONES):
                    continue
                if cls._handle_external(_dns_req_message):
                    continue
                cls._handle_server_fail(_dns_req_message)

            except Exception as err:
                dns_logger.error(f"Processing error: {str(err)}.")

            finally:
                cls._recv_queue.task_done()
                # Metrics.add_sample(time.monotonic() - _start)

    @classmethod
    def start(cls):
        """Start listening and processing threads."""
        if not cls._is_init:
            raise RuntimeError("Must init")
        cls._stop_event.clear()
        cls._recv_thread = Thread(target=cls._listen_traffic, daemon=True)
        cls._recv_thread.start()
        for _ in range(cls._max_workers):
            _worker_thread = Thread(target=cls._process_dns_req_packets, daemon=True)
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
        dns_logger.info("DNSResolver stopped.")


class DNSServer:
    _lock = RLock()
    _initialised = False
    _running = False

    @classmethod
    def init(cls):
        with cls._lock:
            if cls._initialised:
                raise RuntimeError("Already Init")
            DnsStatsDb.init()
            DnsQueryHistoryDb.init()
            DbPersistanceService.init(logger=dns_logger)
            ExternalResolverService.init(logger=dns_logger)
            LocalResolverService.init()
            BlacklistService.init(logger=dns_logger)
            cls._initialised = True
            # Metrics.init(max_size=METRICS_SAMPLE_BUFFER_SIZE)

    @classmethod
    def start(cls):
        if cls._running:
            raise RuntimeError("Server already running.")
        with cls._lock:
            BlacklistService.start()
            DbPersistanceService.start()
            ExternalResolverService.start()
            LocalResolverService.start()
            cls._running = True
            dns_logger.info("DNS server started.")

    @classmethod
    def stop(cls):
        if not cls._running:
            raise RuntimeError("Server not running.")
        with cls._lock:
            DbPersistanceService.stop()
            ExternalResolverService.stop()
            BlacklistService.stop()
            LocalResolverService.stop()
            dns_logger.info("Server stopped.")
            cls._running = False
