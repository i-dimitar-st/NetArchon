# Native
from concurrent.futures import Future, ThreadPoolExecutor, as_completed
from functools import lru_cache
from json import load
from pathlib import Path
from queue import Full, Empty, Queue
from random import choices
from select import select
from socket import (
    socket,
    AF_INET,
    SOCK_DGRAM,
    SOL_SOCKET,
    SO_REUSEADDR,
    SO_RCVBUF,
    timeout as socketTimeout,
)
from threading import Lock, Event, Thread, RLock
from time import monotonic
from typing import Optional, Any
from fnmatch import fnmatch

# 3rd party
from dnslib import DNSRecord, QTYPE, RR, A

# Local
from models.models import DNSReqMessage, DnsResponseCode, DnsServersIpv4
from config.config import config
from services.logger.logger import MainLogger
from services.dns.db import DnsQueryHistoryDb, DnsStatsDb
from libs.libs import TTLCache, MRUCache
from utils.dns_utils import DNSUtils


PATHS = config.get("paths")
ROOT_PATH = Path(PATHS.get("root"))
DB_PATH = ROOT_PATH / PATHS.get("database")

DNS_CONFIG = config.get("dns").get("config")
DNS_HOST = DNS_CONFIG.get("host")
DNS_PORT = DNS_CONFIG.get("port")
DNS_CACHE_TTL = int(DNS_CONFIG.get("cache_ttl", 1200))
DNS_UDP_PACKET_MAX_SIZE = int(DNS_CONFIG.get("udp_max_size", 1232))
DNS_SOCKET_OS_BUFFER_SIZE = int(DNS_CONFIG.get("os_buffer_size", 4194304))
DB_FLUSH_INTERVAL = int(DNS_CONFIG.get("db_flush_interval", 30))
EXTERNAL_DNS_SERVERS = DNS_CONFIG.get("external_dns_servers")

WORKERS_CONFIG = config.get("dns").get("worker_config")
EXTERNAL_WORKERS = WORKERS_CONFIG.get("external", 300)
PROCESS_WORKERS = WORKERS_CONFIG.get("processors", 100)

BLACKLISTS_CONFIG = config.get("dns").get("blacklists_config")
BLACKLIST_PATH = ROOT_PATH / BLACKLISTS_CONFIG.get(
    "path", "config/dns_control_list.json"
)
BLACKLIST_CACHE_SIZE = BLACKLISTS_CONFIG.get("cache_size", 100)
BLACKLISTS_LOADING_INTERVAL = BLACKLISTS_CONFIG.get("loading_interval", 30)

TIMEOUTS = config.get("dns").get("timeouts")
DNS_SOCKET_TIMEOUT = float(TIMEOUTS.get("local_socket", 0.1))
EXTERNAL_TIMEOUT = float(TIMEOUTS.get("external_socket", 15))
EXTERNAL_TIMEOUT_BUFFER = float(TIMEOUTS.get("external_socket_buffer", 2))
QUEUE_GET_TIMEOUT = float(TIMEOUTS.get("local_queue_get", 0.5))
WORKER_JOIN_TIMEOUT = float(TIMEOUTS.get("worker_join", 1))

DNS_STATIC_ZONES = config.get("dns").get("static_zones")

RESOURCE_LIMITS = config.get("dns").get("resource_limits")
DNS_LOCAL_RECV_QUEUE_SIZE = RESOURCE_LIMITS.get("queues").get("receive", 100)
METRICS_SAMPLE_BUFFER_SIZE = RESOURCE_LIMITS.get("caches").get(
    "metrics_sample_buffer_size", 100
)
DNS_DEDUPLICATION_CACHE_SIZE = RESOURCE_LIMITS.get("caches").get(
    "deduplication_cache_size", 100
)
DNS_REPLY_CACHE_SIZE = RESOURCE_LIMITS.get("caches").get("reply_cache_size", 100)


dns_logger = MainLogger.get_logger(service_name="DNS", log_level="debug")


class DbFlushService:
    """
    Background service that periodically flushes in-memory DNS databases to disk.
    This service runs a dedicated thread which triggers saving of DnsStatsDb and DnsQueryHistoryDb
    at a configured interval to persist current state safely to disk.
    """

    _lock = Lock()
    _stop_event = Event()
    _worker: Optional[Thread] = None
    _interval: Optional[int] = None

    @classmethod
    def init(cls, interval: int = DB_FLUSH_INTERVAL):
        """
        Initialize the flush service with the given interval (seconds).
        """
        with cls._lock:
            cls._interval = interval

    @classmethod
    def start(cls):
        """
        Fresh start of new background worker.
        """
        with cls._lock:
            if not cls._interval:
                raise RuntimeError("Not init")
            if cls._worker and cls._worker.is_alive():
                raise RuntimeError("Already started")
            cls._stop_event.clear()
            cls._worker = Thread(target=cls._work, daemon=True)
            cls._worker.start()
            dns_logger.info("%s started.", cls.__name__)

    @classmethod
    def stop(cls):
        """
        Stop the background flush thread and wait for it to finish.
        Resets worker.
        """
        with cls._lock:
            cls._stop_event.set()
            if cls._worker:
                cls._worker.join(timeout=WORKER_JOIN_TIMEOUT)
                cls._worker = None
        dns_logger.info("%s stopped.", cls.__name__)

    @classmethod
    def restart(cls):
        """
        Restart the flush service
        """
        cls.stop()
        cls.start()

    @classmethod
    def _work(cls):
        """
        Main worker.
        Periodically calls save_to_disk on DnsStatsDb and DnsQueryHistoryDb,
        catching and logging any exceptions.
        """
        while not cls._stop_event.is_set():
            try:
                DnsStatsDb.save_to_disk()
                DnsQueryHistoryDb.save_to_disk()
            except Exception as _err:
                dns_logger.warning("Persistence error: %s.", _err)
            cls._stop_event.wait(cls._interval)


class BlacklistService:
    """
    Loads and refreshes blacklist rules from a JSON file in a background thread.
    """

    _lock = Lock()
    _stop_event = Event()
    _worker: Optional[Thread] = None
    _interval: Optional[int] = None
    _blacklists = {"blacklist": set(), "blacklist_rules": set()}

    @classmethod
    def init(cls, interval: int = BLACKLISTS_LOADING_INTERVAL):
        """
        Set refresh interval in seconds.
        """
        with cls._lock:
            cls._interval = interval

    @classmethod
    def start(cls):
        """
        Start background thread to reload blacklists periodically.
        """
        with cls._lock:
            if not cls._interval:
                raise RuntimeError("Not init")
            if cls._worker and cls._worker.is_alive():
                raise RuntimeError("Already started")
            cls._stop_event.clear()
            cls._worker = Thread(target=cls._work, daemon=True)
            cls._worker.start()
            dns_logger.info("%s started.", cls.__name__)

    @classmethod
    def stop(cls):
        """
        Stop, wait and reset for worker.
        """
        with cls._lock:
            cls._stop_event.set()
            if cls._worker:
                cls._worker.join(timeout=WORKER_JOIN_TIMEOUT)
                cls._worker = None
            dns_logger.info("%s stopped.", cls.__name__)

    @classmethod
    def restart(cls):
        """
        Stop and start worker.
        """
        cls.stop()
        cls.start()
        dns_logger.info("%s restarted.", cls.__name__)

    @classmethod
    def _load_blacklists(cls) -> dict:
        """
        Load blacklist data from JSON file.
        """
        with open(BLACKLIST_PATH, "r", encoding="utf-8") as file_handle:
            control_list: Any = load(file_handle)
        return {
            "blacklist": set(
                url.strip().lower()
                for url in control_list.get("blacklist", {}).get("urls", [])
            ),
            "blacklist_rules": set(
                rule.strip().lower()
                for rule in control_list.get("blacklist", {}).get("rules", [])
            ),
        }

    @classmethod
    def _work(cls):
        """
        Background thread: reload blacklist periodically.
        """
        while not cls._stop_event.is_set():
            try:
                new_lists = cls._load_blacklists()
                with cls._lock:
                    if new_lists != cls._blacklists:
                        cls._blacklists = new_lists
                        dns_logger.info(
                            "blacklist:%d, blacklist_rules:%d.",
                            len(new_lists["blacklist"]),
                            len(new_lists["blacklist_rules"]),
                        )
                        cls.is_blacklisted.cache_clear()
            except Exception as err:
                dns_logger.error("Failed processing control lists %s.", err)
            cls._stop_event.wait(cls._interval)

    @staticmethod
    @lru_cache(maxsize=BLACKLIST_CACHE_SIZE)
    def is_blacklisted(qname: str) -> bool:
        """
        Check if domain matches blacklist or wildcard rules.
        """
        if not qname:
            return False
        if qname in BlacklistService._blacklists["blacklist"]:
            return True
        for _rule in BlacklistService._blacklists["blacklist_rules"]:
            if fnmatch(qname, _rule):
                return True
        return False


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

    _lock = Lock()
    _port: int = DNS_PORT
    _max_msg_size: int = DNS_UDP_PACKET_MAX_SIZE
    _timeout: float = EXTERNAL_TIMEOUT
    _timeout_buffer: float = EXTERNAL_TIMEOUT_BUFFER
    _max_workers: int = EXTERNAL_WORKERS
    _executor: Optional[ThreadPoolExecutor] = None
    _dns_servers: Optional[DnsServersIpv4] = None

    @classmethod
    def init(
        cls,
        port: int = DNS_PORT,
        timeout: float = EXTERNAL_TIMEOUT,
        timeout_buffer: float = EXTERNAL_TIMEOUT_BUFFER,
        dns_servers: list = EXTERNAL_DNS_SERVERS,
        max_msg_size: int = DNS_UDP_PACKET_MAX_SIZE,
        max_workers: int = EXTERNAL_WORKERS,
    ):
        """
        Initialize the resolver with configuration and start thread pool.
        """

        with cls._lock:
            if cls._executor is not None:
                raise RuntimeError("Already initialized")
            cls._dns_servers = DnsServersIpv4(dns_servers)
            cls._port = port
            cls._max_msg_size = max_msg_size
            cls._timeout = timeout
            cls._timeout_buffer = timeout_buffer
            cls._max_workers = max_workers
            dns_logger.info("%s init.", cls.__name__)

    @classmethod
    def start(cls):
        """Start thread pool executor."""
        with cls._lock:
            if cls._executor:
                raise RuntimeError("Already started")
            cls._executor = ThreadPoolExecutor(max_workers=cls._max_workers)
            dns_logger.info("%s started.", cls.__name__)

    @classmethod
    def stop(cls):
        """Stop and clean up the thread pool executor."""
        with cls._lock:
            if cls._executor:
                cls._executor.shutdown(wait=True, cancel_futures=True)
                cls._executor = None
                dns_logger.info("%s stopped.", cls.__name__)

    @classmethod
    def restart(cls, max_workers: int = EXTERNAL_WORKERS):
        """Restart the thread pool executor with new worker count."""
        cls.stop()
        with cls._lock:
            cls._executor = ThreadPoolExecutor(max_workers=max_workers)
            dns_logger.info("%s restarted.", cls.__name__)

    @classmethod
    def resolve_external(cls, dns_request: DNSRecord) -> Optional[DNSRecord]:
        """Send DNS query to external servers in parallel; return first successful reply."""
        with cls._lock:
            if not cls._executor:
                raise RuntimeError("Not started")
            if cls._dns_servers is None:
                raise RuntimeError("No DNS Servers")

        # Randomize to distribute requests across DNS servers evenly per thread
        futures = {}
        for dns_server_ip in choices(cls._dns_servers, k=len(cls._dns_servers)):
            future: Future[DNSRecord] = cls._executor.submit(
                cls._query_external_dns_server, dns_request, dns_server_ip
            )
            futures[future] = dns_server_ip

        try:
            # As completed return first completed so we want that and cancel rest
            for _completed in as_completed(
                futures, timeout=cls._timeout + cls._timeout_buffer
            ):
                _dns_server_ip: str = futures[_completed]
                try:
                    # Get first resut but cancel other futures to avoid zombies.
                    reply: Any = _completed.result()
                    for _still_pending in futures:
                        if _still_pending != _completed:
                            _still_pending.cancel()
                    return reply

                except Exception as err:
                    dns_logger.error(f"{_dns_server_ip} errored with {str(err)}.")

        except Exception as err:
            dns_logger.error(f"Error with DNS futures: {str(err)}.")

        # All failed
        return None

    @classmethod
    def _query_external_dns_server(
        cls, request: DNSRecord, dns_server: str
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


class LocalResolverService:
    """
    Local DNS Resolver service.

    Responsibilities:
    - Initialize and manage UDP socket for DNS queries.
    - Listen for incoming DNS requests asynchronously.
    - Process requests with worker threads (cache, blacklist, local zones, external resolution).
    - Cache responses with TTL.
    - Track metrics and query history.
    - Clean shutdown with thread and socket management.

    Usage:
    1. Call init() once to configure and bind socket.
    2. Call start() to begin listening and processing.
    3. Call stop() to gracefully shutdown.

    Designed for concurrent processing with thread safety via locks and sentinel queue values.
    """

    _is_init = False
    _recv_thread = None
    _req_worker_threads = []
    _dns_socket_lock = RLock()
    _dedup_cache = MRUCache(max_size=DNS_DEDUPLICATION_CACHE_SIZE)
    _dns_cache = TTLCache(max_size=DNS_REPLY_CACHE_SIZE, ttl=DNS_CACHE_TTL)
    _stop_event = Event()

    @classmethod
    def init(
        cls,
        dns_servers: list = EXTERNAL_DNS_SERVERS,
        port: int = DNS_PORT,
        host: str = DNS_HOST,
        msg_size: int = DNS_UDP_PACKET_MAX_SIZE,
        external_timeout: float = EXTERNAL_TIMEOUT,
        queue_get_timeout: float = QUEUE_GET_TIMEOUT,
        max_workers: int = PROCESS_WORKERS,
    ):
        """
        Initialize the local DNS resolver service.

        Sets up UDP socket bound to the specified host and port for receiving DNS requests.
        Configures socket options like packet size, timeouts, and worker count.
        Initializes the request queue for incoming DNS packets.
        """
        if cls._is_init:
            raise RuntimeError("Already init")

        cls._host: str = host
        cls._port: int = port
        cls._msg_size: int = msg_size
        cls._queue_get_timeout: float = queue_get_timeout
        cls._external_timeout: float = external_timeout
        cls._max_workers: int = max_workers
        cls._dns_socket = socket(AF_INET, SOCK_DGRAM)
        cls._dns_socket.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
        cls._dns_socket.setsockopt(SOL_SOCKET, SO_RCVBUF, DNS_SOCKET_OS_BUFFER_SIZE)
        cls._dns_socket.setblocking(False)
        cls._dns_socket.bind((cls._host, cls._port))
        cls._dns_servers: list[str] = dns_servers
        cls._recv_queue = Queue(maxsize=DNS_LOCAL_RECV_QUEUE_SIZE)
        cls._is_init = True

    @classmethod
    def _handle_blacklist(cls, dns_req_message: DNSReqMessage) -> bool:
        """Check if the domain is blacklisted and send a refusal reply if so."""

        if BlacklistService.is_blacklisted(dns_req_message.domain):
            DnsStatsDb.increment(key="request_blacklisted")
            reply: DNSRecord = dns_req_message.dns_message.reply()
            reply.header.rcode = DnsResponseCode.REFUSED
            cls._send_reply(dns_req_message, reply)
            return True

        return False

    @classmethod
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
                reply.header.rcode = DnsResponseCode.NO_ERROR
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
    def _handle_cache_hit(cls, dns_req_message: DNSReqMessage) -> bool:
        """Check if the DNS query result is cached and send the cached reply if found."""

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
    def _handle_external(cls, dns_req_message: DNSReqMessage) -> bool:
        """
        Forward DNS query externally and send the reply if successful.
        Returns: bool: True if the external resolution and reply sending succeeded; False otherwise.
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
    def _handle_server_fail(cls, dns_req_message: DNSReqMessage) -> bool:
        """
        Send a SERVFAIL response to the client for the given DNS message.
        Returns True if reply sent successfully, False otherwise.
        """
        try:
            reply: DNSRecord = dns_req_message.dns_message.reply()
            reply.header.rcode = DnsResponseCode.SERVER_FAILURE
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
                # Wait for the socket to be readable (i.e. data ready to recv), with timeout
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
            _start = monotonic()
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
            DbFlushService.init()
            ExternalResolverService.init()
            LocalResolverService.init()
            BlacklistService.init()
            cls._initialised = True
            # Metrics.init(max_size=METRICS_SAMPLE_BUFFER_SIZE)

    @classmethod
    def start(cls):
        if cls._running:
            raise RuntimeError("Server already running.")
        with cls._lock:
            BlacklistService.start()
            DbFlushService.start()
            ExternalResolverService.start()
            LocalResolverService.start()
            cls._running = True
            dns_logger.info("DNS server started.")

    @classmethod
    def stop(cls):
        if not cls._running:
            raise RuntimeError("Server not running.")
        with cls._lock:
            DbFlushService.stop()
            ExternalResolverService.stop()
            BlacklistService.stop()
            LocalResolverService.stop()
            dns_logger.info("Server stopped.")
            cls._running = False
