import time
import json
import queue
import socket
import select
import threading
import random
import fnmatch
from typing import Optional
from functools import lru_cache
from collections import deque
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed, TimeoutError
from dnslib import DNSRecord, QTYPE, RR, A
from models.models import DNSReqMessage, DnsResponseCode
from config.config import config
from services.logger.logger import MainLogger
from services.dns.db import DnsHistoryDb, DnsStatsDb
from libs.libs import Metrics, TTLCache, MRUCache
from utils.dns_utils import DNSUtils

dns_logger = MainLogger.get_logger(service_name="DNS", log_level="debug")

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
BLACKLIST_PATH = ROOT_PATH / BLACKLISTS_CONFIG.get("path", "config/dns_control_list.json")
BLACKLIST_CACHE_SIZE = BLACKLISTS_CONFIG.get("cache_size", 100)
BLACKLISTS_LOADING_INTERVAL = BLACKLISTS_CONFIG.get("loading_interval", 30)

TIMEOUTS = config.get("dns").get("timeouts")
DNS_SOCKET_TIMEOUT = float(TIMEOUTS.get("local_socket", 0.1))
EXTERNAL_TIMEOUT = float(TIMEOUTS.get("external_socket", 15))
EXTERNAL_TIMEOUT_BUFFER = float(TIMEOUTS.get("external_socket_buffer", 2))
QUEUE_GET_TIMEOUT = float(TIMEOUTS.get("local_queue_get", 0.5))

DNS_STATIC_ZONES = config.get("dns").get("static_zones")

RESOURCE_LIMITS = config.get("dns").get("resource_limits")
DNS_LOCAL_RECV_QUEUE_SIZE = RESOURCE_LIMITS.get("queues").get("receive", 100)
METRICS_SAMPLE_BUFFER_SIZE = RESOURCE_LIMITS.get("caches").get("metrics_sample_buffer_size", 100)
DNS_DEDUPLICATION_CACHE_SIZE = RESOURCE_LIMITS.get("caches").get("deduplication_cache_size", 100)
DNS_REPLY_CACHE_SIZE = RESOURCE_LIMITS.get("caches").get("reply_cache_size", 100)


class DbPersistenceService:
    _lock = threading.Lock()

    @classmethod
    def init(cls, interval: int = DB_FLUSH_INTERVAL):
        with cls._lock:
            cls._stop_event = threading.Event()
            cls._interval = interval
            cls._worker = threading.Thread(target=cls._work, daemon=True)

    @classmethod
    def start(cls):
        with cls._lock:
            if not hasattr(cls, "_worker") or cls._worker is None:
                raise RuntimeError("Init missing")
            if cls._worker.is_alive():
                raise RuntimeError("Error already started")
            cls._stop_event.clear()
            cls._worker.start()
            dns_logger.info(f"{cls.__name__} started.")

    @classmethod
    def stop(cls):
        with cls._lock:
            cls._stop_event.set()
        worker = None
        with cls._lock:
            worker = cls._worker
        if worker:
            worker.join(timeout=1)
        dns_logger.info(f"{cls.__name__} stopped.")

    @classmethod
    def restart(cls):
        cls.stop()
        with cls._lock:
            cls._worker = threading.Thread(target=cls._work, daemon=True)
            cls._stop_event.clear()
            cls._worker.start()
            dns_logger.info(f"{cls.__name__} restarted.")

    @classmethod
    def _work(cls):
        while not cls._stop_event.is_set():
            try:
                DnsStatsDb.save_to_disk()
                DnsHistoryDb.save_to_disk()
            except Exception as _err:
                dns_logger.warning(f"Persistence error: {str(_err)}")
            cls._stop_event.wait(cls._interval)


class DomainBlacklistService:

    @classmethod
    def init(cls, interval: int = BLACKLISTS_LOADING_INTERVAL):
        cls._lock = threading.Lock()
        with cls._lock:
            cls._stop_event = threading.Event()
            cls._blacklists = {"blacklist": set(), "blacklist_rules": set(), "whitelist": set()}
            cls._interval = interval
            cls._worker = threading.Thread(target=cls._work, daemon=True)

    @classmethod
    def start(cls):
        with cls._lock:
            if not cls._worker:
                raise RuntimeError("Init missing")
            if cls._worker.is_alive():
                raise RuntimeError("Error already started")
            cls._stop_event.clear()
            cls._worker.start()
            dns_logger.info(f"{cls.__name__} started.")

    @classmethod
    def stop(cls):
        with cls._lock:
            cls._stop_event.set()
        if cls._worker:
            cls._worker.join(timeout=1)
        dns_logger.info(f"{cls.__name__} stopped.")

    @classmethod
    def restart(cls):
        cls.stop()
        with cls._lock:
            cls._worker = threading.Thread(target=cls._work, daemon=True)
            cls._stop_event.clear()
            cls._worker.start()
            dns_logger.info(f"{cls.__name__} restarted.")

    @classmethod
    def _work(cls):
        while not cls._stop_event.is_set():
            try:
                with open(BLACKLIST_PATH, "r", encoding="utf-8") as _file_handle:
                    _control_list = json.load(_file_handle)
                    _new = {
                        "blacklist": set(
                            url.strip().lower()
                            for url in _control_list.get("blacklist", {}).get("urls", [])
                        ),
                        "blacklist_rules": set(
                            rule.strip().lower()
                            for rule in _control_list.get("blacklist", {}).get("rules", [])
                        ),
                        "whitelist": set(
                            item.strip().lower() for item in _control_list.get("whitelist", [])
                        ),
                    }
                with cls._lock:
                    if _new != cls._blacklists:
                        cls._blacklists = _new
                        dns_logger.info(
                            f"Loaded: "
                            f"blacklist:{len(_new['blacklist'])}, "
                            f"blacklist_rules:{len(_new['blacklist_rules'])}, "
                            f"whitelist:{len(_new['whitelist'])}."
                        )
                        DomainBlacklistService.is_blacklisted.cache_clear()
            except Exception as err:
                dns_logger.error(f"Failed processing control lists {str(err)}.")
            cls._stop_event.wait(cls._interval)

    @staticmethod
    @lru_cache(maxsize=BLACKLIST_CACHE_SIZE)
    def is_blacklisted(qname: str) -> bool:
        if not qname:
            return False
        if qname in DomainBlacklistService._blacklists["blacklist"]:
            return True
        for rule in DomainBlacklistService._blacklists["blacklist_rules"]:
            if rule == "*":
                continue
            if fnmatch.fnmatch(qname, rule):
                return True
        return False


class DNSExternalResolverService:
    _lock = threading.Lock()

    @classmethod
    def init(
        cls,
        port: int = DNS_PORT,
        timeout: float = EXTERNAL_TIMEOUT,
        timeout_buffer: float = EXTERNAL_TIMEOUT_BUFFER,
        dns_servers: list = EXTERNAL_DNS_SERVERS,
        max_msg_size: int = DNS_UDP_PACKET_MAX_SIZE,
    ):
        cls._port = port
        cls._dns_servers = deque(dns_servers)
        cls._max_msg_size = max_msg_size
        cls._timeout = timeout
        cls._timeout_buffer = timeout_buffer

    @classmethod
    def start(cls, max_workers: int = EXTERNAL_WORKERS):
        with cls._lock:
            if not hasattr(cls, "_executor"):
                cls._executor = ThreadPoolExecutor(max_workers=max_workers)
                dns_logger.info(f"{cls.__name__} started.")

    @classmethod
    def stop(cls):
        with cls._lock:
            if cls._executor:
                cls._executor.shutdown(wait=True, cancel_futures=True)
                cls._executor = None
                dns_logger.info(f"{cls.__name__} stopped.")

    @classmethod
    def restart(cls, max_workers: int = EXTERNAL_WORKERS):
        with cls._lock:
            if cls._executor is not None:
                cls._executor.shutdown(wait=True, cancel_futures=True)
            cls._executor = ThreadPoolExecutor(max_workers=max_workers)
            dns_logger.info(f"{cls.__name__} restarted.")

    @classmethod
    def resolve_external(cls, request: DNSRecord) -> Optional[DNSRecord]:
        if not cls._executor:
            raise RuntimeError("Not init")

        # We want a copy to prevent mutation in multi thread env, then randomize to introduce jitter
        _servers = list(cls._dns_servers)
        random.shuffle(_servers)

        _futures = {}
        for _ip in _servers:
            _future = cls._executor.submit(cls._query_external_dns_server, request, _ip)
            _futures[_future] = _ip

        try:
            # As completed return first completed so we want that and cancel rest
            for _completed in as_completed(_futures, timeout=cls._timeout + cls._timeout_buffer):
                _ip = _futures[_completed]
                try:
                    # We want result collected first, if error is thrown interator waits for the next (and we dont cancel them)
                    reply = _completed.result()
                    for _still_pending in _futures:
                        if _still_pending != _completed:
                            _still_pending.cancel()
                    return reply

                except Exception as err:
                    dns_logger.error(f"Error getting DNS reply from {_ip}:{str(err)}.")

        except Exception as err:
            dns_logger.error(f"Error waiting for DNS futures: {str(err)}.")

        # All failed
        return None

    @classmethod
    def _query_external_dns_server(cls, request: DNSRecord, dns_server: str) -> DNSRecord:

        if not request or not dns_server:
            raise ValueError("Missing data or upstream DNS server.")

        with socket.socket(socket.AF_INET, int(socket.SOCK_DGRAM)) as _dns_socket:
            _dns_socket.settimeout(cls._timeout)

            try:
                _dns_socket.sendto(request.pack(), (str(dns_server), int(cls._port)))
                _reply_raw, _ = _dns_socket.recvfrom(cls._max_msg_size)
                _reply = DNSRecord.parse(_reply_raw)

                if _reply.header.id != request.header.id:
                    raise ValueError(f"Mismatched DNS Transaction ID from {dns_server}.")

                return _reply

            except socket.timeout:
                raise TimeoutError(f"Timeout waiting for response from {dns_server}.")

            except Exception as _err:
                raise RuntimeError(f"Error contacting upstream {dns_server}: {str(_err)}.")


class DNSLocalResolverService:
    _is_init = False
    _listener = None
    _workers = []
    _init_lock = threading.RLock()
    _startup_lock = threading.RLock()
    _dns_socket_lock = threading.RLock()
    _dedup_cache = MRUCache(max_size=DNS_DEDUPLICATION_CACHE_SIZE)
    _dns_cache = TTLCache(max_size=DNS_REPLY_CACHE_SIZE, ttl=DNS_CACHE_TTL)
    _stop_event = threading.Event()

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
        if cls._is_init:
            raise RuntimeError("Already init")
        with cls._init_lock:
            cls._is_init = True
            cls._host = host
            cls._port = port
            cls._msg_size = msg_size
            cls._queue_get_timeout = queue_get_timeout
            cls._external_timeout = external_timeout
            cls._max_workers = max_workers
            cls._dns_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            cls._dns_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            cls._dns_socket.setsockopt(
                socket.SOL_SOCKET, socket.SO_RCVBUF, DNS_SOCKET_OS_BUFFER_SIZE
            )
            cls._dns_socket.setblocking(False)
            cls._dns_socket.bind((cls._host, cls._port))
            cls._dns_servers = dns_servers
            cls._recv_queue = queue.Queue(maxsize=DNS_LOCAL_RECV_QUEUE_SIZE)

    @classmethod
    def _handle_blacklist(cls, dns_req_message: DNSReqMessage) -> bool:
        """Check if the domain is blacklisted and send a refusal reply if so."""

        if DomainBlacklistService.is_blacklisted(dns_req_message.domain):
            DnsStatsDb.increment(key='request_blacklisted')
            reply = dns_req_message.dns_message.reply()
            reply.header.rcode = DnsResponseCode.REFUSED
            cls._send_reply(dns_req_message, reply)

            return True

        return False

    @classmethod
    def _handle_local(cls, dns_req_message: DNSReqMessage, zones: dict = DNS_STATIC_ZONES) -> bool:
        try:
            _hostname_ip = None
            for _zone in zones.keys():

                if not DNSUtils.is_local_query(dns_req_message.domain, _zone.lower()):
                    continue

                if dns_req_message.domain.endswith(_zone.lower()):
                    _hostname = DNSUtils.extract_hostname(dns_req_message.domain, _zone)
                    _hostname_ip = zones[_zone].get(_hostname)
                    if _hostname_ip:
                        break

            if _hostname_ip:
                DnsStatsDb.increment(key='request_local')
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
            dns_logger.error(f"Failed to handle local query : {str(err)}")

        return False

    @classmethod
    def _handle_cache_hit(cls, dns_req_message: DNSReqMessage) -> bool:

        _cached_reply: Optional[DNSRecord] = cls._dns_cache.get(dns_req_message.cache_key)
        if _cached_reply:
            DnsStatsDb.increment(key='request_cache_hit')
            cls._send_reply(dns_req_message, _cached_reply)
            return True

        DnsStatsDb.increment(key='request_cache_miss')
        return False

    @classmethod
    def _handle_external(cls, dns_req_message: DNSReqMessage) -> bool:
        """
        Forward DNS query externally and send the reply if successful.
        Returns: bool: True if the external resolution and reply sending succeeded; False otherwise.
        """

        try:
            dns_res_message: Optional[DNSRecord] = DNSExternalResolverService.resolve_external(
                dns_req_message.dns_message
            )
            if dns_res_message:
                DnsStatsDb.increment('request_external')
                _ttl = DNSUtils.extract_ttl(dns_res_message)
                cls._dns_cache.add(
                    key=dns_req_message.cache_key,
                    ttl=_ttl if _ttl > DNS_CACHE_TTL else DNS_CACHE_TTL,
                    value=dns_res_message,
                )
                cls._send_reply(dns_req_message, dns_res_message)
                return True

        except Exception as err:
            dns_logger.error(f"External resolution failed: {str(err)}")
            DnsStatsDb.increment('request_external_failed')

        return False

    @classmethod
    def _handle_server_fail(cls, dns_req_message: DNSReqMessage) -> bool:
        """
        Send a SERVFAIL response to the client for the given DNS message.
        Returns True if reply sent successfully, False otherwise.
        """
        try:
            reply = dns_req_message.dns_message.reply()
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
            dns_logger.error(f"Failed to send reply to {dns_req_message.addr} {str(_err)}.")

    @classmethod
    def _listen_traffic(cls, timeout: float = DNS_SOCKET_TIMEOUT):
        while not cls._stop_event.is_set():
            try:
                # Wait for the socket to be readable (i.e. data ready to recv), with timeout
                # OS level select()
                if cls._dns_socket:
                    rlist, _wlist, xlist = select.select([cls._dns_socket], [], [], timeout)
                    if cls._dns_socket in rlist:
                        data, addr = cls._dns_socket.recvfrom(cls._msg_size)
                        cls._recv_queue.put_nowait(DNSReqMessage(data, addr))
            except queue.Full:
                dns_logger.warning("Receive queue full.")
            except Exception as err:
                dns_logger.error(f"Error reading from DNS socket:{str(err)}.")

    @classmethod
    def _process_dns_req_packets(cls):
        while not cls._stop_event.is_set():
            _start = time.monotonic()
            try:
                _dns_req_message: DNSReqMessage = cls._recv_queue.get(
                    timeout=cls._queue_get_timeout
                )
            except queue.Empty:
                continue

            try:
                if (
                    not _dns_req_message.is_query
                    or not _dns_req_message.is_domain_valid
                    or cls._dedup_cache.is_present(_dns_req_message.dedup_key)
                ):
                    continue

                DnsStatsDb.increment(key='request_total')

                if cls._handle_blacklist(_dns_req_message):
                    continue

                cls._dedup_cache.add(_dns_req_message.dedup_key)

                DnsHistoryDb.add_query(_dns_req_message.domain)
                DnsStatsDb.increment(key='request_valid')

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
                Metrics.add_sample(time.monotonic() - _start)

    @classmethod
    def start(cls):
        with cls._startup_lock:
            if not cls._is_init:
                raise RuntimeError("Must init")
            cls._stop_event.clear()
            cls._listener = threading.Thread(target=cls._listen_traffic, daemon=True)
            cls._listener.start()
            for _ in range(cls._max_workers):
                _worker_thread = threading.Thread(target=cls._process_dns_req_packets, daemon=True)
                _worker_thread.start()
                cls._workers.append(_worker_thread)

    @classmethod
    def stop(cls):
        cls._stop_event.set()
        with cls._dns_socket_lock:
            if cls._dns_socket:
                try:
                    cls._dns_socket.shutdown(socket.SHUT_RDWR)
                except Exception:
                    pass
                cls._dns_socket.close()
                cls._dns_socket = None
        if cls._listener:
            cls._listener.join(timeout=1)
        for _thread in cls._workers:
            _thread.join(timeout=1)
        cls._workers.clear()
        dns_logger.info("DNSResolver stopped")


class DNSServer:
    _lock = threading.Lock()
    _initialised = False
    _running = False

    @classmethod
    def init(cls):
        with cls._lock:
            if cls._initialised:
                raise RuntimeError("Already Init")
            DnsStatsDb.init()
            DnsHistoryDb.init()
            DbPersistenceService.init()
            DNSExternalResolverService.init()
            DNSLocalResolverService.init()
            DomainBlacklistService.init()
            cls._initialised = True
            Metrics.init(max_size=METRICS_SAMPLE_BUFFER_SIZE)

    @classmethod
    def start(cls):
        if cls._running:
            raise RuntimeError("Server already running.")
        with cls._lock:
            DbPersistenceService.start()
            DNSExternalResolverService.start()
            DomainBlacklistService.start()
            DNSLocalResolverService.start()
            cls._running = True
            dns_logger.info("DNS server started.")

    @classmethod
    def stop(cls):
        if not cls._running:
            raise RuntimeError("Server not running.")
        with cls._lock:
            DbPersistenceService.stop()
            DNSExternalResolverService.stop()
            DomainBlacklistService.stop()
            DNSLocalResolverService.stop()
            dns_logger.info("Server stopped.")
            cls._running = False
