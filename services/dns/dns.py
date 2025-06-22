import time
import json
import queue
import socket
import select
import threading
import random
import fnmatch
from copy import deepcopy
from functools import lru_cache
from collections import deque
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed, TimeoutError
from dnslib import DNSRecord, QTYPE, RR, A
from models.models import DnsMessage, DnsResponseCode
from config.config import config
from services.logger.logger import MainLogger
from services.dns.db import DnsHistoryDb, DnsStatsDb
from services.dns.utils import DNSUtils, Metrics, TTLCache, MRUCache

dns_logger = MainLogger.get_logger(service_name="DNS", log_level="debug")

PATHS = config.get("paths")
DNS_CONFIG = config.get("dns")
ROOT_PATH = Path(PATHS.get("root"))

BLACKLIST_PATH = ROOT_PATH / "config" / "dns_control_list.json"
BLACKLIST_CACHE_SIZE = 100
BLACKLISTS_LOADING_INTERVAL = 30
DB_PATH = ROOT_PATH / PATHS.get("database")
DB_PERSISTENCE_INTERVAL = 30

DNS_SERVERS = DNS_CONFIG.get("dns_servers")
DNS_HOST = DNS_CONFIG.get("host")
DNS_PORT = DNS_CONFIG.get("port")
MSG_SIZE = DNS_CONFIG.get("msg_size")
DNS_SOCKET_RECEIVED_BUFFER_SIZE = 4 * 1024 * 1024
DNS_SOCKET_TIMEOUT = 0.1

EXTERNAL_TIMEOUT = float(DNS_CONFIG.get("external_timeout"))
EXTERNAL_TIMEOUT_BUFFER = 2
LOCAL_TIMEOUT = float(DNS_CONFIG.get("local_timeout"))
CACHE_TTL = int(DNS_CONFIG.get("cache_ttl"))
EXTERNAL_WORKERS = DNS_CONFIG.get("external_workers")
PROCESS_WORKERS = DNS_CONFIG.get("process_workers")
ZONES = DNS_CONFIG.get("zones")
RECEIVED_QUEUE_SIZE = 100
MAX_METRICS_SIZE = 100
MAX_INPUT_DEQUE_SIZE = 100
MAX_CACHE_SIZE = 100


class DbPersistenceService:
    _lock = threading.Lock()

    @classmethod
    def init(cls, interval: int = DB_PERSISTENCE_INTERVAL):
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
        dns_servers: list = DNS_SERVERS,
        max_msg_size: int = MSG_SIZE,
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
    def resolve_external(cls, request: DNSRecord) -> DNSRecord | None:
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
    _dedup_cache = MRUCache(max_size=MAX_INPUT_DEQUE_SIZE)
    _dns_cache = TTLCache(max_size=MAX_CACHE_SIZE, ttl=CACHE_TTL)
    _stop_event = threading.Event()

    @classmethod
    def init(
        cls,
        dns_servers: list = DNS_SERVERS,
        port: int = DNS_PORT,
        host: str = DNS_HOST,
        msg_size: int = MSG_SIZE,
        external_timeout: float = EXTERNAL_TIMEOUT,
        local_timeout: float = LOCAL_TIMEOUT,
        max_workers: int = PROCESS_WORKERS,
    ):

        if cls._is_init:
            raise RuntimeError("Already init")

        with cls._init_lock:
            cls._is_init = True
            cls._host = host
            cls._port = port
            cls._msg_size = msg_size
            cls._local_timeout = local_timeout
            cls._external_timeout = external_timeout
            cls._max_workers = max_workers
            cls._dns_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            cls._dns_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            cls._dns_socket.setsockopt(
                socket.SOL_SOCKET, socket.SO_RCVBUF, DNS_SOCKET_RECEIVED_BUFFER_SIZE
            )
            cls._dns_socket.setblocking(False)
            cls._dns_socket.bind((cls._host, cls._port))
            cls._dns_servers = dns_servers
            cls._recv_queue = queue.Queue(maxsize=RECEIVED_QUEUE_SIZE)

    @classmethod
    def _handle_blacklist(cls, dnsMessage: DnsMessage) -> bool:
        """Check if the domain is blacklisted and send a refusal reply if so."""

        if DomainBlacklistService.is_blacklisted(dnsMessage.domain):
            DnsStatsDb.increment(key='request_blacklisted')
            reply = dnsMessage.dns_message.reply()
            reply.header.rcode = DnsResponseCode.REFUSED
            cls._send_reply(dnsMessage, reply)

            return True

        return False

    @classmethod
    def _handle_local(cls, dnsMessage: DnsMessage, zones: dict = ZONES) -> bool:
        try:
            _hostname_ip = None
            for _zone in zones.keys():

                if not DNSUtils.is_local_query(dnsMessage.domain, _zone.lower()):
                    continue

                if dnsMessage.domain.endswith(_zone.lower()):
                    _hostname = DNSUtils.extract_hostname(dnsMessage.domain, _zone)
                    _hostname_ip = zones[_zone].get(_hostname)
                    if _hostname_ip:
                        break

            if _hostname_ip:
                DnsStatsDb.increment(key='request_local')
                reply = dnsMessage.dns_message.reply()
                reply.header.rcode = DnsResponseCode.NO_ERROR
                reply.add_answer(
                    RR(
                        rname=dnsMessage.dns_message.q.qname,
                        rtype=QTYPE.A,
                        rclass=1,
                        ttl=CACHE_TTL,
                        rdata=A(_hostname_ip),
                    )
                )
                cls._send_reply(dnsMessage, reply)
                return True

        except Exception as err:
            dns_logger.error(f"Failed to handle local query : {str(err)}")

        return False

    @classmethod
    def _handle_cache_hit(cls, dnsMessage: DnsMessage) -> bool:
        _cached_reply = cls._dns_cache.get(dnsMessage.cache_key)
        if _cached_reply:
            DnsStatsDb.increment(key='request_cache_hit')
            cls._send_reply(dnsMessage, _cached_reply)
            return True
        DnsStatsDb.increment(key='request_cache_miss')
        return False

    @classmethod
    def _handle_external(cls, dnsMessage: DnsMessage) -> bool:
        """
        Forward DNS query externally and send the reply if successful.
        Returns: bool: True if the external resolution and reply sending succeeded; False otherwise.
        """

        try:
            reply = DNSExternalResolverService.resolve_external(dnsMessage.dns_message)
            if reply:
                DnsStatsDb.increment('request_external')
                cls._dns_cache.add(key=dnsMessage.cache_key, ttl=dnsMessage.ttl, value=reply)
                cls._send_reply(dnsMessage, reply)
                return True

        except Exception as err:
            dns_logger.error(f"External resolution failed: {str(err)}")
            DnsStatsDb.increment('request_external_failed')

        return False

    @classmethod
    def _handle_server_fail(cls, dnsMessage: DnsMessage) -> bool:
        """
        Send a SERVFAIL response to the client for the given DNS message.
        Returns True if reply sent successfully, False otherwise.
        """
        try:
            reply = dnsMessage.dns_message.reply()
            reply.header.rcode = DnsResponseCode.SERVER_FAILURE
            cls._send_reply(dnsMessage, reply)
            return True
        except Exception as _err:
            dns_logger.error(f"Failed to send SERVFAIL:{str(_err)}.")
            return False

    @classmethod
    def _send_reply(cls, dnsMessage: DnsMessage, reply: DNSRecord):
        """Send DNS response to the message holder."""

        try:
            DnsStatsDb.increment(key="response_total")
            reply.header.id = dnsMessage.dns_message.header.id
            with cls._dns_socket_lock:
                if cls._dns_socket:
                    cls._dns_socket.sendto(reply.pack(), dnsMessage.addr)

        except Exception as _err:
            dns_logger.error(f"Failed to send reply to {dnsMessage.addr} {str(_err)}.")

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
                        cls._recv_queue.put_nowait(DnsMessage(data, addr))
            except queue.Full:
                dns_logger.warning("Receive queue full.")
            except Exception as err:
                dns_logger.error(f"Error reading from DNS socket:{str(err)}.")

    @classmethod
    def _process_packets(cls):
        while not cls._stop_event.is_set():
            _start = time.monotonic()
            try:
                _dnsMessage: DnsMessage = cls._recv_queue.get(timeout=cls._local_timeout)
            except queue.Empty:
                continue

            try:
                if (
                    not _dnsMessage.is_query
                    or not _dnsMessage.is_domain_valid
                    or cls._dedup_cache.is_present(_dnsMessage.dedup_key)
                ):
                    continue

                DnsStatsDb.increment(key='request_total')

                if cls._handle_blacklist(_dnsMessage):
                    continue

                cls._dedup_cache.add(_dnsMessage.dedup_key)

                DnsHistoryDb.add_query(_dnsMessage.domain)
                DnsStatsDb.increment(key='request_valid')

                if cls._handle_cache_hit(_dnsMessage):
                    continue
                if cls._handle_local(_dnsMessage, ZONES):
                    continue
                if cls._handle_external(_dnsMessage):
                    continue
                cls._handle_server_fail(_dnsMessage)

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
                _worker_thread = threading.Thread(target=cls._process_packets, daemon=True)
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
    def _init(cls):
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
            Metrics.init(max_size=MAX_METRICS_SIZE)

    @classmethod
    def start(cls):
        if not cls._initialised:
            cls._init()
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
