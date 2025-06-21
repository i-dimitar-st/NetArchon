import time
import json
import queue
import socket
import threading
import fnmatch
from functools import lru_cache
from collections import deque
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed, TimeoutError
from dnslib import DNSRecord, QTYPE, RR, A
from models.models import DnsMessage, DnsResponseCode
from services.config.config import config
from services.logger.logger import MainLogger
from services.dns.db import DnsHistoryDb, DnsStatsDb
from services.dns.utils import DNSUtils, Metrics, TTLCache, MRUCache

dns_logger = MainLogger.get_logger(service_name="DNS", log_level="debug")

ROOT = Path(config.get("paths", "root"))
BLACKLIST_PATH = ROOT / config.get("dns", "blacklists")
BLACKLIST_CACHE_SIZE = 4*1024
BLACKLISTS_LOADING_INTERVAL = config.get("database", "blacklists_loading_interval")
DB_PATH = ROOT / config.get("paths", "database")
DB_PERSISTENCE_INTERVAL = config.get("database", "persistence_interval")

DNS_SERVERS = config.get("dns", "dns_servers")
DNS_HOST = config.get("dns", "host")
DNS_PORT = config.get("dns", "port")
MSG_SIZE = config.get("dns", "msg_size")
DNS_SOCKET_RECEIVED_BUFFER_SIZE = 4 * 1024 * 1024
DNS_SOCKET_TIMEOUT = 0.001

EXTERNAL_TIMEOUT = float(config.get("dns", "external_timeout"))
LOCAL_TIMEOUT = float(config.get("dns", "local_timeout"))
CACHE_TTL = int(config.get("dns", "cache_ttl"))
EXTERNAL_WORKERS = config.get("dns", "external_workers")
PROCESS_WORKERS = config.get("dns", "process_workers")
ZONES = config.get("dns", "zones")
RECEIVED_QUEUE_SIZE = 100
MAX_METRICS_SIZE = 100
MAX_INPUT_DEQUE_SIZE = 100
MAX_CACHE_SIZE = 100


class DbPersistenceService:

    @classmethod
    def init(cls, interval: int = DB_PERSISTENCE_INTERVAL):
        cls._stop_event = threading.Event()
        cls._interval = interval
        cls._worker = threading.Thread(target=cls._work, daemon=True)

    @classmethod
    def start(cls):
        if cls._worker is None:
            raise RuntimeError("Init missing")
        if cls._worker.is_alive():
            raise RuntimeError("Error already started")
        cls._stop_event.clear()
        cls._worker.start()
        dns_logger.info("ServicesPersistence started.")

    @classmethod
    def _work(cls):
        while not cls._stop_event.is_set():
            try:
                DnsStatsDb.save_to_disk()
                DnsHistoryDb.save_to_disk()
            except Exception as _err:
                dns_logger.warning(f"Persistence error: {str(_err)}")
            cls._stop_event.wait(cls._interval)

    @classmethod
    def stop(cls):
        cls._stop_event.set()
        if cls._worker:
            cls._worker.join(timeout=1)
        dns_logger.info("ServicesPersistence stopped.")


class BlacklistService:

    @classmethod
    def init(cls, interval: int = BLACKLISTS_LOADING_INTERVAL):
        cls._lock = threading.RLock()
        cls._stop_event = threading.Event()
        cls._blacklists = {"blacklist": set(),
                           "blacklist_rules": set(),
                           "whitelist": set()}
        cls._interval = interval
        cls._worker = threading.Thread(target=cls._work, daemon=True)

    @classmethod
    def start(cls):
        if not cls._worker:
            raise RuntimeError("Init missing")
        if cls._worker.is_alive():
            raise RuntimeError("Error already started")
        cls._worker.start()
        dns_logger.info("Started Control list loader")

    @classmethod
    def stop(cls):
        cls._stop_event.set()
        if cls._worker:
            cls._worker.join(timeout=1)
        dns_logger.info("BlacklistService stopped.")

    @classmethod
    def _work(cls):
        while not cls._stop_event.is_set():
            try:
                with open(BLACKLIST_PATH, "r", encoding="utf-8") as _file_handle:
                    _control_list = json.load(_file_handle)
                    _new = {
                        "blacklist": set(url.strip().lower()
                                         for url in _control_list.get("blacklist", {}).get("urls", [])),
                        "blacklist_rules": set(rule.strip().lower()
                                               for rule in _control_list.get("blacklist", {}).get("rules", [])),
                        "whitelist": set(item.strip().lower()
                                         for item in _control_list.get("whitelist", []))
                    }
                with cls._lock:
                    if _new != cls._blacklists:
                        cls._blacklists = _new
                        dns_logger.info(f"Loaded: "
                                        f"blacklist:{len(_new['blacklist'])}, "
                                        f"blacklist_rules:{len(_new['blacklist_rules'])}, "
                                        f"whitelist:{len(_new['whitelist'])}.")
                        BlacklistService.is_blacklisted.cache_clear()
            except Exception as err:
                dns_logger.error(f"Failed processing control lists {str(err)}.")
            cls._stop_event.wait(cls._interval)

    @staticmethod
    @lru_cache(maxsize=BLACKLIST_CACHE_SIZE)
    def is_blacklisted(qname: str) -> bool:
        if not qname:
            return False
        if qname in BlacklistService._blacklists["blacklist"]:
            return True
        for rule in BlacklistService._blacklists["blacklist_rules"]:
            if rule == "*":
                continue
            if fnmatch.fnmatch(qname, rule):
                return True
        return False


class ForwarderService:
    _rotate_lock = threading.Lock()

    @classmethod
    def init(cls,
             port: int = DNS_PORT,
             timeout: float = EXTERNAL_TIMEOUT,
             dns_servers: list = DNS_SERVERS,
             max_msg_size: int = MSG_SIZE):
        cls._port = port
        cls._dns_servers = deque(dns_servers)
        cls._max_msg_size = max_msg_size
        cls._timeout = timeout

    @classmethod
    def start(cls, max_workers: int = EXTERNAL_WORKERS):
        if not hasattr(cls, "_executor"):
            cls._executor = ThreadPoolExecutor(max_workers=max_workers)

    @classmethod
    def stop(cls):
        if cls._executor:
            cls._executor.shutdown(wait=True, cancel_futures=True)
            cls._executor = None
            dns_logger.info("ForwarderService stopped.")

    @classmethod
    def resolve_external(cls, request: DNSRecord) -> DNSRecord | None:
        if not cls._executor:
            raise RuntimeError("Not init")

        with cls._rotate_lock:
            cls._dns_servers.rotate(1)
            _servers = list(cls._dns_servers)

        _futures = {cls._executor.submit(cls._query_external_dns, request, _ip): _ip
                    for _ip in _servers}

        try:
            for _future in as_completed(_futures, timeout=cls._timeout + 1):
                _ip = _futures[_future]

                try:
                    reply = _future.result()
                    for _future in _futures:
                        _future.cancel()
                    return reply
                except Exception as err:
                    dns_logger.error(f"Error getting DNS reply from {_ip} {str(err)}.")

        except Exception as err:
            dns_logger.error(f"Error waiting for DNS futures: {str(err)}.")

        return None

    @classmethod
    def _query_external_dns(cls, request: DNSRecord, dns_server: str) -> DNSRecord:

        if not request or not dns_server:
            raise ValueError("Missing data or upstream DNS server.")

        with socket.socket(socket.AF_INET, int(socket.SOCK_DGRAM)) as _dns_socket:
            _dns_socket.settimeout(cls._timeout)

            try:
                _dns_socket.sendto(request.pack(), (dns_server, cls._port))
                _reply_raw, _ = _dns_socket.recvfrom(cls._max_msg_size)
                _reply = DNSRecord.parse(_reply_raw)

                if _reply.header.id != request.header.id:
                    raise ValueError(f"Mismatched DNS Transaction ID from {dns_server}.")
                return _reply

            except socket.timeout:
                raise TimeoutError(f"Timeout waiting for response from {dns_server}.")

            except Exception as _err:
                raise RuntimeError(f"Error contacting upstream {dns_server}: {str(_err)}.")


class ResolverService:
    _is_init = False
    _listener_thread = None
    _worker_threads = []
    _init_lock = threading.RLock()
    _startup_lock = threading.RLock()
    _dns_socket_lock = threading.RLock()
    _dedup_cache = MRUCache(max_size=MAX_INPUT_DEQUE_SIZE)
    _dns_cache = TTLCache(max_size=MAX_CACHE_SIZE, ttl=CACHE_TTL)
    _stop_event = threading.Event()

    @classmethod
    def init(cls,
             dns_servers: list = DNS_SERVERS,
             port: int = DNS_PORT,
             host: str = DNS_HOST,
             msg_size: int = MSG_SIZE,
             external_timeout: float = EXTERNAL_TIMEOUT,
             local_timeout: float = LOCAL_TIMEOUT,
             max_processor_thread: int = PROCESS_WORKERS):

        if cls._is_init:
            raise RuntimeError("Already init")

        with cls._init_lock:
            cls._is_init = True
            cls._host = host
            cls._port = port
            cls._msg_size = msg_size
            cls._local_timeout = local_timeout
            cls._external_timeout = external_timeout
            cls._max_processor_thread = max_processor_thread
            cls._dns_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            cls._dns_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            cls._dns_socket.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, DNS_SOCKET_RECEIVED_BUFFER_SIZE)
            cls._dns_socket.setblocking(False)
            cls._dns_socket.bind((cls._host, cls._port))
            cls._dns_servers = dns_servers
            cls._recv_queue = queue.Queue(maxsize=RECEIVED_QUEUE_SIZE)

    @classmethod
    def _handle_blacklist(cls, dnsMessage: DnsMessage) -> bool:
        """Check if the domain is blacklisted and send a refusal reply if so."""

        if BlacklistService.is_blacklisted(dnsMessage.domain):
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
                if DNSUtils.is_local_query(dnsMessage.domain, _zone.lower()):
                    if dnsMessage.domain.endswith(f".{_zone.lower()}"):
                        _hostname = DNSUtils.extract_hostname(dnsMessage.domain, _zone)
                        _hostname_ip = zones[_zone].get(_hostname)
                        if _hostname_ip:
                            break
            if _hostname_ip:
                DnsStatsDb.increment(key='request_local')
                reply = dnsMessage.dns_message.reply()
                reply.header.rcode = DnsResponseCode.NO_ERROR
                reply.add_answer(RR(rname=dnsMessage.dns_message.q.qname,
                                    rtype=QTYPE.A,
                                    rclass=1,
                                    ttl=CACHE_TTL,
                                    rdata=A(_hostname_ip)))
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
            reply = ForwarderService.resolve_external(dnsMessage.dns_message)
            if reply:
                DnsStatsDb.increment('request_external')
                cls._dns_cache.add(key=dnsMessage.cache_key,
                                   ttl=dnsMessage.ttl,
                                   value=reply)
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
                cls._dns_socket.sendto(reply.pack(), dnsMessage.addr)

        except Exception as _err:
            dns_logger.error(f"Failed to send reply to {dnsMessage.addr} {str(_err)}.")

    @classmethod
    def _listen_traffic(cls):
        while not cls._stop_event.is_set():
            try:
                cls._recv_queue.put_nowait(DnsMessage(*cls._dns_socket.recvfrom(cls._msg_size)))
            except BlockingIOError:
                time.sleep(DNS_SOCKET_TIMEOUT)
            except queue.Full:
                dns_logger.warning("Receive queue full.")
            except Exception as err:
                dns_logger.error(f"Error reading from DNS socket:{str(err)}.")

    @classmethod
    def _process_packets(cls):
        while not cls._stop_event.is_set():
            # _start = time.monotonic()
            try:
                _dnsMessage: DnsMessage = cls._recv_queue.get(timeout=cls._local_timeout)
            except queue.Empty:
                continue

            try:
                if (not _dnsMessage.is_query or
                    not _dnsMessage.is_domain_valid or
                        cls._dedup_cache.is_present(_dnsMessage.dedup_key)):
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
                # Metrics.add_sample(time.monotonic()-_start)

    @classmethod
    def start(cls):
        with cls._startup_lock:
            if not cls._is_init:
                raise RuntimeError("Must init")
            cls._stop_event.clear()
            cls._listener_thread = threading.Thread(target=cls._listen_traffic, daemon=True)
            cls._listener_thread.start()
            for _ in range(cls._max_processor_thread):
                _worker_thread = threading.Thread(target=cls._process_packets, daemon=True)
                _worker_thread.start()
                cls._worker_threads.append(_worker_thread)

    @classmethod
    def stop(cls):
        cls._stop_event.set()
        if cls._dns_socket:
            cls._dns_socket.close()
        if cls._listener_thread:
            cls._listener_thread.join(timeout=1)
        for _thread in cls._worker_threads:
            _thread.join(timeout=1)
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
            ForwarderService.init()
            ResolverService.init()
            BlacklistService.init()

            cls._initialised = True
            # Metrics.init(max_size=MAX_METRICS_SIZE)

    @classmethod
    def start(cls):

        if not cls._initialised:
            cls._init()

        if cls._running:
            raise RuntimeError("Server already running.")

        with cls._lock:
            DbPersistenceService.start()
            ForwarderService.start()
            BlacklistService.start()
            ResolverService.start()

            cls._running = True
            dns_logger.info("DNS server started.")

    @classmethod
    def stop(cls):

        if not cls._running:
            raise RuntimeError("Server not running.")

        with cls._lock:
            DbPersistenceService.stop()
            ForwarderService.stop()
            BlacklistService.stop()
            ResolverService.stop()

            dns_logger.info("Server stopped.")
            cls._running = False
