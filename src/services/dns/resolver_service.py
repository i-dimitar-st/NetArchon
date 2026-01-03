import pathlib
import threading
import time

from dnslib import DNSRecord

from src.config.config import config
from src.libs.libs import MRUCache
from src.services.dns.blacklist_service import BlacklistService
from src.services.dns.db import DnsQueryHistoryDb, DnsStatsDb
from src.services.dns.external_resolver import ExternalResolverService
from src.services.dns.metrics import (
    dns_metrics,
    dns_metrics_external,
    dns_per_server_metrics,
    received_metrics,
)
from src.services.dns.models import (
    DNSCache,
    DNSMessageQueue,
    DNSReqMsg,
    DNSRequestType,
    DNSResponseCode,
    DnsSocket,
)
from src.services.dns.utils import is_valid_dns_query, is_valid_domain

PATHS = config.get("paths")
ROOT_PATH = pathlib.Path(PATHS.get("root"))
DB_PATH = ROOT_PATH / PATHS.get("database")

DNS_CONFIG = config.get("dns").get("config")
DNS_HOST = str(DNS_CONFIG.get("host","0.0.0.0"))
DNS_PORT = int(DNS_CONFIG.get("port",53))
DNS_CACHE_TTL = int(DNS_CONFIG.get("cache_ttl", 3600))
DNS_UDP_MAX_SIZE = int(DNS_CONFIG.get("udp_max_size", 1232))
DNS_SOCKET_OS_BUFFER_SIZE = int(DNS_CONFIG.get("os_buffer_size", 16777246))


TIMEOUTS = config.get("dns").get("timeouts")
DNS_SOCKET_TIMEOUT = float(TIMEOUTS.get("local_socket", 0.1))
QUEUE_GET_TIMEOUT = float(TIMEOUTS.get("local_queue_get", 0.5))
WORKER_JOIN_TIMEOUT = float(TIMEOUTS.get("worker_join", 1))
LISTEN_SLEEP_TIMEOUT = float(TIMEOUTS.get("listen_pacer", 0.003))
CACHE_PURGE_INTERVAL = int(TIMEOUTS.get("cache_purge_interval", 60))

RESOURCE_LIMITS = config.get("dns").get("resource_limits")
LOC_RECV_QUEUE_SIZE = RESOURCE_LIMITS.get("receive_queue_size", 1000)
DEDUP_CACHE_SIZE = RESOURCE_LIMITS.get("deduplication_cache_size", 100)
REPLY_CACHE_SIZE = RESOURCE_LIMITS.get("cache_size", 1000)

WORKERS_CONFIG = config.get("dns").get("worker_config")
PROCESS_WORKERS = 64 #WORKERS_CONFIG.get("processors", int(0.5/LISTEN_SLEEP_TIMEOUT))

DNS_POS_CACHE = DNSCache(max_size=1024,max_ttl=3600)
DNS_NEG_CACHE = DNSCache(max_size=2048,max_ttl=87600)
DNS_DEDUP_CACHE = MRUCache(max_size=128)
DNS_MSG_QUEUE = DNSMessageQueue(max_size=512)
DNS_LISTENER_SOCKET = DnsSocket(host=DNS_HOST,port=DNS_PORT,buffer_size=DNS_SOCKET_OS_BUFFER_SIZE)


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

    is_running = False
    _stop_event = threading.Event()

    @classmethod
    def init(cls,logger,max_workers: int = PROCESS_WORKERS) -> None:
        """Initialize the local DNS resolver service.

        Binds UDP socket specified host+port to receiving DNS requests.
        Configures socket options like packet size, timeouts, and worker count.
        Initializes the request queue for incoming DNS packets.
        """
        if cls.is_running:
            raise RuntimeError("Stop service before re-init.")
        if not isinstance(max_workers, int) or not (0 < max_workers <= 512):
            raise ValueError(f"Invalid max_workers count: {max_workers}")
        cls.logger = logger
        cls._stop_event.clear()
        cls._max_workers: int = max_workers
        cls._dns_processor_worker = []
        cls.is_init = True


    @classmethod
    def start(cls) -> None:
        """Start listening and processing threads."""
        if cls.is_running:
            raise RuntimeError("Already running.")

        cls._stop_event.clear()

        DNS_POS_CACHE.clear()
        DNS_NEG_CACHE.clear()
        DNS_DEDUP_CACHE.clear()

        cls._dns_processor_worker.clear()
        cls._dns_received_worker = threading.Thread(target=cls._work_listen_traffic, daemon=True)
        cls._dns_received_worker.start()

        for _ in range(cls._max_workers):
            _worker_thread = threading.Thread(target=cls._work_process_dns_packet, daemon=True)
            _worker_thread.start()
            cls._dns_processor_worker.append(_worker_thread)

        cls.is_running = True

    @classmethod
    def stop(cls) -> None:
        """Stop service, close socket, send sentinel to workers, wait for shutdown."""
        if not cls.is_running:
            raise RuntimeError("Already stopped.")
        cls._stop_event.set()

        DNS_LISTENER_SOCKET.close()
        DNS_MSG_QUEUE.drain()

        if cls._dns_received_worker:
            cls._dns_received_worker.join(timeout=WORKER_JOIN_TIMEOUT)

        for _worker in cls._dns_processor_worker:
            _worker.join(timeout=WORKER_JOIN_TIMEOUT)

        cls.is_running = False
        cls.logger.info("DNSResolver stopped.")

    @staticmethod
    def get_or_set_cache(dns_req_message: DNSReqMsg, cache:DNSCache) -> DNSRecord:
        """Get a cached negative DNS reply or generate, cache, and return it.
        Uses walrus operator to avoid computing reply twice.
        """
        _cached: DNSRecord | None = cache.get(dns_req_message.cache_key)
        if not _cached:
            res: DNSRecord = dns_req_message.dns_message.reply()
            cache.set(
                key=dns_req_message.cache_key,
                value=res
            )
            return res
        return _cached

    @classmethod
    def _handle_invalid_domain(cls, dns_req_message: DNSReqMsg) -> bool:
        """Reject requests with an invalid domain name."""
        if not is_valid_domain(dns_req_message.domain):
            reply: DNSRecord = __class__.get_or_set_cache(dns_req_message,DNS_NEG_CACHE)
            reply.header.rcode = DNSResponseCode.NXDOMAIN
            cls._send_reply(dns_req_message, reply)
            DnsStatsDb.increment(key="request_invalid_domain")
            return True
        return False

    @classmethod
    def _handle_unsupported_type(cls, dns_req_message: DNSReqMsg) -> bool:
        """Reject requests with an invalid domain name."""
        if dns_req_message.dns_message.q.qtype == DNSRequestType.AAAA:
            reply: DNSRecord = __class__.get_or_set_cache(dns_req_message,DNS_NEG_CACHE)
            reply.header.rcode = DNSResponseCode.NOT_IMPLEMENTED
            cls._send_reply(dns_req_message, reply)
            DnsStatsDb.increment(key="request_unsupported")
            return True
        return False

    @classmethod
    def _handle_blacklist(cls, dns_req_message: DNSReqMsg) -> bool:
        """Check if the domain is blacklisted and send a refusal reply if so."""
        if BlacklistService.is_blacklisted(dns_req_message.domain):
            reply: DNSRecord = __class__.get_or_set_cache(dns_req_message,DNS_NEG_CACHE)
            reply.header.rcode = DNSResponseCode.NXDOMAIN
            cls._send_reply(dns_req_message, reply)
            DnsStatsDb.increment(key="request_blacklisted")
            return True
        return False

    @classmethod
    def _handle_deduplicate(cls, dns_req_message: DNSReqMsg) -> bool:
        """Check if the domain is blacklisted and send a refusal reply if so."""
        if DNS_DEDUP_CACHE.is_present(dns_req_message.dedup_key):
            DnsStatsDb.increment(key="request_duplicate")
            return True
        DNS_DEDUP_CACHE.add(dns_req_message.dedup_key)
        return False

    @classmethod
    def _handle_cache_hit(cls, dns_req_message: DNSReqMsg) -> bool:
        """Is DNS query result cached and send the cached reply if found."""
        cached_response: DNSRecord | None  = DNS_POS_CACHE.get(dns_req_message.cache_key)
        if cached_response:
            cls._send_reply(dns_req_message, cached_response)
            DnsStatsDb.increment(key="request_cache_hit")
            return True
        return False

    @classmethod
    def _handle_external(cls, dns_req_message: DNSReqMsg) -> bool:
        """Forward DNS query externally and send the reply if successful."""
        try:
            start = time.perf_counter()

            _raw_reply, _server = ExternalResolverService.resolve(dns_req_message)
            if not _raw_reply or not _server:
                return False

            _duration = time.perf_counter() - start
            dns_res: DNSRecord = DNSRecord.parse(_raw_reply)
            cls._send_reply(dns_req_message, dns_res)

            DNS_POS_CACHE.set(key=dns_req_message.cache_key,value=dns_res)

            dns_metrics_external.add_sample(_duration)
            dns_per_server_metrics[_server].add_sample(_duration)
            DnsStatsDb.increment("request_external")
            return True

        except Exception as err:
            cls.logger.warning(f"External resolution failed: {str(err)}.")

        DnsStatsDb.increment("request_external_failed")
        return False


    @classmethod
    def _handle_server_fail(cls, dns_request: DNSReqMsg) -> None:
        """Send a SERVFAIL response to the client for the given DNS message."""
        try:
            reply: DNSRecord = dns_request.dns_message.reply()
            reply.header.rcode = DNSResponseCode.SERVER_FAILURE
            cls._send_reply(dns_request, reply)
            DnsStatsDb.increment("request_failed")

        except Exception as _err:
            cls.logger.error(f"Failed to send SERVFAIL:{str(_err)}.")


    @classmethod
    def _send_reply(cls,dns_req: DNSReqMsg,dns_res: DNSRecord) -> None:
        """Send DNS response to the message holder."""
        try:
                dns_res.header.id = dns_req.dns_message.header.id
                DNS_LISTENER_SOCKET.send(dns_res.pack(),dns_req.addr)
                DnsStatsDb.increment(key="response_total")
        except Exception as err:
            cls.logger.error(f"Failed sending reply to {dns_req.addr} err:{str(err)}.")

    @classmethod
    def _work_listen_traffic(cls, socket_timeout:float=0.005,msg_size:int=DNS_UDP_MAX_SIZE,sleep_timeout: float = LISTEN_SLEEP_TIMEOUT) -> None:
        """Receive UDP packets and enqueue requests."""
        while not cls._stop_event.is_set():
            try:
                cls._stop_event.wait(sleep_timeout)
                _raw_data: tuple[bytes, tuple[str, int]] | None = DNS_LISTENER_SOCKET.receive(msg_size=msg_size, timeout=socket_timeout)
                if _raw_data:
                    data, addr = _raw_data
                    if is_valid_dns_query(data):
                        DNS_MSG_QUEUE.set((data, addr))

            except Exception as err:
                cls.logger.error(f"Error reading from DNS socket: {str(err)}.")
                continue

    @classmethod
    def _work_process_dns_packet(cls,get_timeout:float=0.005) -> None:
        """Worker: dequeue and process DNS requests until sentinel or stop event."""
        while not cls._stop_event.is_set():

            _dns_raw_message: tuple | None = DNS_MSG_QUEUE.get(timeout=get_timeout)
            if _dns_raw_message is None:
                continue

            start = time.perf_counter()
            try:

                received_message:DNSReqMsg = DNSReqMsg(*_dns_raw_message)

                if cls._handle_unsupported_type(received_message):
                    continue
                if cls._handle_invalid_domain(received_message):
                    continue
                if cls._handle_blacklist(received_message):
                    continue
                if cls._handle_deduplicate(received_message):
                    continue

                DnsQueryHistoryDb.add_query(received_message.domain)

                if cls._handle_cache_hit(received_message):
                    continue
                if cls._handle_external(received_message):
                    continue
                cls._handle_server_fail(received_message)

            except Exception as err:
                cls.logger.error(f"Processing error: {str(err)}.")

            finally:
                dns_metrics.add_sample(time.perf_counter()-start)
                received_metrics.add_sample()
                DNS_MSG_QUEUE.task_done()
                DnsStatsDb.increment(key="request_total")


