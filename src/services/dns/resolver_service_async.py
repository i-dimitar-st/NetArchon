from asyncio import Queue as QueueAsyncio
from asyncio import new_event_loop, set_event_loop
from pathlib import Path
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
from time import monotonic
from typing import Optional

from cachetools import TTLCache
from dnslib import DNSRecord

from src.config.config import config
from src.libs.libs import MRUCache
from src.models.models import DNSReqMessage, DNSResponseCode
from src.services.dns.blacklist_service import BlacklistService
from src.services.dns.db import DnsQueryHistoryDb, DnsStatsDb
from src.services.dns.external_resolver_async import AsyncExternalResolverService
from src.services.dns.metrics import dns_metrics
from src.services.dns.utils import is_dns_query, is_valid_domain

PATHS = config.get("paths")
ROOT_PATH = Path(PATHS.get("root"))
DB_PATH = ROOT_PATH / PATHS.get("database")

DNS_CONFIG = config.get("dns").get("config")
DNS_HOST = DNS_CONFIG.get("host")
DNS_PORT = DNS_CONFIG.get("port")
DNS_CACHE_TTL = int(DNS_CONFIG.get("cache_ttl", 1200))
DNS_UDP_PACKET_MAX_SIZE = int(DNS_CONFIG.get("udp_max_size", 1232))
DNS_SOCKET_OS_BUFFER_SIZE = int(DNS_CONFIG.get("os_buffer_size", 4194304))

TIMEOUTS = config.get("dns").get("timeouts")
DNS_SOCKET_TIMEOUT = float(TIMEOUTS.get("local_socket", 0.1))
WORKER_JOIN_TIMEOUT = float(TIMEOUTS.get("worker_join", 1))

DNS_STATIC_ZONES = config.get("dns").get("static_zones")

RESOURCE_LIMITS = config.get("dns").get("resource_limits")
LOC_RECV_QUEUE_SIZE = RESOURCE_LIMITS.get("receive_queue_size", 100)
DEDUP_CACHE_SIZE = RESOURCE_LIMITS.get("deduplication_cache_size", 100)
REPLY_CACHE_SIZE = RESOURCE_LIMITS.get("reply_cache_size", 100)


class ResolverServiceAsync:
    """
    Docstring for ResolverServiceAsync

    :var Args: Description
    :var Returns: Description
    :var bool: Description
    """
    _is_init:bool = False
    _stop_event = Event()
    _dns_socket_lock = RLock()

    @classmethod
    def init(cls, logger, host=DNS_HOST, port=DNS_PORT, msg_size=DNS_UDP_PACKET_MAX_SIZE):
        if cls._is_init:
            raise RuntimeError("Already init")
        cls.logger = logger
        cls._host = host
        cls._port = port
        cls._msg_size = msg_size
        cls._async_queue = QueueAsyncio(maxsize=LOC_RECV_QUEUE_SIZE)
        cls._dns_socket = socket(AF_INET, SOCK_DGRAM)
        cls._dns_socket.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
        cls._dns_socket.setsockopt(SOL_SOCKET, SO_RCVBUF, DNS_SOCKET_OS_BUFFER_SIZE)
        cls._dns_socket.setblocking(False)
        cls._dns_socket.bind((cls._host, cls._port))
        cls._dedup_cache = MRUCache(max_size=DEDUP_CACHE_SIZE)
        cls._dns_cache = TTLCache(maxsize=REPLY_CACHE_SIZE, ttl=DNS_CACHE_TTL)
        cls._is_init = True

    @classmethod
    def start(cls):
        if not cls._is_init:
            raise RuntimeError("Must init")
        cls._stop_event.clear()

        cls._recv_thread = Thread(target=cls._listen_thread, daemon=True)
        cls._recv_thread.start()

        cls._async_loop = new_event_loop()
        cls._async_thread = Thread(target=cls._worker_thread, daemon=True)
        cls._async_thread.start()

    @classmethod
    def stop(cls):
        cls._stop_event.set()
        with cls._dns_socket_lock:
            if cls._dns_socket:
                cls._dns_socket.close()
            cls._dns_socket = None

        if cls._recv_thread:
            cls._recv_thread.join(timeout=WORKER_JOIN_TIMEOUT)

        if cls._async_loop:
            cls._async_loop.call_soon_threadsafe(cls._async_queue.put_nowait, None)
            cls._async_loop.call_soon_threadsafe(cls._async_loop.stop)

        if cls._async_thread:
            cls._async_thread.join(timeout=WORKER_JOIN_TIMEOUT)
        cls._is_init = False
        cls.logger.info("DNSResolver stopped.")

    @classmethod
    def _listen_thread(cls, timeout: float = DNS_SOCKET_TIMEOUT):
        while not cls._stop_event.is_set():
            with cls._dns_socket_lock:
                sock = cls._dns_socket
                if sock is None:
                    break
            try:
                rlist, _, _ = select([sock], [], [], timeout)
                if sock in rlist:
                    with cls._dns_socket_lock:
                        if cls._dns_socket is None:
                            break
                        data, addr = cls._dns_socket.recvfrom(cls._msg_size)
                    req_msg = DNSReqMessage(data, addr)
                    cls._async_loop.call_soon_threadsafe(cls._async_queue.put_nowait, req_msg)
            except Exception as e:
                cls.logger.error(f"DNS recvfrom failed: {e}")

    @classmethod
    def _worker_thread(cls):
        set_event_loop(cls._async_loop)
        cls._async_loop.run_until_complete(cls._worker_async_loop())

    @classmethod
    async def _worker_async_loop(cls):
        while not cls._stop_event.is_set():
            req = await cls._async_queue.get()
            if req is None:
                break
            await cls._process_dns_request(req)

    @classmethod
    def _handle_blacklist(cls, dns_req_message: DNSReqMessage) -> bool:
        """Check if the domain is blacklisted and send a refusal reply if so."""
        if BlacklistService.is_blacklisted(dns_req_message.domain):
            reply: DNSRecord = dns_req_message.dns_message.reply()
            reply.header.rcode = DNSResponseCode.REFUSED
            cls._send_reply(dns_req_message, reply)
            return True

        return False

    @classmethod
    def _handle_cache_hit(cls, dns_req_message: DNSReqMessage) -> bool:
        """Is DNS query result cached and send the cached reply if found.
        """
        _cached_reply: Optional[DNSRecord] = cls._dns_cache.get(dns_req_message.cache_key)
        if _cached_reply:
            cls._send_reply(dns_req_message, _cached_reply)
            return True

        return False

    @classmethod
    async def _handle_external(cls, dns_req_message: DNSReqMessage) -> bool:
        """Forward DNS query externally and send the reply if successful.

        Args:
            dns_req_message(DNSReqMessage): DNS request.

        Returns:
            bool: True if the external resolution and reply sending succeeded.

        """
        try:
            response = await AsyncExternalResolverService.resolve_external_async(
                dns_request=dns_req_message.dns_message,
                loop=cls._async_loop
            )
            if response:
                cls._dns_cache[dns_req_message.cache_key] = response
                cls._send_reply(
                    dns_req=dns_req_message,
                    dns_res=response
                )
                return True

        except Exception as err:
            cls.logger.error("External resolution failed: %s", err)

        return False

    @classmethod
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
    def _send_reply(cls,dns_req: DNSReqMessage,dns_res: DNSRecord):
        """Send DNS response to the message holder."""
        try:
            DnsStatsDb.increment(key="response_total")
            dns_res.header.id = dns_req.dns_message.header.id
            with cls._dns_socket_lock:
                if cls._dns_socket:
                    cls._dns_socket.sendto(dns_res.pack(),dns_req.addr)
        except Exception as _err:
            cls.logger.error(f"Failed sending reply to {dns_req.addr} {_err}.")

    @classmethod
    async def _process_dns_request(cls, dns_req_message: DNSReqMessage):
        start = monotonic()
        try:
            DnsStatsDb.increment(key="request_total")
            if not is_dns_query(dns_req_message.dns_message):
                return
            if not is_valid_domain(dns_req_message.domain):
                return
            if cls._dedup_cache.is_present(dns_req_message.dedup_key):
                return

            cls._dedup_cache.add(dns_req_message.dedup_key)
            DnsStatsDb.increment(key="request_valid")

            if cls._handle_blacklist(dns_req_message):
                DnsStatsDb.increment(key="request_blacklisted")
                return

            DnsQueryHistoryDb.add_query(dns_req_message.domain)

            if cls._handle_cache_hit(dns_req_message):
                DnsStatsDb.increment(key="request_cache_hit")
                return

            DnsStatsDb.increment(key="request_cache_miss")

            if await cls._handle_external(dns_req_message):
                DnsStatsDb.increment("request_external")
                return

            DnsStatsDb.increment("request_external_failed")
            cls._handle_server_fail(dns_req_message)

        except Exception as err:
            cls.logger.error(f"Processing error: {err}")
        finally:
            dns_metrics.add_sample((monotonic()-start)*1000)

