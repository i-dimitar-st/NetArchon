import queue
import select
import socket
import threading
import typing
from _thread import RLock
from enum import IntEnum, unique

from cachetools import TTLCache
from dnslib import DNSLabel, DNSRecord

from src.services.dns.utils import normalize_domain


@unique
class DNSResponseCode(IntEnum):
    """DnsResponseCode"""

    NO_ERROR = 0
    FORMAT_ERROR = 1
    SERVER_FAILURE = 2
    NXDOMAIN = 3
    NOT_IMPLEMENTED = 4
    REFUSED = 5

    def __str__(self) -> str:
        return str(self.value)


@unique
class DNSRequestType(IntEnum):
    """DnsRequestType"""

    A = 1
    NS = 2
    CNAME = 5
    SOA = 6
    PTR = 12
    MX = 15
    TXT = 16
    AAAA = 28
    SRV = 33
    NAPTR = 35
    KX = 36
    CERT = 37
    A6 = 38
    DNAME = 39
    DS = 43
    SSHFP = 44
    RRSIG = 46
    NSEC = 47
    DNSKEY = 48
    NSEC3 = 50
    NSEC3PARAM = 51
    TLSA = 52
    SMIMEA = 53
    HIP = 55
    CDS = 59
    CDNSKEY = 60
    OPENPGPKEY = 61
    SVCB = 64
    HTTPS = 65
    SPF = 99
    EUI48 = 108
    EUI64 = 109
    TKEY = 249
    TSIG = 250
    IXFR = 251
    AXFR = 252
    ANY = 255
    URI = 256
    CAA = 257
    TA = 32768
    DLV = 32769

    def __str__(self) -> str:
        return str(self.value)


class DNSReqMsg:
    """DNSReqMessage"""

    def __init__(self, raw: bytes, addr: tuple):
        self.raw: bytes = raw
        self.addr = addr
        self.dns_message: DNSRecord = DNSReqMsg._parse_dns(raw)
        self.domain: str = normalize_domain(str(self.dns_message.q.qname))
        self.cache_key = DNSReqMsg._generate_cache_key(self.dns_message)
        self.dedup_key = DNSReqMsg._generate_dedup_key(self.dns_message, self.addr)

    @staticmethod
    def _parse_dns(raw: bytes) -> DNSRecord:
        return DNSRecord.parse(raw)

    @staticmethod
    def _generate_dedup_key(dns_message: DNSRecord, addr: tuple) -> tuple:
        return (
            dns_message.q.qname,
            dns_message.q.qtype,
            dns_message.header.id,
            addr[0],
        )

    @staticmethod
    def _generate_cache_key(reply: DNSRecord) -> tuple[DNSLabel, int]:
        """Generate cache key as normalized tuple of (qname string, qtype int).
        Using string rather than DNSLabel to avoid subtle equality/hash issues.

        Args:
            reply (DNSRecord): DNSRecord object
        Returns:
            tuple[DNSLabel, int]: Cache key tuple

        """
        return (reply.q.qname, reply.q.qtype)


class DNSCache:
    def __init__(self, max_size: int, max_ttl: float) -> None:
        self._lock = threading.RLock()
        self._cache = TTLCache(maxsize=max_size, ttl=max_ttl)

    def get(self, key:typing.Any)-> DNSRecord | None:
        with self._lock:
            return self._cache.get(key) or None

    def set(self, key:typing.Any, value:DNSRecord) -> None:
        with self._lock:
            self._cache[key] = value

    def clear(self) -> None:
        with self._lock:
            self._cache.clear()


class DNSMessageQueue:
    def __init__(self, max_size: int = 512) -> None:
        self._queue = queue.Queue(maxsize=max_size)

    def get(self, timeout: float = 0.0) -> typing.Any | None:
        """Retrieve one item from the queue. Returns None if queue is empty."""
        try:
            if timeout > 0:
                return self._queue.get(timeout=timeout)
            else:
                return self._queue.get_nowait()
        except queue.Empty:
            return None

    def set(self, value: typing.Any, timeout: float = 0.0) -> None:
        """Add item to queue; if full, remove oldest items until space is available."""
        while True:
            try:
                if timeout > 0:
                    self._queue.put(value, timeout=timeout)
                else:
                    self._queue.put_nowait(value)
                break
            except queue.Full:
                try:
                    self._queue.get_nowait()
                except queue.Empty:
                    break

    def task_done(self) -> None:
        """Mark one queue item as processed."""
        try:
            self._queue.task_done()
        except ValueError:
            pass

    def drain(self) -> None:
        """Remove all items currently in the queue."""
        while True:
            try:
                self._queue.get_nowait()
            except queue.Empty:
                break


class DnsSocket:
    def __init__(self, host: str = "0.0.0.0", port: int = 53, buffer_size: int = 16_777_216) -> None:
        self._lock: RLock = threading.RLock()
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, buffer_size)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, buffer_size)
        self._sock.setblocking(False)
        self._sock.bind((host, port))
        self._closed = False

    def receive(self,msg_size:int = 1500,timeout: float = 0.005) -> tuple[bytes, tuple[str, int]] | None:
        if self._closed:
            return None
        try:
            readable, _, _ = select.select([self._sock], [], [], timeout)
            if not readable:
                return None
            return self._sock.recvfrom(msg_size)
        except (OSError, ValueError):
            return None

    def send(self, data: bytes, addr: tuple[str, int]) -> None:
        with self._lock:
            if not self._closed:
                self._sock.sendto(data, addr)

    def close(self) -> None:
        with self._lock:
            if not self._closed:
                self._closed = True
                self._sock.close()

