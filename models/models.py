from dataclasses import dataclass
from enum import Enum, IntEnum, unique
from time import time

from dnslib import DNSRecord
from scapy.layers.inet import IP
from scapy.layers.l2 import Ether
from scapy.packet import Packet

from utils.dhcp_utils import DHCPUtilities
from utils.dns_utils import DNSUtils


@unique
class DNSResponseCode(IntEnum):
    """DnsResponseCode"""

    NO_ERROR = 0
    FORMAT_ERROR = 1
    SERVER_FAILURE = 2
    NAME_ERROR = 3
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
        return f"request_type_{self.name.lower()}"


class DNSReqMessage:
    """DNSReqMessage"""

    def __init__(self, raw: bytes, addr: tuple):
        self.received = time()
        self.raw: bytes = raw
        self.addr = addr
        self.error: str | None = None
        self.is_query: bool = False
        self.domain: str = ""
        self.cache_key: tuple = ()
        self.dedup_key: tuple = ()
        self.is_blacklisted: bool = False
        self.is_domain_valid: bool = False

        try:
            self.dns_message: DNSRecord = self._parse_dns(raw)
            self.is_query = self._is_query(self.dns_message)
            self.domain = DNSUtils.normalize_domain(str(self.dns_message.q.qname))
            self.is_domain_valid = DNSUtils.is_valid_domain(self.domain)
            self.cache_key = DNSUtils.generate_cache_key(self.dns_message)
            self.dedup_key = self._generate_dedup_key(self.dns_message, self.addr)
        except Exception as err:
            self.error = str(err)

    @staticmethod
    def _parse_dns(raw: bytes) -> DNSRecord:
        return DNSRecord.parse(raw)

    @staticmethod
    def _is_query(dns_message: DNSRecord) -> bool:
        return dns_message.header.qr == 0

    @staticmethod
    def _generate_dedup_key(dns_message: DNSRecord, addr: tuple) -> tuple:
        return (
            dns_message.q.qname,
            dns_message.q.qtype,
            dns_message.header.id,
            addr[0],
        )


@unique
class LogLevel(Enum):
    """LogLevel"""

    DEBUG = 10
    INFO = 20
    WARNING = 30
    ERROR = 40
    CRITICAL = 50

    @classmethod
    def _missing_(cls, value):
        """Handle cases where a value passed to the Enum is not found among its members"""
        if isinstance(value, str):
            value = value.strip().upper()
            for member in cls:
                if member.name == value:
                    return member
        return cls.DEBUG  # fallback


class DBSchemas:
    dhcpStats = """
        CREATE TABLE IF NOT EXISTS stats (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            start_time INTEGER NOT NULL DEFAULT (CAST(strftime('%s','now') AS INTEGER)),
            last_updated INTEGER DEFAULT 0,
            received_total INTEGER DEFAULT 0,
            received_total_valid INTEGER DEFAULT 0,
            received_discover INTEGER DEFAULT 0,
            received_request INTEGER DEFAULT 0,
            received_decline INTEGER DEFAULT 0,
            received_release INTEGER DEFAULT 0,
            received_inform INTEGER DEFAULT 0,
            sent_total INTEGER DEFAULT 0,
            sent_offer INTEGER DEFAULT 0,
            sent_ack INTEGER DEFAULT 0,
            sent_nak INTEGER DEFAULT 0
        )
    """
    dhcpLeases = """
        CREATE TABLE IF NOT EXISTS leases (
            mac TEXT PRIMARY KEY,
            ip TEXT NOT NULL,
            hostname TEXT DEFAULT 'unknown',
            timestamp INTEGER NOT NULL,
            expiry_time INTEGER NOT NULL,
            type TEXT DEFAULT 'static'
        )
    """
    dnsHistory: str = """
        CREATE TABLE IF NOT EXISTS history (
            query TEXT NOT NULL PRIMARY KEY,
            query_counter INTEGER NOT NULL DEFAULT 0,
            created INTEGER NOT NULL
        )
    """
    dnsStats: str = """
        CREATE TABLE IF NOT EXISTS stats (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            start_time INTEGER NOT NULL DEFAULT (CAST(strftime('%s','now') AS INTEGER)),
            last_updated INTEGER DEFAULT 0,
            request_total INTEGER DEFAULT 0,
            request_local INTEGER DEFAULT 0,
            request_valid INTEGER DEFAULT 0,
            request_blacklisted INTEGER DEFAULT 0,
            request_cache_hit INTEGER DEFAULT 0,
            request_cache_negative_hit INTEGER DEFAULT 0,
            request_cache_miss INTEGER DEFAULT 0,
            request_cache_expired INTEGER DEFAULT 0,
            request_external INTEGER DEFAULT 0,
            request_external_failed INTEGER DEFAULT 0,
            response_total INTEGER DEFAULT 0,
            response_external INTEGER DEFAULT 0,
            response_no_error INTEGER DEFAULT 0,
            response_format_error INTEGER DEFAULT 0,
            response_server_failure INTEGER DEFAULT 0,
            response_name_error INTEGER DEFAULT 0,
            response_not_implemented INTEGER DEFAULT 0,
            response_refused INTEGER DEFAULT 0,
            response_failure INTEGER DEFAULT 0,
            external_total INTEGER DEFAULT 0,
            external_no_error INTEGER DEFAULT 0,
            external_format_error INTEGER DEFAULT 0,
            external_server_failure INTEGER DEFAULT 0,
            external_name_error INTEGER DEFAULT 0,
            external_not_implemented INTEGER DEFAULT 0,
            external_refused INTEGER DEFAULT 0,
            external_failure INTEGER DEFAULT 0
        )
    """


@dataclass(frozen=True)
class ArpClient:
    mac: str
    ip: str

    def __repr__(self):
        return f"mac='{self.mac}',ip='{self.ip}'"

    def to_dict(self) -> dict:
        return {"mac": self.mac, "ip": self.ip}
