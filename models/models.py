from time import time
from ipaddress import IPv4Address
from dataclasses import dataclass
from enum import Enum, unique
from enum import IntEnum
from collections.abc import Sequence
from dnslib import DNSRecord
from utils.dns_utils import DNSUtils
from scapy.packet import Packet
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, UDP
from scapy.layers.dhcp import BOOTP, DHCP
from utils.dhcp_utils import DHCPUtilities


@unique
class DHCPLeaseType(IntEnum):
    DISCOVER = 1
    OFFER = 2
    REQUEST = 3
    DECLINE = 4
    ACK = 5
    NAK = 6
    RELEASE = 7
    INFORM = 8
    FORCE_RENEW = 9
    LEASE_QUERY = 10
    LEASE_UNASSIGNED = 11
    LEASE_UNKNOWN = 12
    LEASE_ACTIVE = 13


@unique
class DnsResponseCode(IntEnum):
    NO_ERROR = 0
    FORMAT_ERROR = 1
    SERVER_FAILURE = 2
    NAME_ERROR = 3
    NOT_IMPLEMENTED = 4
    REFUSED = 5

    def __str__(self) -> int:
        return self.value


@unique
class DnsRequestType(IntEnum):
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


@unique
class LogLevel(Enum):
    DEBUG = 10
    INFO = 20
    WARNING = 30
    ERROR = 40
    CRITICAL = 50

    @classmethod
    def _missing_(cls, value):
        if isinstance(value, str):
            value = value.strip().upper()
            for member in cls:
                if member.name == value:
                    return member
        return cls.DEBUG  # fallback


class DnsServersIpv4(Sequence):
    """
    Holds a validated list of IPv4 DNS server addresses.
    - Validates each address on initialization.
    - Supports iteration and string representation of the server list.
    """

    def __init__(self, servers: list[str]):
        """
        Initialize with a list of IPv4 DNS server strings.
        - No empty servers allowd.
        """
        if not servers or not isinstance(servers, list):
            raise ValueError("Must provide a non-empty list of DNS servers")
        self._servers = []
        for _server in servers:
            if not DnsServersIpv4._is_ipv4_server(_server):
                raise ValueError(f"Invalid IPv4 address: {_server}")
            self._servers.append(_server)

    def __getitem__(self, index: int) -> str:
        """
        Return the DNS server at the specified index.
        """
        return self._servers[index]

    def __repr__(self):
        """
        Return a string representation of the DNS server list.
        """
        return repr(self._servers)

    def __len__(self):
        """
        Return the number of DNS servers stored.
        """
        return len(self._servers)

    @staticmethod
    def _is_ipv4_server(ip: str) -> bool:
        """
        Check if the given string is a valid IPv4 address.
        """
        try:
            IPv4Address(ip)
            return True
        except:
            return False


class DNSReqMessage:
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


class DHCPResponseFactory:
    server_ip: str
    server_mac: str
    port: int
    broadcast_mac: str
    broadcast_ip: str
    lease_time: int
    flags: int
    subnet_mask: str
    router: str
    name_server: str
    renewal_time: int
    rebinding_time: int
    mtu: int

    @classmethod
    def initialize(
        cls,
        server_ip: str,
        server_mac: str,
        port: int,
        broadcast_mac: str,
        broadcast_ip: str,
        lease_time: int,
        flags: int,
        subnet_mask: str,
        router: str,
        name_server: str,
        renewal_time: int,
        rebinding_time: int,
        mtu: int,
    ):
        cls.server_ip = server_ip
        cls.server_mac = server_mac
        cls.port = port
        cls.broadcast_mac = broadcast_mac
        cls.broadcast_ip = broadcast_ip
        cls.lease_time = lease_time
        cls.flags = flags
        cls.subnet_mask = subnet_mask
        cls.router = router
        cls.name_server = name_server
        cls.renewal_time = renewal_time
        cls.rebinding_time = rebinding_time
        cls.mtu = mtu

    @classmethod
    def build(cls, dhcp_type: int, your_ip: str, request_packet: Packet) -> Packet:

        bootp_opts = {
            "op": 2,
            "xid": request_packet[BOOTP].xid,
            "chaddr": request_packet[BOOTP].chaddr[:6] + b"\x00" * 10,
            "yiaddr": your_ip,
            "siaddr": cls.server_ip,
            "flags": cls.flags,
        }

        return (
            Ether(src=cls.server_mac, dst=cls.broadcast_mac)
            / IP(src=cls.server_ip, dst=cls.broadcast_ip)
            / UDP(sport=cls.port, dport=request_packet[UDP].sport)
            / BOOTP(**bootp_opts)
            / DHCP(options=cls._build_dhcp_opts(dhcp_type))
        )

    @classmethod
    def _build_dhcp_opts(cls, dhcp_type: int) -> list:

        if dhcp_type == DHCPType.NAK:
            return [("message-type", DHCPType.NAK), ("server_id", cls.server_ip), "end"]

        elif dhcp_type == DHCPType.ACK:
            return [
                ("message-type", dhcp_type),
                ("server_id", cls.server_ip),
                ("subnet_mask", cls.subnet_mask),
                ("router", cls.router),
                ("name_server", cls.name_server),
                ("lease_time", cls.lease_time),
                ("renewal_time", cls.renewal_time),
                ("rebinding_time", cls.rebinding_time),
                ("interface-mtu", cls.mtu),
                "end",
            ]

        elif dhcp_type == DHCPType.OFFER:
            return [
                ("message-type", dhcp_type),
                ("server_id", cls.server_ip),
                ("subnet_mask", cls.subnet_mask),
                ("router", cls.router),
                ("name_server", cls.name_server),
                ("lease_time", cls.lease_time),
                ("renewal_time", cls.renewal_time),
                ("rebinding_time", cls.rebinding_time),
                ("interface-mtu", cls.mtu),
                "end",
            ]

        else:
            raise RuntimeError(f"Unknown DHCP type: {dhcp_type}")


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
            type TEXT DEFAULT 'dynamic'
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


@unique
class DHCPType(IntEnum):
    DISCOVER = 1
    OFFER = 2
    REQUEST = 3
    DECLINE = 4
    ACK = 5
    NAK = 6
    RELEASE = 7
    INFORM = 8

    def __str__(self) -> str:
        return str(self.value)


class DhcpMessage:
    def __init__(self, packet: Packet):
        self.received = time()
        self.packet: Packet = packet  # Raw Scapy packet
        self.mac: str = packet[Ether].src.lower()
        self.src_ip: str = packet[IP].src  # Source IP of the UDP packet
        self.xid: int = packet[BOOTP].xid  # Transaction ID
        self.chaddr: bytes = packet[BOOTP].chaddr  # hardware address (raw,16 bytes)
        self.yiaddr: str = packet[BOOTP].yiaddr  # 'Your' address (server assigned)
        self.ciaddr: str = packet[BOOTP].ciaddr  # current IP (used in RENEW/REBIND)
        self.giaddr: str = packet[BOOTP].giaddr  # Gateway IP (by relay agents)
        self.dhcp_type: int = DHCPUtilities.extract_dhcp_type_from_packet(packet)
        self.hostname: str = DHCPUtilities.extract_hostname_from_packet(packet)
        self.requested_ip: str = DHCPUtilities.extract_req_addr_from_packet(packet)
        self.server_id: str = DHCPUtilities.extract_server_id_from_dhcp_packet(packet)
        self.param_req_list: list[int] = DHCPUtilities.extract_param_req_list(packet)

    def __str__(self) -> str:
        return "TYPE:%s, XID:%s, MAC:%s, IP_req:%s, HOSTNAME:%s." % (
            self.dhcp_type,
            self.xid,
            self.mac,
            self.requested_ip,
            self.hostname,
        )

    @property
    def dedup_key(self) -> tuple[int, str, int]:
        return (self.xid, self.mac, self.dhcp_type)
