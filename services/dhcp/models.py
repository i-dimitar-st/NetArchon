from dataclasses import dataclass
from enum import Enum, IntEnum, unique
from time import time

from scapy.layers.dhcp import BOOTP, DHCP
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether
from scapy.packet import Packet

from services.dhcp.utils import (
    extract_dhcp_type_from_packet,
    extract_hostname_from_packet,
    extract_param_req_list,
    extract_req_addr_from_packet,
    extract_server_id_from_dhcp_packet,
)


@unique
class DHCPMessageType(IntEnum):
    """DHCP Lease Type"""

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


@dataclass
class DHCPConfig:
    """
    DHCP Configuratin options
    """

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


@dataclass
class BOOTPOptions:
    """
    Common BOOTP options

    Attributes:
        op (int): Message opcode/type.
            - 1 = BOOTREQUEST (client request)
            - 2 = BOOTREPLY (server reply)
        xid (int): Transaction ID, random number chosen by client.
        flags (int): Flags field (e.g., 0x8000 for broadcast reply).
        chaddr (str): Client hardware address (MAC address), usually in bytes or hex string format.
        yiaddr (str): 'Your' IP address — the IP address assigned to the client.
        siaddr (str): Server IP address — address of the DHCP server sending the reply.
        ciaddr (str): Client IP address (current IP address, if any).
        giaddr (str): Relay agent IP address (usually 0.0.0.0 if none).
    """

    op: int
    xid: int
    flags: int
    chaddr: str
    yiaddr: str
    siaddr: str
    ciaddr: str
    giaddr: str


class DHCPResponseFactory:
    """
    Factory class to generate DHCP response packets.

    Usage:
        1. Initialize the factory once with server/network configuration using `init()`.
        2. Call build() with DHCP message type, IP, and request to get response packets.

    Dependencies:
        - Requires Scapy for packet construction (`Ether`, `IP`, `UDP`, `BOOTP`, `DHCP`).
        - Expects a `DHCPType` enum or constants to define DHCP message types (NAK, ACK, OFFER).
        - `request_packet` must contain valid BOOTP and UDP layers.
        - IP addresses must be valid IPv4 strings.

    Notes:
        - Must call `initialize()` before `build()`, otherwise RuntimeError is raised.
        - Handles basic DHCP options for NAK, ACK, and OFFER message types.
    """

    _config: DHCPConfig | None = None

    @classmethod
    def init(
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
        """
        Init class
        """
        cls._config = DHCPConfig(
            server_ip=server_ip,
            server_mac=server_mac,
            port=port,
            broadcast_mac=broadcast_mac,
            broadcast_ip=broadcast_ip,
            lease_time=lease_time,
            flags=flags,
            subnet_mask=subnet_mask,
            router=router,
            name_server=name_server,
            renewal_time=renewal_time,
            rebinding_time=rebinding_time,
            mtu=mtu,
        )

    @classmethod
    def build(cls, dhcp_type: int, your_ip: str, request_packet: Packet) -> Packet:
        """Build and return a DHCP response packet using the assigned IP request."""

        if not cls._config:
            raise RuntimeError("not initialized")

        _cfg: DHCPConfig | None = cls._config

        _bootp_opts = BOOTPOptions(
            op=2,
            xid=request_packet[BOOTP].xid,
            chaddr=request_packet[BOOTP].chaddr[:6] + b"\x00" * 10,
            ciaddr=request_packet[BOOTP].ciaddr,
            yiaddr=your_ip,
            siaddr=_cfg.server_ip,
            giaddr="0.0.0.0",
            flags=_cfg.flags,
        )

        return (
            Ether(src=_cfg.server_mac, dst=_cfg.broadcast_mac)
            / IP(src=_cfg.server_ip, dst=_cfg.broadcast_ip)
            / UDP(sport=_cfg.port, dport=request_packet[UDP].sport)
            / BOOTP(**_bootp_opts.__dict__)
            / DHCP(options=cls._build_dhcp_opts(dhcp_type))
        )

    @classmethod
    def _build_dhcp_opts(cls, dhcp_type: int) -> list:
        """Create DHCP options list corresponding to the DHCP message type."""
        if not cls._config:
            raise RuntimeError("not initialized")

        _cfg: DHCPConfig | None = cls._config
        if dhcp_type == DHCPType.NAK:
            return [
                ("message-type", DHCPType.NAK),
                ("server_id", _cfg.server_ip),
                "end",
            ]

        if dhcp_type in (DHCPType.ACK, DHCPType.OFFER):
            return [
                ("message-type", dhcp_type),
                ("server_id", _cfg.server_ip),
                ("subnet_mask", _cfg.subnet_mask),
                ("router", _cfg.router),
                ("name_server", _cfg.name_server),
                ("lease_time", _cfg.lease_time),
                ("renewal_time", _cfg.renewal_time),
                ("rebinding_time", _cfg.rebinding_time),
                ("interface-mtu", _cfg.mtu),
                "end",
            ]

        raise RuntimeError(f"Unknown DHCP type: {dhcp_type}")


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


class DHCPMessage:
    def __init__(self, packet: Packet):
        self.received = time()
        self.packet: Packet = packet
        self.mac: str = packet[Ether].src.lower()
        self.src_ip: str = packet[IP].src
        self.xid: int = packet[BOOTP].xid
        self.chaddr: bytes = packet[BOOTP].chaddr  # hardware address (raw,16 bytes)
        self.yiaddr: str = packet[BOOTP].yiaddr  # 'Your' address (server assigned)
        self.ciaddr: str = packet[BOOTP].ciaddr  # current IP (used in RENEW/REBIND)
        self.giaddr: str = packet[BOOTP].giaddr  # Gateway IP (by relay agents)
        self.dhcp_type: int = extract_dhcp_type_from_packet(packet)
        self.hostname: str = extract_hostname_from_packet(packet)
        self.requested_ip: str = extract_req_addr_from_packet(packet)
        self.server_id: str = extract_server_id_from_dhcp_packet(packet)
        self.param_req_list: list[int] = extract_param_req_list(packet)

    @property
    def dedup_key(self) -> tuple[int, str, int]:
        return (self.xid, self.mac, self.dhcp_type)


@unique
class DHCPLeaseType(str, Enum):
    """Define DHCP lease type"""

    STATIC = "static"
    DYNAMIC = "dynamic"
    MANUAL = "manual"


@dataclass(frozen=True)
class DHCPStatsSchema:
    name: str = "stats"
    columns: frozenset[str] = frozenset(
        {
            "id",
            "start_time",
            "last_updated",
            "received_total",
            "received_malformed",
            "received_discover",
            "received_request",
            "received_decline",
            "received_release",
            "received_inform",
            "sent_total",
            "sent_offer",
            "sent_ack",
            "sent_nak",
        }
    )
    schema: str = """
        CREATE TABLE IF NOT EXISTS stats (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            start_time INTEGER NOT NULL DEFAULT (CAST(strftime('%s','now') AS INTEGER)),
            last_updated INTEGER DEFAULT 0,
            received_total INTEGER DEFAULT 0,
            received_malformed INTEGER DEFAULT 0,
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


@dataclass(frozen=True)
class DHCPLeasesSchema:
    name: str = "leases"
    schema: str = """
        CREATE TABLE IF NOT EXISTS leases (
            mac TEXT PRIMARY KEY,
            ip TEXT NOT NULL,
            hostname TEXT DEFAULT 'unknown',
            timestamp INTEGER NOT NULL,
            expiry_time INTEGER NOT NULL,
            type TEXT DEFAULT 'static'
        )
    """


@dataclass(frozen=True)
class DHCPArpClient:
    mac: str
    ip: str

    def __repr__(self):
        return f"mac='{self.mac}',ip='{self.ip}'"

    def to_dict(self) -> dict:
        return {"mac": self.mac, "ip": self.ip}
