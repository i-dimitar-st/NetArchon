import time
from dnslib import DNSRecord, QTYPE, RR, A
from services.dns.utils import DNSUtils
from scapy.packet import Packet
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, UDP
from scapy.layers.dhcp import BOOTP, DHCP


class DnsMessage:
    def __init__(self, raw: bytes, addr: tuple):
        self.received = time.time()
        self.raw = raw
        self.addr = addr
        self.error: str | None = None
        self.is_query: bool = False
        self.domain: str = ""
        self.cache_key: tuple = ()
        self.dedup_key: tuple = ()
        self.is_blacklisted: bool = False
        self.is_domain_valid: bool = False

        try:
            self.dns_message = self._parse_dns(raw)
            self.is_query = self._is_query(self.dns_message)
            self.ttl = DNSUtils.extract_ttl(self.dns_message)
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
        return (dns_message.q.qname,
                dns_message.q.qtype,
                dns_message.header.id,
                addr[0])


class DHCPResponseFactory:

    @classmethod
    def build(
        cls,
        server_ip: str,
        server_mac: str,
        port: int,
        broadcast_mac: str,
        broadcast_ip: str,
        lease_time: int,
        flags: int,
        dhcp_type: int,
        your_ip: str,
        request_packet: Packet,
        subnet_mask: str,
        router: str,
        name_server: str,
        renewal_time: int,
        rebinding_time: int,
        mtu: int,
        domain_name: str = "home.lan"
    ) -> Packet:

        bootp_opts = {
            "op": 2,
            "xid": request_packet[BOOTP].xid,
            "chaddr": request_packet[BOOTP].chaddr[:6] + b"\x00" * 10,
            "yiaddr": your_ip,
            "siaddr": server_ip,
            "flags": flags
        }

        dhcp_opts = cls._build_dhcp_ops(
            dhcp_type=dhcp_type,
            subnet_mask=subnet_mask,
            router=router,
            server_ip=server_ip,
            name_server=name_server,
            lease_time=lease_time,
            renewal_time=renewal_time,
            rebinding_time=rebinding_time,
            mtu=mtu,
            domain=domain_name
        )

        return (
            Ether(src=server_mac, dst=broadcast_mac) /
            IP(src=server_ip, dst=broadcast_ip) /
            UDP(sport=port, dport=request_packet[UDP].sport) /
            BOOTP(**bootp_opts) /
            DHCP(options=dhcp_opts)
        )

    @staticmethod
    def _build_dhcp_ops(
        dhcp_type: int,
        server_ip: str,
        subnet_mask: str,
        router: str,
        name_server: str,
        lease_time: int,
        renewal_time: int,
        rebinding_time: int,
        mtu: int,
        domain: str
    ) -> list:

        if dhcp_type == 6:
            return [
                ("message-type", 6),
                ("server_id", server_ip),
                "end"
            ]

        return [
            ("message-type", dhcp_type),
            ("server_id", server_ip),
            ("subnet_mask", subnet_mask),
            ("router", router),
            ("name_server", name_server),
            ("lease_time", lease_time),
            ("renewal_time", renewal_time),
            ("rebinding_time", rebinding_time),
            ("interface-mtu", mtu),
            # ("domain", domain),
            "end"
        ]


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
    dnsHistory = """
        CREATE TABLE IF NOT EXISTS history (
            query TEXT NOT NULL PRIMARY KEY,
            query_counter INTEGER NOT NULL DEFAULT 0,
            active INTEGER NOT NULL DEFAULT 1,
            created INTEGER NOT NULL
        )
    """
    dnsStats = """
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
            request_type_a INTEGER DEFAULT 0,
            request_type_aaaa INTEGER DEFAULT 0,
            request_type_ptr INTEGER DEFAULT 0,
            request_type_mx INTEGER DEFAULT 0,
            request_type_svcb INTEGER DEFAULT 0,
            request_type_https INTEGER DEFAULT 0,
            request_type_cname INTEGER DEFAULT 0,
            request_type_ns INTEGER DEFAULT 0,
            request_type_soa INTEGER DEFAULT 0,
            request_type_txt INTEGER DEFAULT 0,
            request_type_srv INTEGER DEFAULT 0,
            request_type_any INTEGER DEFAULT 0,
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
