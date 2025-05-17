import re
import random
from typing import Optional, List
from concurrent.futures import ThreadPoolExecutor
from scapy.all import IP, UDP, DNS, DNSQR, sr1, DNSRR, Ether


OWN_INTERFACE = 'enp2s0'
DNS_PORT = 53
DNS_TIMEOUT = 2.5
DNS_RETRY = 0
DNS_DEFAULT_SERVER = "1.1.1.1"
DNS_MIN_TTL = 30


def is_valid_external_domain(dns_query: DNSQR) -> bool:
    if not isinstance(dns_query, DNSQR):
        return False

    _qname = dns_query.qname
    if isinstance(_qname, bytes):
        _qname = _qname.decode(errors='ignore')

    # RFC 1035 min one . => 2+ labels
    _regex = re.compile(
    r"^"                              # start
    r"^(?=.{1,253}$)"                 # 1-253 chars
    r"(?!-)"                          # not start -
    r"([A-Za-z0-9-]{1,63}(?<!-)\.)+"  # 1^ lables end with . no trailing - in each
    r"[A-Za-z0-9-]{1,63}(?<!-)\.?"    # label (TLD) with optional trailing dot, no trailing hyphen
    r"$"                              # end
)
    return bool(_regex.fullmatch(_qname))


def is_valid_domain(dns_query: DNSQR) -> bool:
    
    if not isinstance(dns_query, DNSQR):
        return False

    _qname = dns_query.qname
    if isinstance(_qname, bytes):
        _qname = _qname.decode(errors='ignore')

    # RFC 1035 domain pattern
    _regex = re.compile(r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*\.?$")
    # ^(?=.{1,253}$)          => Assert total length between 1 and 253 characters
    # (?!-)                   => Domain must NOT start with a hyphen
    # [A-Za-z0-9-]{1,63}      => First label: 1 to 63 alphanumeric or hyphen chars
    # (?<!-)                  => First label must NOT end with a hyphen
    # (                       => Start of group for additional labels
    #    \.                   => Literal dot separator between labels
    #    (?!-)                => Next label must NOT start with a hyphen
    #    [A-Za-z0-9-]{1,63}   => Label: 1 to 63 alphanumeric or hyphen chars
    #    (?<!-)               => Label must NOT end with a hyphen
    # )*                      => Zero or more additional labels allowed
    # \.?                     => Optional trailing dot for fully qualified domain names (FQDN)
    # $                       => End of string
    return bool(_regex.fullmatch(_qname))


def is_valid_ipv4(ip: str) -> bool:
    if not isinstance(ip, str):
        return False
    return bool(re.compile(r"^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$").match(ip))


def generate_dnsqr(qtype='A', qname='example.com', qclass=1) -> DNSQR:
    return DNSQR(qtype=qtype, qname=qname, qclass=qclass)


def is_valid_response(response: IP) -> bool:
    return bool(
        response is not None
        and response.haslayer(DNS)
        and response[DNS].rcode == 0
        and response[DNS].ancount > 0
    )


def is_empty_response(response: IP) -> bool:
    return bool(
        response is not None
        and response.haslayer(DNS)
        and response[DNS].rcode == 0
        and response[DNS].ancount == 0)


def extract_longest_dnrr_to_dict(dns_resource_records: list[DNSRR]) -> dict:
    best_rr = max(dns_resource_records, key=lambda dns_rr: getattr(dns_rr, 'ttl', 0))
    return {
        "rrname": best_rr.rrname.decode() if isinstance(best_rr.rrname, bytes) else best_rr.rrname,
        "type": best_rr.type,
        "ttl": best_rr.ttl,
        "rclass": best_rr.rclass,
        "rdata": best_rr.rdata
    }


def extract_min_and_max_ttl(dns_resource_records: DNSRR = None) -> tuple:
    if not dns_resource_records:
        return DNS_MIN_TTL,DNS_MIN_TTL
    min_ttl = min((getattr(dns_resource_record, 'ttl', DNS_MIN_TTL) for dns_resource_record in dns_resource_records), default=DNS_MIN_TTL)
    max_ttl = max((getattr(dns_resource_record, 'ttl', DNS_MIN_TTL) for dns_resource_record in dns_resource_records), default=DNS_MIN_TTL)
    return min_ttl, max_ttl


def extract_dnsrr_as_dict(dns_rr: DNSRR) -> dict:
    return {
        "rrname": dns_rr.rrname.decode() if isinstance(dns_rr.rrname, bytes) else dns_rr.rrname,
        "type": dns_rr.type,
        "ttl": dns_rr.ttl,
        "rclass": dns_rr.rclass,
        "rdata": dns_rr.rdata
    }


def extract_longest_dnsrr(dns_resource_records: List[DNSRR]) -> DNSRR:
    return min(dns_resource_records, key=lambda dns_rr: getattr(dns_rr, 'ttl', 0))


class DNSQuery:
    def __init__(self, retry: int = DNS_RETRY, dst_port: int = DNS_PORT, timeout: float = DNS_TIMEOUT, dns_server_ip: str = DNS_DEFAULT_SERVER, interface: str = OWN_INTERFACE):

        if not is_valid_ipv4(dns_server_ip):
            raise ValueError("Invalid IP")

        self.dst_ip = dns_server_ip
        self.src_port = random.randint(1024, 65000)
        self.dst_port = dst_port
        self.dns_id = random.randint(1, 65000)
        self.dns_rd = 1
        self.verbose = 0
        self.retry = retry
        self.timeout = timeout
        self.interface = interface

    def query(self, dns_query: DNSQR) -> IP | None:
        try:

            if not is_valid_external_domain(dns_query):
                return None
            
            response = sr1(
                IP(dst=self.dst_ip) /
                UDP(sport=self.src_port, dport=self.dst_port) /
                DNS(id=self.dns_id, rd=self.dns_rd, qd=dns_query),
                verbose=self.verbose,
                retry=self.retry,
                timeout=self.timeout,
                iface=self.interface
            )

            if is_valid_response(response) or is_empty_response(response):
                return response
            return None

        except Exception as e:
            return None


class DNSQueries:
    def __init__(self, dns_servers: list[str]):
        self.dns_servers = dns_servers

    def query_best_from_multiple_servers(self, dns_query_record: DNSQR) -> IP | None:

        results = {}
        dns_queries = [DNSQuery(dns_server_ip=ip) for ip in self.dns_servers]

        with ThreadPoolExecutor(max_workers=len(self.dns_servers)) as executor:
            futures = {
                dns_query.dst_ip: executor.submit(dns_query.query, dns_query_record)
                for dns_query in dns_queries
            }
            results = {}
            for ip, future in futures.items():
                try:
                    results[ip] = future.result()
                except Exception as e:
                    results[ip] = None

        return self.extract_best_response(results) or self.extract_fallback(results)

    def extract_best_response(self, dns_responses: dict) -> IP | None:

        _best_ttl = 0
        best_response = None

        for response in dns_responses.values():
            if not is_valid_response(response):
                continue
            _ttl_min, _ = extract_min_and_max_ttl(response.an)
            if _ttl_min > _best_ttl:
                _best_ttl = _ttl_min
                best_response: IP = response

        return best_response

    def extract_fallback(self, dns_responses: dict) -> IP | None:

        for response in dns_responses.values():
            if is_empty_response(response):
                return response

        return None
