import functools
import re

from dnslib import DNSRecord


def extract_max_ttl(message: DNSRecord) -> float:
    """Return the highest TTL found in any section of the DNSRecord using an iterator."""
    return max(
            (
                rr.ttl
                for section in (message.rr, message.auth, message.ar)
                for rr in section
            ),
            default=0
    )


@functools.lru_cache(maxsize=1024)
def normalize_domain(domain: str) -> str:
    """Lowercase domain and remove trailing dot."""
    return domain.lower().rstrip(".")


def is_valid_dns_query(dns_message_raw:bytes)->bool:
    try:
        return DNSRecord.parse(dns_message_raw).header.qr == 0
    except Exception:
        return False


def is_dns_query_bytes(data: bytes) -> bool:
    """Check if a raw DNS packet is a query by inspecting the QR bit in the header.

    DNS header layout (first 12 bytes):
        0-1   : Transaction ID
        2-3   : Flags (byte 2: QR + opcode + AA + TC + RD, byte 3: RA + Z + RCODE)
        4-5   : QDCOUNT
        6-7   : ANCOUNT
        8-9   : NSCOUNT
        10-11 : ARCOUNT

    QR bit:
        - Most significant bit of byte 2
        - 0 = Query
        - 1 = Response

    Args:
        data (bytes): Raw DNS packet (at least 12 bytes)

    Returns:
        bool: True if the packet is a DNS query, False otherwise

    """
    return (data[2] & 0x80) == 0


def is_dns_query(dns_message:DNSRecord) -> bool:
    """Is DNSRecord a DNS Query."""
    return dns_message and dns_message.header.qr == 0


_LABEL_RE = re.compile(r"[a-z0-9-_]{1,63}$")

@functools.lru_cache(maxsize=1024)
def is_valid_domain(domain: str) -> bool:
    if not domain or len(domain) > 253:
        return False

    labels = domain.lower().rstrip(".").split(".")
    if len(labels) < 2:
        return False

    for label in labels:
        if label.startswith("-") or label.endswith("-"):
            return False
        if not _LABEL_RE.fullmatch(label):
            return False

    return True
