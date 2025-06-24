import re
from dnslib import DNSRecord, DNSLabel


class DNSUtils:
    """DNS utility functions."""

    @staticmethod
    def normalize_domain(domain: str) -> str:
        """Lowercase domain and remove trailing dot."""
        return domain.lower().rstrip('.')

    @staticmethod
    def is_local_query(query: str, zone: str = "home.local") -> bool:
        """Check if query is in local zone."""
        _zone: str = re.escape(zone.lower())
        return bool(re.match(rf"^[a-z0-9-]+\.{_zone}$", query.lower()))

    @staticmethod
    def extract_hostname(query: str, zone: str = "home.local") -> str:
        """Check if query is in local zone."""
        return query[: -(len(zone) + 1)]  # +1 the .home.lan the first .

    @staticmethod
    def is_valid_domain(domain: str) -> bool:
        """Validate domain format."""
        if not domain or len(domain) > 253:
            return False
        for label in domain.split("."):
            if not label:
                return False
            if len(label) > 63:
                return False
            if not re.match(r"^[a-zA-Z0-9-_]+$", label):
                return False
            if label.startswith("-") or label.endswith("-"):
                return False
        return True

    @staticmethod
    def extract_ttl(reply: DNSRecord) -> int:
        """Extract TTL from Records"""
        if reply.rr:
            _ttls: list[int] = [int(rr.ttl) for rr in reply.rr]
            return min(_ttls)
        return 0

    @staticmethod
    def generate_cache_key(reply: DNSRecord) -> tuple[DNSLabel, int]:
        """Generate Cache Key"""
        return (reply.q.qname, reply.q.qtype)
