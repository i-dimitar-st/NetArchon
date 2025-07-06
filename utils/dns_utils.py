from re import match
from dnslib import DNSRecord, DNSLabel


class DNSUtils:
    """DNS utility functions."""

    @staticmethod
    def normalize_domain(domain: str) -> str:
        """Lowercase domain and remove trailing dot."""
        return domain.lower().rstrip(".")

    @staticmethod
    def is_local_query(query: str, zone: str = "home.local") -> bool:
        """
        Check if query is in local zone or any subdomain of the zone.
        Matches:
        - exact zone ("home.local")
        - any subdomain ("sub.home.local", "a.b.home.local")
        """
        _query = query.lower().rstrip(".")
        _zone = zone.lower().rstrip(".")
        return _query == _zone or _query.endswith("." + _zone)

    @staticmethod
    def extract_hostname(query: str, zone: str = "home.local") -> str:
        """
        Extract hostname from domain within the zone.
        For example:
        - query = "host.home.local", zone = "home.local" → "host"
        - query = "a.b.home.local", zone = "home.local" → "a.b"
        Returns empty string if query == zone.
        """
        _query = query.lower().rstrip(".")
        _zone = zone.lower().rstrip(".")
        if _query == _zone:
            return ""
        if _query.endswith("." + _zone):
            return _query[: -(len(_zone) + 1)]
        return ""

    @staticmethod
    def is_valid_domain(domain: str) -> bool:
        """
        Validate domain format.

        - Max length 253 chars total.
        - Labels 1–63 chars.
        - Labels only contain letters, digits, and hyphens.
        - Labels cannot start or end with hyphen.
        - No underscores allowed (strict RFC-compliant).
        """
        if not domain or len(domain) > 253:
            return False
        _domain = domain.lower().rstrip(".")
        _labels = _domain.split(".")
        for _label in _labels:
            if not (1 <= len(_label) <= 63):
                return False
            if not match(r"^[a-z0-9-_]+$", _label):
                return False
            if _label.startswith("-") or _label.endswith("-"):
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
        """
        Generate cache key as normalized tuple of (qname string, qtype int).
        Using string rather than DNSLabel to avoid subtle equality/hash issues.
        """
        return (reply.q.qname, reply.q.qtype)
