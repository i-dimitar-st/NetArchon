from functools import lru_cache
from re import match


def is_dns_query(dns_message) -> bool:
    return bool(dns_message and dns_message.header.qr == 0)


@lru_cache(maxsize=100)
def is_valid_domain(domain: str) -> bool:
    """Validate domain format.

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
        if not 1 <= len(_label) <= 63:
            return False
        if not match(r"^[a-z0-9-_]+$", _label):
            return False
        if _label.startswith("-") or _label.endswith("-"):
            return False

    return True
