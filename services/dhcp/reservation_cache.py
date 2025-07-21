from functools import wraps

from cachetools import TTLCache

from config.config import config

# from libs.libs import TTLCache


DHCP_CONF = config.get("dhcp")
LEASE_RESERVATION_CACHE = DHCP_CONF.get("lease_reservation_cache")
CACHE_SIZE = int(LEASE_RESERVATION_CACHE.get("size"))
CACHE_TTL = int(LEASE_RESERVATION_CACHE.get("ttl"))


def is_init(func):
    """Decorator to ensure the cache is initialized before use."""

    @wraps(func)
    def wrapper(cls, *args, **kwargs):
        if not getattr(cls, "initialized", False):
            raise RuntimeError("Init first")
        return func(cls, *args, **kwargs)

    return wrapper


class LeaseReservationCache:
    """
    In-memory IP-to-MAC reservation cache for DHCP.

    Each entry maps an IP address (key) to a MAC address (value).
    Entries expire automatically after a configured TTL, managed internally by TTLCache.
    """

    _cache: TTLCache | None = None
    initialized: bool = False

    @classmethod
    def init(cls, max_size: int = CACHE_SIZE, ttl: int = CACHE_TTL):
        """
        Initialize the TTL cache.

        Args:
            max_size: Maximum number of entries.
            ttl: Time-to-live for each entry in seconds.
        """
        if cls._cache is not None:
            raise RuntimeError("Cache is not none")
        cls._cache = TTLCache(maxsize=max_size, ttl=ttl)
        cls.initialized = True

    @classmethod
    @is_init
    def book(cls, ip: str, mac: str) -> bool:
        """Reserve IP for MAC if not reserved by different MAC."""
        if cls._cache is not None:
            existing_mac = cls._cache.get(ip)
            if existing_mac and existing_mac != mac:
                return False
            cls._cache[ip] = mac
        return True

    @classmethod
    @is_init
    def cancel_booking(cls, ip: str, mac: str):
        """Remove reservation if matches."""
        if cls._cache is not None:
            if cls._cache.get(ip) == mac:
                try:
                    del cls._cache[ip]
                except KeyError:
                    pass  # Already removed

    @classmethod
    @is_init
    def get_mac_from_ip(cls, ip: str) -> str | None:
        if cls._cache is not None:
            return cls._cache.get(ip)
        return None

    @classmethod
    @is_init
    def get_ip_from_mac(cls, mac: str) -> str | None:
        if cls._cache is not None:
            for ip, cached_mac in cls._cache.items():
                if cached_mac == mac:
                    return ip
        return None

    @classmethod
    @is_init
    def get_all_ips(cls) -> list[str]:
        if cls._cache is not None:
            return list(cls._cache.keys())
        return []

    @classmethod
    @is_init
    def clear(cls):
        if cls._cache is not None:
            cls._cache.clear()
