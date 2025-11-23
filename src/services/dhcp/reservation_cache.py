from functools import wraps
from threading import RLock

from cachetools import TTLCache

from src.config.config import config

# from libs.libs import TTLCache


DHCP_CONF = config.get("dhcp")
RESERVATION_CACHE = DHCP_CONF.get("reservation_cache")
CACHE_SIZE = int(RESERVATION_CACHE.get("size"))
CACHE_TTL = int(RESERVATION_CACHE.get("ttl"))


def is_init(func):
    """Decorator to ensure the cache is initialized before use."""

    @wraps(func)
    def wrapper(cls, *args, **kwargs):
        if not getattr(cls, "initialized", False):
            raise RuntimeError("Init first")
        if getattr(cls, "cache", None) is None:
            raise RuntimeError("Wrong init Cache cant be none")
        return func(cls, *args, **kwargs)

    return wrapper


class LeaseReservationCache:
    """In-memory IP-to-MAC reservation cache for DHCP.

    Each entry maps an IP address (key) to a MAC address (value).
    Entries expire automatically after a configured TTL, managed internally by TTLCache.
    """

    initialized = False
    _lock = RLock()

    @classmethod
    def init(cls, max_size: int = CACHE_SIZE, ttl: int = CACHE_TTL):
        """Initialize the TTL cache.

        Args:
            max_size: Maximum number of entries.
            ttl: Time-to-live for each entry in seconds.

        """
        with cls._lock:
            if cls.initialized:
                raise RuntimeError("Wrong init already initialized")
            cls.cache: TTLCache = TTLCache(maxsize=max_size, ttl=ttl)
            cls.initialized = True

    @classmethod
    @is_init
    def book(cls, ip: str, mac: str) -> bool:
        """Reserve IP for MAC if not reserved by different MAC."""
        with cls._lock:
            existing_mac = cls.cache.get(ip)
            if existing_mac and existing_mac != mac:
                return False
            cls.cache[ip] = mac
            return True

    @classmethod
    @is_init
    def cancel_booking(cls, ip: str, mac: str) -> bool:
        """Remove reservation if matches."""
        with cls._lock:
            if cls.cache.get(ip) == mac:
                del cls.cache[ip]
                return True
            return False

    @classmethod
    @is_init
    def get_mac_from_ip(cls, ip: str) -> str | None:
        with cls._lock:
            return cls.cache.get(ip)

    @classmethod
    @is_init
    def get_ip_from_mac(cls, mac: str) -> str | None:
        with cls._lock:
            for ip, cached_mac in cls.cache.items():
                if cached_mac == mac:
                    return ip
            return None

    @classmethod
    @is_init
    def get_all_ips(cls) -> list[str] | list:
        with cls._lock:
            return list(cls.cache.keys())

    @classmethod
    @is_init
    def clear(cls):
        with cls._lock:
            cls.cache.clear()
