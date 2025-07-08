from typing import Optional
from functools import wraps

from config.config import config
from libs.libs import TTLCache

DHCP_CONF = config.get("dhcp")
LEASE_RESERVATION_CACHE = DHCP_CONF.get("lease_reservation_cache")
CACHE_SIZE = int(LEASE_RESERVATION_CACHE.get("size"))
CACHE_TTL = int(LEASE_RESERVATION_CACHE.get("ttl"))


def is_init(func):
    @wraps(func)
    def wrapper(cls, *args, **kwargs):
        if not getattr(cls, "initialized", False):
            raise RuntimeError("Init first")
        return func(cls, *args, **kwargs)

    return wrapper


class LeaseReservationCache:
    _cache: Optional[TTLCache] = None
    initialized = False

    @classmethod
    def init(cls, max_size: int = CACHE_SIZE, ttl: int = CACHE_TTL):
        if cls._cache is not None:
            raise RuntimeError("Cache is not none")
        cls._cache = TTLCache(max_size=max_size, ttl=ttl)
        cls.initialized = True

    @classmethod
    @is_init
    def reserve(cls, ip: str, mac: str) -> bool:
        """
        Reserve IP for MAC if free or reserved by same MAC.
        Return False if IP reserved by different MAC.
        """
        if cls._cache:
            existing_mac = cls._cache.get(ip)
            if existing_mac and existing_mac != mac:
                return False
            cls._cache.add(ip, mac)
        return True

    @classmethod
    @is_init
    def unreserve(cls, ip: str, mac: str):
        """Release IP reservation if reserved by MAC."""
        if cls._cache:
            if cls._cache.get(ip) == mac:
                cls._cache.remove(ip)

    @classmethod
    @is_init
    def get_mac(cls, ip: str) -> Optional[str]:
        """Return MAC reserved on IP or None."""
        if cls._cache:
            return cls._cache.get(ip)

    @classmethod
    @is_init
    def get_ip(cls, mac: str) -> Optional[str]:
        """Return IP reserved by MAC or None."""
        if cls._cache:
            return cls._cache.get_by_value(mac)

    @classmethod
    @is_init
    def get_all_ips(cls) -> list[str]:
        """Return all IPs currently reserved in the cache."""
        if cls._cache:
            return list(cls._cache.keys())
        return []

    @classmethod
    @is_init
    def clear(cls):
        """Clear all IP-MAC reservations from the cache."""
        if cls._cache:
            cls._cache.clear()
