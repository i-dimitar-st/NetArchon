from cachetools import TTLCache

from config.config import config

DHCP_CONF = config.get("dhcp")
LEASE_RESERVATION_CACHE = DHCP_CONF.get("lease_reservation_cache")
CACHE_SIZE = int(LEASE_RESERVATION_CACHE.get("size"))
CACHE_TTL = int(LEASE_RESERVATION_CACHE.get("ttl"))


class LeaseReservationCache:
    """
    Bidirectional cache for IP <-> MAC with TTL expiration.
    Primaryely it stores IP-to-MAC cache.
    Second cache is stored too ie MAC-to-IP for reverse lookup.
    """

    _ip_to_mac: TTLCache | None = None
    _mac_to_ip: TTLCache | None = None

    @classmethod
    def init(cls, max_size: int = CACHE_SIZE, ttl: int = CACHE_TTL):
        if cls._ip_to_mac is not None or cls._mac_to_ip is not None:
            raise RuntimeError("Cache already initialized")
        cls._ip_to_mac = TTLCache(maxsize=max_size, ttl=ttl)
        cls._mac_to_ip = TTLCache(maxsize=max_size, ttl=ttl)

    @classmethod
    def book(cls, ip: str, mac: str) -> bool:

        if cls._ip_to_mac and cls._mac_to_ip:
            mac = mac.lower()

            existing_mac = cls._ip_to_mac.get(ip)
            existing_ip = cls._mac_to_ip.get(mac)

            if existing_mac and existing_mac.lower() != mac:
                return False

            if existing_ip and existing_ip != ip:
                return False

            cls._ip_to_mac[ip] = mac
            cls._mac_to_ip[mac] = ip

            return True

        raise RuntimeError("Not Init")

    @classmethod
    def cancel_booking(cls, ip: str, mac: str):
        if cls._ip_to_mac and cls._mac_to_ip:
            mac = mac.lower()
            if cls._ip_to_mac.get(ip) == mac:
                cls._ip_to_mac.pop(ip, None)
                cls._mac_to_ip.pop(mac, None)

    @classmethod
    def get_mac_from_ip(cls, ip: str) -> str | None:
        if cls._ip_to_mac:
            return cls._ip_to_mac.get(ip)

    @classmethod
    def get_ip_from_mac(cls, mac: str) -> str | None:
        if cls._mac_to_ip:
            mac = mac.lower()
            return cls._mac_to_ip.get(mac)

    @classmethod
    def get_all_ips(cls) -> list[str]:
        if cls._ip_to_mac:
            return list(cls._ip_to_mac.keys())
        return []

    @classmethod
    def clear(cls):
        if cls._ip_to_mac and cls._mac_to_ip:
            cls._ip_to_mac.clear()
            cls._mac_to_ip.clear()
