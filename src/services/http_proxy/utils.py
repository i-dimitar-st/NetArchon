"""Docstring for src.services.http_proxy.utils."""


from functools import lru_cache
from ipaddress import (
    IPv4Address,
    IPv4Network,
    IPv6Address,
    IPv6Network,
    ip_address,
    ip_network,
)


@lru_cache(maxsize=100)
def extract_hostname(host: bytes | str | None) -> str:
    """Docstring for extract_hostname
    Args:
        host(bytes | str | None): Description.

    Returns:
        str: hostname.

    """
    if not host:
        return ""
    return (
        host.decode("utf-8").lower()
        if isinstance(host, bytes)
        else str(host).lower()
    )

@lru_cache(maxsize=100)
def is_ip_address(ip: str) -> bool:
    """Return True if ip is a valid IPv4 or IPv6 address, else False."""
    try:
        ip_address(ip)
        return True
    except ValueError:
        return False


@lru_cache(maxsize=100)
def is_in_subnet(host: str, proxy_ip: str,subnet:str="24") -> bool:
    """Check if host is in the same /24 subnet as proxy_ip."""
    try:
        host_ip: IPv4Address | IPv6Address = ip_address(host)
        network: IPv4Network | IPv6Network = ip_network(
            address=f"{proxy_ip}/{subnet}",
            strict=False
        )
        return host_ip in network
    except ValueError:
        return False
