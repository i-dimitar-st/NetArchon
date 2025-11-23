from functools import lru_cache


@lru_cache(maxsize=1024)
def extract_hostname_from_proxy_request(host:bytes | None = None) -> str:
    return (
        host.decode("utf-8").lower()
        if isinstance(host, bytes) else
        str(host).lower()
    ) if host is not None else ""
