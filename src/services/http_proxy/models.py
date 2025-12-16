"""Docstring for src.services.http_proxy.models."""


from enum import Enum, unique

from proxy.http.exception import HttpRequestRejected


@unique
class ProxyStatsType(str,Enum):
    """DHCP message types."""

    PROXY_RECEIVED = "proxy_received"
    PROXY_BAD_REQUEST = "proxy_bad_request"
    PROXY_BLOCKED_HIT = "proxy_blocked_hit"
    PROXY_HIT = "proxy_hit"

    def __str__(self):
        """Return the string representation of the enum value.

        Returns:
            str: The string value associated with the enum member

        """
        return self.value

class HttpRequestRejectedBadRequest(HttpRequestRejected):
    """Exception raised when a client request is invalid or malformed.

    Inherits from HttpRequestRejected and sets a 400 Bad Request response.
    """

    def __init__(self):
        """Initialize the bad request exception.

        Sets:
            status_code (int): 400
            reason (bytes): b"Bad Request"
            headers (dict[bytes, bytes]): Content-Type as text/plain
            body (bytes): Message indicating the host header is missing or invalid
        """
        super().__init__(
            status_code=400,
            reason=b"Bad Request",
            headers={b"Content-Type": b"text/plain"},
            body=b"Host header is missing or invalid."
        )

class HttpRequestRejectedForbidden(HttpRequestRejected):
    """Exception raised when a client request is blocked by the proxy.

    Inherits from HttpRequestRejected and sets a 403 Forbidden response.
    """

    def __init__(self):
        """Initialize the forbidden request exception.

        Sets:
            status_code (int): 403
            reason (bytes): b"Forbidden"
            headers (dict[bytes, bytes]): Content-Type as text/plain
            body (bytes): Message indicating the site is blocked by the proxy
        """
        super().__init__(
            status_code=403,
            reason=b"Forbidden",
            headers={b"Content-Type": b"text/plain"},
            body=b"This site is blocked by the proxy."
        )
