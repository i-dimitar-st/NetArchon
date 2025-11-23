"""API request models for GUI service."""

from enum import Enum


class RequestQuery:
    """Structured wrapper around the incoming JSON request.
    Normalizes and validates 'type', 'category', 'resource', and 'payload'.
    """

    def __init__(self, data: dict | None):
        """Initialize RequestQuery from raw data."""
        _data = data or {}

        self.raw = _data
        self.type = RequestType.get(_data.get("type", ""))
        self.category = RequestCategory.get(_data.get("category", ""))
        self.resource = RequestResource.get(_data.get("resource", ""))
        self.payload = _data.get("payload", None)

    @property
    def is_valid(self) -> bool:
        """Check whether the request has valid enums."""
        return (
            self.type != RequestType.UNKNOWN
            and self.category != RequestCategory.UNKNOWN
        )

    @property
    def error_message(self) -> str:
        """Human-readable error for gateway."""
        if self.type == RequestType.UNKNOWN:
            return "Unknown request type"
        if self.category == RequestCategory.UNKNOWN:
            return "Unknown request category"
        return ""


class RequestType(Enum):
    """Request types for API calls."""

    UNKNOWN = "unknown"
    GET = "get"
    ADD = "add"
    REMOVE = "remove"
    CLEAR = "clear"
    TRAIN = "train"
    PREDICT = "predict"

    @staticmethod
    def get(value: str) -> "RequestType":
        """Get RequestType enum from string value.

        Returns:
            RequestType: Corresponding enum or UNKNOWN if invalid.

        """
        try:
            return RequestType(value)
        except ValueError:
            return RequestType.UNKNOWN


class RequestResource(Enum):
    """Request resources for API calls."""

    UNKNOWN = "unknown"
    HISTORY = "history"
    LEASES = "leases"
    STATS = "stats"
    SYSTEM = "system"
    MODEL_AGE = "model-age"
    DATA = "data"

    @staticmethod
    def get(value: str) -> "RequestResource":
        """Get RequestResource enum from string value.

        Returns:
            RequestResource: Corresponding enum or UNKNOWN if invalid.

        """
        try:
            return RequestResource(value)
        except ValueError:
            return RequestResource.UNKNOWN


class RequestCategory(Enum):
    """Request categories for API calls."""

    UNKNOWN = "unknown"
    DASHBOARD = "dashboard"
    BLACKLIST = "blacklist"
    WHITELIST = "whitelist"
    DNS = "dns"
    DHCP = "dhcp"
    NEURAL_NET = "neural-net"
    METRICS = "metrics"
    CONFIG = "config"
    INFO = "info"
    LOGS = "logs"

    @staticmethod
    def get(value: str) -> "RequestCategory":
        """Get RequestCategory enum from string value.

        Returns:
            RequestCategory: Corresponding enum or UNKNOWN if invalid.

        """
        try:
            return RequestCategory(value)
        except ValueError:
            return RequestCategory.UNKNOWN
