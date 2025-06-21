import re
import time
import threading
from typing import Optional, Tuple, Any
from collections import deque, OrderedDict
from dnslib import DNSRecord, DNSLabel


TTL_MAX_SIZE = 100
TTL_DEFAULT = 600
MRU_MAX_sIZE = 100


class DNSUtils:
    """DNS utility functions."""

    @staticmethod
    def normalize_domain(domain: str) -> str:
        """Lowercase domain and remove trailing dot."""
        return domain.lower().rstrip('.')

    @staticmethod
    def is_local_query(query: str, zone: str = "home.local") -> bool:
        """Check if query is in local zone."""
        _zone = re.escape(zone.lower())
        return bool(re.match(rf"^[a-z0-9-]+\.{_zone}$", query.lower()))

    @staticmethod
    def extract_hostname(query: str, zone: str = "home.local") -> str:
        """Check if query is in local zone."""
        return query[:-(len(zone) + 1)]  # +1 the .home.lan the first .

    @staticmethod
    def is_valid_domain(domain: str) -> bool:
        """Validate domain format."""
        if not domain or len(domain) > 253:
            return False
        for label in domain.split("."):
            if not label:
                return False
            if len(label) > 63:
                return False
            if not re.match(r"^[a-zA-Z0-9-_]+$", label):
                return False
            if label.startswith("-") or label.endswith("-"):
                return False
        return True

    @staticmethod
    def extract_ttl(reply: DNSRecord) -> int:
        """Extract TTL from Records"""
        return min(
            (int(rr.ttl) for rr in reply.rr),
            default=0)

    @staticmethod
    def generate_cache_key(reply: DNSRecord) -> tuple[DNSLabel, int]:
        """Generate Cache Key"""
        return (reply.q.qname, reply.q.qtype)


class Metrics:
    """Store timing samples and calculate percentiles."""
    _lock = threading.RLock()

    @classmethod
    def init(cls, max_size: int = 100):
        """Set max number of samples stored."""
        with cls._lock:
            cls._max_size = max_size
            cls._samples = deque(maxlen=cls._max_size)

    @classmethod
    def add_sample(cls, duration: float):
        """Add a timing sample."""
        with cls._lock:
            cls._samples.append((time.monotonic(), duration))

    @classmethod
    def get_count(cls) -> int:
        """Return number of samples."""
        with cls._lock:
            return len(cls._samples)

    @classmethod
    def get_percentile(cls, percentile: float) -> float:
        """Get elapsed time at given percentile."""
        with cls._lock:
            if not cls._samples:
                return 0.0
            values = sorted(_sample[1] for _sample in cls._samples)
            _key = int((percentile / 100.0) * (len(values) - 1))
            return values[_key]

    @classmethod
    def get_stats(cls):
        """Print count and some percentile stats."""
        return (f"Counter:{cls.get_count()}, "
                f"5%:{cls.get_percentile(5):.3f}, "
                f"50%:{cls.get_percentile(50):.3f}, "
                f"95%:{cls.get_percentile(95):.3f}.")


class MRUCache:
    """Thread-safe MRU cache with fixed max size (Most Recently Used at front)."""

    def __init__(self, max_size: int = MRU_MAX_sIZE):
        """Initialize the cache with an optional max size."""
        self._lock = threading.RLock()
        self._cache = OrderedDict()
        self._max_size = max_size

    def _remove_oldest(self):
        """Remove oldest (least recently used) item (at end)."""
        self._cache.popitem(last=True)

    def is_present(self, key: tuple) -> bool:
        """Return True if key is in cache."""
        with self._lock:
            return key in self._cache

    def add(self, key: tuple, value=None):
        """Add or update key-value. Evict oldest if full. Move to front."""
        with self._lock:
            if key in self._cache:
                self._cache[key] = value
                self._cache.move_to_end(key, last=False)
            else:
                if len(self._cache) > self._max_size:
                    self._remove_oldest()
                self._cache[key] = value
                self._cache.move_to_end(key, last=False)

    def size(self) -> int:
        """Return number of keys."""
        with self._lock:
            return len(self._cache)

    def clear(self):
        """Clear the cache."""
        with self._lock:
            self._cache.clear()


class TTLCache:
    """Simple, thread-safe, one-directional TTL cache (key → value)."""

    def __init__(self, max_size: int = 100, ttl: int = 60):
        self._lock = threading.RLock()
        self._cache: dict[Any, tuple[Any, float]] = {}  # key → (value, expiry)
        self._max_size = max_size
        self._ttl = ttl

    def add(self, key: Any, value: Any, ttl: Optional[int] = None):
        """Add or update key with TTL. Evict oldest if full."""
        with self._lock:
            self._cleanup_expired()

            if key not in self._cache and len(self._cache) >= self._max_size:
                self._evict_oldest()

            expiry = time.time() + (ttl if ttl and ttl > 0 else self._ttl)
            self._cache[key] = (value, expiry)

    def get(self, key: Any) -> Optional[Any]:
        """Return value if present and not expired; else None."""
        with self._lock:
            self._cleanup_expired()
            item = self._cache.get(key)
            if not item:
                return None
            value, _ = item
            return value

    def get_by_value(self, value: Any) -> Optional[Any]:
        """Return key by value."""
        with self._lock:
            self._cleanup_expired()
            for _key, (_value, _ttl) in self._cache.items():
                if value == _value:
                    return _key
            return None

    def remove(self, key: Any) -> None:
        """Remove key from cache."""
        with self._lock:
            self._cache.pop(key, None)

    def size(self) -> int:
        """Return number of valid items."""
        with self._lock:
            self._cleanup_expired()
            return len(self._cache)

    def clear(self) -> None:
        """Clear entire cache."""
        with self._lock:
            self._cache.clear()

    def keys(self) -> list:
        """Return list of valid keys."""
        with self._lock:
            self._cleanup_expired()
            return list(self._cache.keys())

    def _cleanup_expired(self) -> None:
        """Remove expired entries in-place."""
        _now = time.time()
        for _key in list(self._cache):
            if self._cache[_key][1] < _now:
                self._cache.pop(_key)

    def _evict_oldest(self):
        oldest = min(self._cache.items(), key=lambda x: x[1][1])[0]
        self._cache.pop(oldest)
