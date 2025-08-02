from collections import OrderedDict, deque
from functools import wraps
from threading import RLock
from time import monotonic, time
from typing import Any, Optional

from app.config.config import config

LIBS_CONF = config.get("libs")
MRU_MAX_SIZE = LIBS_CONF.get("mru_max_size")
TTL_MAX_SIZE = LIBS_CONF.get("ttl_max_size")
TTL_DEFAULT = LIBS_CONF.get("ttl_default")


class Metrics:
    """Store timing samples and calculate percentiles."""

    _lock = RLock()

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
            cls._samples.append((monotonic(), duration))

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
        """Return count and common percentile stats."""
        return {
            "count": cls.get_count(),
            "p5": cls.get_percentile(5),
            "p50": cls.get_percentile(50),
            "p95": cls.get_percentile(95),
        }

    @classmethod
    def clear(cls):
        """Clear."""
        with cls._lock:
            return cls._samples.clear()


class MRUCache:
    """
    Thread-safe Most Recently Used (MRU) cache.

    The cache stores keys in MRU order internally:
    - Index 0 corresponds to the most recently used (newest) key.
    - The last index corresponds to the oldest key.

    Example:
        adding keys in this order: 'a', 'b', 'c', the internal order is:
        cache => ['c', 'b', 'a']
        adding 'd':
        cache => ['d', 'c', 'b', 'a']
        adding 'a' again (moves to front):
        cache => ['a', 'd', 'c', 'b']
    """

    def __init__(self, max_size: int = MRU_MAX_SIZE):
        """Initialize cache with max size."""
        self._lock = RLock()
        self._cache = OrderedDict()
        self._max_size = max_size

    def add(self, key: Any, value: Any = None):
        """Add or update key and mark as most recently used."""
        with self._lock:
            if key in self._cache:
                self._cache.move_to_end(key, last=False)
            else:
                self._cache[key] = value
                self._cache.move_to_end(key, last=False)  # moves to front => freshest
                self._evict()

    def _evict(self):
        """Remove oldest items if size exceeds limit."""
        with self._lock:
            while len(self._cache) > self._max_size:
                self._cache.popitem(last=True)

    def is_present(self, key: Any) -> bool:
        """Check if key exists."""
        with self._lock:
            return bool(key in self._cache)

    def get(self, key: Any) -> Any:
        """Check if key exists."""
        with self._lock:
            if key:
                return self._cache.get(key)

    def get_keys(self) -> list:
        """Return list of keys in order."""
        with self._lock:
            return list(self._cache.keys())

    def size(self) -> int:
        """Size."""
        with self._lock:
            return len(self._cache)

    def clear(self):
        """Clear the cache."""
        with self._lock:
            self._cache.clear()


def ttl_clean_expired(func):
    """
    Decorator to remove expired cache entries before executing the decorated method.
    Calls the instance's `_clean_expired` method to purge stale items,
    ensuring the cache is up-to-date during the decorated method's operation.
    """

    @wraps(func)
    def wrapper(self, *args, **kwargs):
        self.clean_expired()
        return func(self, *args, **kwargs)

    return wrapper


def ttl_evict(func):
    """
    Decorator to evict oldest cache entries if the cache exceeds its maximum size
    before executing the decorated method.
    Calls the instance's `_evict` method to maintain cache size constraints.
    """

    @wraps(func)
    def wrapper(self, *args, **kwargs):
        self.evict()
        return func(self, *args, **kwargs)

    return wrapper


class TTLCache:
    """Simple, thread-safe, one-directional TTL cache (key → value).
    cache[key] = (value, expiry)
    """

    def __init__(self, max_size: int = TTL_MAX_SIZE, ttl: int = TTL_DEFAULT):
        """Initialize cache with max size and default TTL."""
        self._lock = RLock()
        self._cache: dict[Any, tuple[Any, float]] = {}  # key -> (value, expiry)
        self._max_size: int = max_size
        self._ttl: int = ttl

    def clean_expired(self):
        """Remove expired entries."""
        with self._lock:
            _now = time()
            for key in list(self._cache):
                if self._cache[key][1] < _now:
                    del self._cache[key]

    def evict(self):
        """Evict oldest entries if size exceeds limit."""
        with self._lock:
            sorted_keys = sorted(self._cache, key=lambda k: self._cache[k][1])
            to_evict = int(len(self._cache) - self._max_size + 1)
            if to_evict > 0:
                for key in sorted_keys[:to_evict]:
                    del self._cache[key]

    @ttl_clean_expired
    @ttl_evict
    def add(self, key: Any, value: Any, ttl: Optional[int] = None):
        """Add item, ttl is optinal default assigned if missing."""
        with self._lock:
            expiry: float = time() + (ttl if ttl and ttl > 0 else self._ttl)
            self._cache[key] = (value, expiry)

    @ttl_clean_expired
    def get(self, key: Any) -> Optional[Any]:
        """Get value by key or None if expired/missing."""
        with self._lock:
            item: tuple[Any, float] | None = self._cache.get(key)
            return item[0] if item else None

    @ttl_clean_expired
    def get_by_value(self, value: Any) -> Optional[Any]:
        """Find key by value or None."""
        with self._lock:
            for _key, (_value, _) in self._cache.items():
                if _value == value:
                    return _key
            return None

    @ttl_clean_expired
    def keys(self) -> list[Any]:
        """Return all non-expired keys in the cache."""
        with self._lock:
            return list(self._cache.keys())

    @ttl_clean_expired
    def remove(self, key: Any):
        """Remove key from cache."""
        with self._lock:
            self._cache.pop(key, None)

    def clear(self):
        """Clear cache."""
        with self._lock:
            self._cache.clear()

    @ttl_clean_expired
    def size(self) -> int:
        """Returns cache size."""
        with self._lock:
            return len(self._cache)
