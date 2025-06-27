import time
import threading
from typing import Optional, Any
from collections import deque, OrderedDict


TTL_MAX_SIZE = 100
TTL_DEFAULT = 600
MRU_MAX_SIZE = 60


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
        return (
            f"Counter:{cls.get_count()}, "
            f"5%:{cls.get_percentile(5):.3f}, "
            f"50%:{cls.get_percentile(50):.3f}, "
            f"95%:{cls.get_percentile(95):.3f}."
        )


class MRUCache:
    """Thread-safe Most Recently Used (MRU) cache."""

    def __init__(self, max_size: int = MRU_MAX_SIZE):
        """Initialize cache with max size."""
        self._lock = threading.RLock()
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
                self._evict_above_limit()

    def _evict_above_limit(self):
        """Remove oldest items if size exceeds limit."""
        with self._lock:
            while len(self._cache) > self._max_size:
                self._cache.popitem(last=True)

    def is_present(self, key: Any) -> bool:
        """Check if key exists."""
        with self._lock:
            return bool(key in self._cache)

    def clear(self):
        """Clear the cache."""
        with self._lock:
            self._cache.clear()


class TTLCache:
    """Simple, thread-safe, one-directional TTL cache (key → value)."""

    def __init__(self, max_size: int = TTL_MAX_SIZE, ttl: int = TTL_DEFAULT):
        """Initialize cache with max size and default TTL."""
        self._lock = threading.RLock()
        self._cache: dict[Any, tuple[Any, float]] = {}  # key -> (value, expiry)
        self._max_size = max_size
        self._ttl = ttl

    def add(self, key: Any, value: Any, ttl: Optional[int] = None):
        """Get value by key or None if expired/missing."""
        with self._lock:
            self._cleanup_expired()
            self._evict_above_limit()
            expiry: float = time.time() + (ttl if ttl and ttl > 0 else self._ttl)
            self._cache[key] = (value, expiry)

    def get(self, key: Any) -> Optional[Any]:
        """Get value by key or None if expired/missing."""

        with self._lock:
            self._cleanup_expired()
            item = self._cache.get(key)
            return item[0] if item else None

    def get_by_value(self, value: Any) -> Optional[Any]:
        """Find key by value or None."""
        with self._lock:
            self._cleanup_expired()
            for k, (v, _) in self._cache.items():
                if v == value:
                    return k
            return None

    def remove(self, key: Any):
        """Remove key from cache."""
        with self._lock:
            self._cache.pop(key, None)

    def clear(self):
        """Clear the cache."""
        with self._lock:
            self._cache.clear()

    def _cleanup_expired(self):
        """Remove expired entries."""
        with self._lock:
            _now = time.time()
            keys_to_remove = [k for k, (_, exp) in self._cache.items() if exp < _now]
            for k in keys_to_remove:
                self._cache.pop(k, None)

    def _evict_above_limit(self):
        """Evict oldest entries if size exceeds limit."""
        with self._lock:
            while len(self._cache) >= self._max_size:
                oldest_key = min(self._cache.items(), key=lambda item: item[1][1])[0]
                self._cache.pop(oldest_key, None)
