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
        self._lock = threading.RLock()
        self._cache = OrderedDict()
        self._max_size = max_size

    def add(self, key: Any, value: Any = None):
        with self._lock:
            if key in self._cache:
                self._cache.move_to_end(key, last=False)
                self._cache[key] = value
            else:
                if len(self._cache) >= self._max_size:
                    self._cache.popitem(last=True)
                self._cache[key] = value
                self._cache.move_to_end(key, last=False)

    def is_present(self, key: Any) -> bool:
        with self._lock:
            return bool(key in self._cache)

    def size(self) -> int:
        with self._lock:
            return len(self._cache)

    def clear(self):
        with self._lock:
            self._cache.clear()


class TTLCache:
    """Simple, thread-safe, one-directional TTL cache (key → value)."""

    def __init__(self, max_size: int = 100, ttl: int = 600):
        self._lock = threading.RLock()
        self._cache: dict[Any, tuple[Any, float]] = {}  # key -> (value, expiry)
        self._max_size = max_size
        self._ttl = ttl

    def add(self, key: Any, value: Any, ttl: Optional[int] = None):
        with self._lock:
            self._cleanup_expired()
            if len(self._cache) >= self._max_size:
                self._evict_oldest()
            expiry = time.time() + (ttl if ttl and ttl > 0 else self._ttl)
            self._cache[key] = (value, expiry)

    def get(self, key: Any) -> Optional[Any]:
        with self._lock:
            self._cleanup_expired()
            item = self._cache.get(key)
            return item[0] if item else None

    def get_by_value(self, value: Any) -> Optional[Any]:
        with self._lock:
            self._cleanup_expired()
            for k, (v, _) in self._cache.items():
                if v == value:
                    return k
            return None

    def remove(self, key: Any):
        with self._lock:
            self._cache.pop(key, None)

    def clear(self):
        with self._lock:
            self._cache.clear()

    def _cleanup_expired(self):
        now = time.time()
        keys_to_remove = [k for k, (_, exp) in self._cache.items() if exp < now]
        for k in keys_to_remove:
            self._cache.pop(k, None)

    def _evict_oldest(self):
        oldest_key = min(self._cache.items(), key=lambda item: item[1][1])[0]
        self._cache.pop(oldest_key, None)
