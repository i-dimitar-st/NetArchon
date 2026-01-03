from collections import OrderedDict
from functools import wraps
from multiprocessing import Manager, RLock
from multiprocessing.managers import ListProxy, SyncManager
from pathlib import Path
from threading import RLock
from time import perf_counter, time
from typing import Any, Callable
import itertools

from lupa import LuaRuntime

from src.config.config import config

LIBS_CONF = config.get("libs")
MRU_MAX_SIZE = int(LIBS_CONF.get("mru_max_size"))
METRICS_MAX_SIZE = int(LIBS_CONF.get("metrics_max_size"))
DEFAULT_PERCENTILES: list[int] = [50, 75, 90, 95, 99]
DEFAULT_WINDOWS: list[int] = [30,300,3600]
DEFAULT_WINDOW_MAX_SIZE: int = 1000


lua = LuaRuntime(unpack_returned_tuples=True)
with open(Path(__file__).parent / "libs.lua", "r") as _file_handle:
    lua.execute(_file_handle.read())
lub_compute_percentiles = lua.globals()["compute_percentiles"]
lub_compute_stats = lua.globals()["compute_stats"]


class Metrics:
    """Store timing samples and calculate percentiles (multiprocess-safe)."""

    def __init__(self, max_size: int = METRICS_MAX_SIZE):
        """Initialize with max number of metrics."""
        self._max_size: int = max_size
        self._manager = Manager()
        self._samples = self._manager.list([0.0] * max_size)  # shared list across processes
        self._cycle = itertools.cycle(range(max_size))
        self._lock = self._manager.RLock()    # process-safe lock

    def add_sample(self, duration: float) -> None:
        """Add a timing sample."""
        with self._lock:
            self._samples[next(self._cycle)] = duration

    def get_count(self) -> int:
        """Return number of samples."""
        with self._lock:
            return len(self._samples)

    def get_percentile(self, percentile: float) -> float:
        """Get duration corresponding to the given percentile."""
        if not (0 <= percentile <= 100):
            raise ValueError("Percentile must be between 0 and 100.")
        with self._lock:
            return float(lub_compute_percentiles(lua.table_from(list(self._samples)), [percentile]))

    def get_stats(self, percentiles: list[int] = DEFAULT_PERCENTILES) -> dict:
        """Return percentile stats."""
        with self._lock:
            return {
                percentile: value
                for percentile, value in lub_compute_stats(
                    lua.table_from(list(self._samples)),
                    lua.table_from(percentiles)
                ).items()
            }

    def clear(self) -> None:
        """Clear samples."""
        with self._lock:
            for i in range(self._max_size):
                self._samples[i] = 0.0
            self._filled = 0


class WindowedMetrics:
    """Multiprocess-safe windowed sample counter."""

    def __init__(self, windows:list[int]=DEFAULT_WINDOWS, max_size=DEFAULT_WINDOW_MAX_SIZE) -> None:
        self.windows:list[int] = windows
        self._max_size:int = max_size
        self._manager: SyncManager = Manager()
        self._lock: RLock = self._manager.RLock()
        self._samples: ListProxy[float] = Manager().list()

    def add_sample(self) -> None:
        """Add a sample occurrence."""
        with self._lock:
            if len(self._samples) >= self._max_size:
                del self._samples[0]
            self._samples.append(time())

    def get_results(self) -> dict[int, int]:
        """Return dict of window -> count of samples in that window."""
        output = {}
        with self._lock:
            _now = time()
            for _window in self.windows:
                output[_window] = sum(
                    1
                    for _timestamp in self._samples
                    if _timestamp >= _now - _window
                )
        return output

    def get_count(self) -> int:
        """Return dict of window -> count of samples in that window."""
        with self._lock:
            return len(self._samples)

    def clear(self):
        """Clear all samples."""
        with self._lock:
            self._samples[:] = []


class MRUCache:
    """Thread-safe Most Recently Used (MRU) cache.

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
        # with self._lock:
        return key in self._cache if key else False

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


def measure_duration_decorator(metrics: Metrics):
    """Decorator to measure execution time and add to metrics object.

    Args:
        metrics: Metrics instance.

    """

    def decorator(func: Callable):
        @wraps(func)
        def wrapper(*args, **kwargs) -> Any:
            start: float = perf_counter()
            result: Any = func(*args, **kwargs)
            metrics.add_sample(perf_counter() - start)
            return result

        return wrapper

    return decorator
