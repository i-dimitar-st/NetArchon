import re
import time
import threading
from pathlib import Path
from typing import Optional, Tuple, Any
from collections import deque, OrderedDict
from dnslib import DNSRecord, DNSLabel

TTL_MAX_SIZE = 100
TTL_DEFAULT = 600
MRU_MAX_sIZE = 100


def delete_files_in_dir(path: str, starts_with: str) -> list:
    """Remove/Unlink all files in dir starting with provided match."""

    _path = Path(path)
    if not _path.is_dir():
        raise FileNotFoundError("Missing directory")

    deleted_files = []
    for _file in _path.iterdir():
        if _file.is_file() and _file.name.lower().startswith(starts_with.strip().lower()):
            _file.unlink()
            deleted_files.append(str(_file))

    return deleted_files


class DNSUtils:
    """DNS utility functions."""

    @staticmethod
    def convert_request_type(request_type: int = 1) -> str:
        """Convert DNS request type number to string."""
        query_type_map = {
            1: 'request_type_a',
            2: 'request_type_ns',
            5: 'request_type_cname',
            6: 'request_type_soa',
            12: 'request_type_ptr',
            15: 'request_type_mx',
            16: 'request_type_txt',
            28: 'request_type_aaaa',
            33: 'request_type_srv',
            35: 'request_type_naptr',
            36: 'request_type_kx',
            37: 'request_type_cert',
            38: 'request_type_a6',
            39: 'request_type_dname',
            43: 'request_type_ds',
            44: 'request_type_sshfp',
            46: 'request_type_rrsig',
            47: 'request_type_nsec',
            48: 'request_type_dnskey',
            50: 'request_type_nsec3',
            51: 'request_type_nsec3param',
            52: 'request_type_tlsa',
            53: 'request_type_smimea',
            55: 'request_type_hip',
            59: 'request_type_cds',
            60: 'request_type_cdnskey',
            61: 'request_type_openpgpkey',
            64: 'request_type_svcb',
            65: 'request_type_https',
            99: 'request_type_spf',
            108: 'request_type_eui48',
            109: 'request_type_eui64',
            249: 'request_type_tkey',
            250: 'request_type_tsig',
            251: 'request_type_ixfr',
            252: 'request_type_axfr',
            255: 'request_type_any',
            256: 'request_type_uri',
            257: 'request_type_caa',
            32768: 'request_type_ta',
            32769: 'request_type_dlv',
        }
        return query_type_map.get(request_type, 'unknown')

    @staticmethod
    def convert_response_code(rcode: int = 0) -> str:
        """Convert DNS response code number to string."""
        response_code_map = {
            0: 'no_error',
            1: 'format_error',
            2: 'server_failure',
            3: 'name_error',
            4: 'not_implemented',
            5: 'refused'
        }
        return response_code_map.get(rcode, 'server_failure')

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
    """Thread-safe TTL cache with fixed max size. TTL only, no ordering."""

    def __init__(self, max_size: int = TTL_MAX_SIZE, ttl: int = TTL_DEFAULT):
        self._lock = threading.RLock()
        self._cache: dict[Tuple, Tuple[Any, float]] = {}  # key: (value, expiry_timestamp)
        self._max_size = max_size
        self._ttl = ttl

    def add(self, key: tuple, value: Any, _ttl: Optional[int] = None) -> Optional[Tuple]:
        """
        Add or update key with TTL.
        Overwrite oldest (earliest expiry) if max size reached.
        Returns evicted key if any.
        """
        with self._lock:
            self._cleanup_expired()
            _ttl = _ttl if (_ttl is not None and _ttl > 0) else self._ttl

            if key not in self._cache and len(self._cache) >= self._max_size:
                _oldest = min(self._cache,
                              key=lambda _key: self._cache[_key][1])
                self._cache.pop(_oldest)
            _expiry = time.time() + _ttl
            self._cache[key] = (value, _expiry)
            return None

    def get(self, key: tuple) -> Optional[Any]:
        """Return value if present and not expired; else None."""
        with self._lock:
            self._cleanup_expired()
            _item = self._cache.get(key)
            if not _item:
                return None
            value, _expiry = _item
            if _expiry < time.time():
                self._cache.pop(key)
                return None
            return value

    def remove(self, key: tuple) -> None:
        """Remove a key from cache."""
        with self._lock:
            self._cache.pop(key, None)

    def size(self) -> int:
        """Return number of non-expired items."""
        with self._lock:
            self._cleanup_expired()
            return len(self._cache)

    def clear(self) -> None:
        """Clear the cache."""
        with self._lock:
            self._cache.clear()

    def _cleanup_expired(self) -> None:
        """Remove all expired items."""
        _now = time.time()
        _expired = [k for k, (_, exp) in self._cache.items() if exp < _now]
        if _expired:
            for key in _expired:
                self._cache.pop(key)
