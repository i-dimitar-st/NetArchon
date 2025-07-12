import threading
import time

from libs.libs import Metrics, MRUCache, TTLCache


def test_metrics_basic():
    Metrics.init(max_size=100)
    Metrics.clear()

    for i in range(1, 101):
        Metrics.add_sample(float(i))

    assert Metrics.get_count() == 100
    assert Metrics.get_percentile(50) == 50

    stats = Metrics.get_stats()
    assert stats["count"] == 100
    assert stats["p50"] == 50

    Metrics.clear()
    assert Metrics.get_count() == 0


def test_metrics_max_size():
    Metrics.init(max_size=5)
    Metrics._samples.clear()

    for i in range(1, 11):
        Metrics.add_sample(float(i))

    assert Metrics.get_count() == 5


def test_mru_cache_size_limit():
    max_size = 5
    cache = MRUCache(max_size=max_size)

    for i in range(1, 101):
        cache.add(i)
        assert cache.size() <= max_size


def test_mru_cache_final_contents():
    max_size = 10
    cache = MRUCache(max_size=max_size)

    for i in range(1, 101):
        cache.add(i, i)

    # Positive
    for key in range(91, 101):
        assert cache.get(key) == key

    # Negative
    assert not cache.is_present(250)
    assert not cache.is_present(-5)


def test_mru_cache_multiple_fills_and_clears():
    cache = MRUCache(max_size=3)
    keys = ["a", "b", "c"]

    for _ in range(3):
        for key in keys:
            cache.add(key)
        # Positive
        for key in keys:
            assert cache.is_present(key)
        # Negative
        assert not cache.is_present("x")

        # Clear cache
        cache.clear()
        for key in keys:
            assert not cache.is_present(key)


def test_mru_cache_key_refresh_on_add():
    cache = MRUCache(max_size=3)
    keys = ["a", "b", "c"]
    for key in keys:
        cache.add(key)
    # cache => [c, b, a] (c newest)

    cache.add("a")
    # [a, c, b]

    cache.add("d")
    # cache => [d, a, c] (d newest)

    # Positive
    assert cache.is_present("a")
    assert cache.is_present("c")
    assert cache.is_present("d")
    assert not cache.is_present("b")

    # Negative
    assert not cache.is_present("e")
    assert not cache.is_present("b")


def test_mru_cache_eviction_order():
    cache = MRUCache(max_size=3)
    cache.add(1)
    cache.add(2)
    cache.add(3)

    # Access key 1 to mark it MRU
    cache.add(1)

    # Add new key to trigger eviction
    cache.add(4)

    # Key 2 should be evicted (LRU), keys 1,3,4 remain
    assert cache.is_present(1)
    assert cache.is_present(3)
    assert cache.is_present(4)
    assert not cache.is_present(2)


def test_mru_cache_add_falsy_values():
    cache = MRUCache(max_size=3)

    cache.add("none_val", None)
    cache.add("zero_val", 0)
    cache.add("empty_str", "")

    assert cache.is_present("none_val")
    assert cache.get("none_val") is None

    assert cache.is_present("zero_val")
    assert cache.get("zero_val") == 0

    assert cache.is_present("empty_str")
    assert cache.get("empty_str") == ""


def test_mru_cache_thread_safety_order():
    cache = MRUCache(max_size=100)

    def _worker(start: int, end: int):
        for _index in range(start, end + 1):
            cache.add(_index, _index)

    threads = []
    for _index in range(10):
        start = _index * 10 + 1
        end = start + 9
        t = threading.Thread(target=_worker, args=(start, end))
        threads.append(t)

    for t in threads:
        t.start()

    for t in threads:
        t.join()

    for _i in range(1, 101):
        assert _i == cache.get(_i)
    assert cache.get_keys() == list(range(1, 101))[::-1]


def test_mru_cache_thread_safety_order_with_evictoin():
    cache = MRUCache(max_size=50)

    def _worker(start: int, end: int):
        for _index in range(start, end + 1):
            cache.add(_index, _index)

    threads = []
    for _index in range(10):
        start = _index * 10 + 1
        end = start + 9
        thread = threading.Thread(target=_worker, args=(start, end))
        threads.append(thread)

    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    for key in range(51, 101):
        assert cache.get(key) == key

    for key in range(1, 51):
        assert cache.get(key) is None

    # Reversed list due to MRU insetion behaviour
    assert cache.get_keys() == list(range(100, 50, -1))


def test_ttl_cache_basic_add_get():
    cache = TTLCache(max_size=5, ttl=2)
    cache.add("key1", "value1")
    cache.add("key2", "value2")

    # positive
    assert cache.get("key1") == "value1"
    assert cache.get("key2") == "value2"

    # negative
    assert not cache.get("key1") == "value2"
    assert cache.get("nonexistent") is None


def test_ttl_cache_expiration():
    cache = TTLCache(max_size=5, ttl=3)
    cache.add("key1", "value1")
    time.sleep(1)
    assert cache.get("key1") == "value1"
    time.sleep(2.5)
    assert cache.get("key1") is None


def test_ttl_cache_ttl_override():
    cache = TTLCache(max_size=5, ttl=10)
    cache.add("key1", "value1", ttl=1)
    assert cache.get("key1") == "value1"
    time.sleep(1.1)
    assert cache.get("key1") is None


def test_ttl_cache_eviction():
    cache = TTLCache(max_size=10, ttl=5)

    # Only the last 10 keys should remain (k11–k20)
    for i in range(1, 21):
        cache.add(f"k{i}", f"v{i}")
        time.sleep(0.01)

    # First 10 keys should be evicted
    for i in range(1, 11):
        assert cache.get(f"k{i}") is None

    # Last 10 should be present
    for i in range(11, 21):
        assert cache.get(f"k{i}") == f"v{i}"

    # Wait for TTL to expire
    time.sleep(5)
    assert cache.size() == 0


def test_ttl_cache_get_by_value():
    cache = TTLCache(max_size=3, ttl=10)
    cache.add("k1", "v1")
    cache.add("k2", "v2")

    # positive
    assert cache.get_by_value("v2") == "k2"

    # negative
    assert cache.get_by_value("v3") is None


def test_ttl_cache_remove_and_clear():
    cache = TTLCache(max_size=3, ttl=10)
    cache.add("k1", "v1")
    assert cache.get("k1") == "v1"
    cache.remove("k1")
    assert cache.get("k1") is None

    cache.add("k2", "v2")
    cache.add("k3", "v3")
    cache.clear()
    assert cache.get("k2") is None
    assert cache.get("k3") is None


def test_ttl_cache_thread_safety():
    cache = TTLCache(max_size=100, ttl=5)

    def _worker(start, end):
        for _i in range(start, end):
            cache.add(f"key{_i}", f"value{_i}")
            assert cache.get(f"key{_i}") == f"value{_i}"

    threads = [
        # Thread 0 → keys 0–9, Thread 1 → keys 10–19, ..., Thread 9 → keys 90–99
        threading.Thread(target=_worker, args=(_i * 10, _i * 10 + 10))
        for _i in range(10)
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    # max_size=100 inserted 100 keys, all keys should be present
    for i in range(100):
        assert cache.get(f"key{i}") == f"value{i}"
