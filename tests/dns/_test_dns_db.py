import sqlite3
import threading
import time
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from src.services.dns.db import (
    DnsQueryHistoryDb,
    DnsStatsDb,
)

# =========================
# Fixtures
# =========================

@pytest.fixture
def logger() -> MagicMock:
    return MagicMock()


@pytest.fixture
def tmp_db_path(tmp_path: Path) -> Path:
    return tmp_path / "dns_test.db"


@pytest.fixture(autouse=True)
def cleanup_db():
    """Ensure DBs are closed between tests
    """
    yield
    try:
        DnsQueryHistoryDb.close()
    except Exception:
        pass
    try:
        DnsStatsDb.close()
    except Exception:
        pass


# =========================
# DnsQueryHistoryDb tests
# =========================

def test_history_init_and_close(logger):
    DnsQueryHistoryDb.init(logger=logger, max_size=10)
    assert DnsQueryHistoryDb._conn is not None
    assert DnsQueryHistoryDb._cursor is not None

    DnsQueryHistoryDb.close()
    assert DnsQueryHistoryDb._conn is None
    assert DnsQueryHistoryDb._cursor is None


def test_history_insert_and_update(logger):
    DnsQueryHistoryDb.init(logger=logger, max_size=10)

    DnsQueryHistoryDb.add_query("Google.COM")
    DnsQueryHistoryDb.add_query("google.com")
    DnsQueryHistoryDb.add_query("google.com")

    cur = DnsQueryHistoryDb._cursor
    cur.execute("SELECT query, query_counter FROM history")
    row = cur.fetchone()

    assert row[0] == "google.com"   # normalized
    assert row[1] == 3              # counter increments


def test_history_max_size_eviction(logger):
    max_size = 3
    DnsQueryHistoryDb.init(logger=logger, max_size=max_size)

    for i in range(5):
        DnsQueryHistoryDb.add_query(f"domain{i}.com")
        time.sleep(0.01)  # ensure created ordering

    cur = DnsQueryHistoryDb._cursor
    cur.execute("SELECT COUNT(*) FROM history")
    count = cur.fetchone()[0]

    assert count == max_size

    cur.execute("SELECT query FROM history ORDER BY created ASC")
    remaining = [r[0] for r in cur.fetchall()]

    assert "domain0.com" not in remaining
    assert "domain1.com" not in remaining


def test_history_clear(logger):
    DnsQueryHistoryDb.init(logger=logger, max_size=10)

    DnsQueryHistoryDb.add_query("a.com")
    DnsQueryHistoryDb.add_query("b.com")

    assert DnsQueryHistoryDb.clear_history() is True

    cur = DnsQueryHistoryDb._cursor
    cur.execute("SELECT COUNT(*) FROM history")
    assert cur.fetchone()[0] == 0


def test_history_save_to_disk(logger, tmp_db_path):
    DnsQueryHistoryDb.init(logger=logger, max_size=10)

    DnsQueryHistoryDb.add_query("example.com")
    DnsQueryHistoryDb.save_to_disk(tmp_db_path)

    conn = sqlite3.connect(tmp_db_path)
    cur = conn.cursor()
    cur.execute("SELECT query FROM history")
    row = cur.fetchone()

    assert row[0] == "example.com"

    conn.close()


def test_history_thread_safety(logger):
    DnsQueryHistoryDb.init(logger=logger, max_size=100)

    def worker():
        for _ in range(50):
            DnsQueryHistoryDb.add_query("threaded.com")

    threads = [threading.Thread(target=worker) for _ in range(10)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    cur = DnsQueryHistoryDb._cursor
    cur.execute("SELECT query_counter FROM history WHERE query='threaded.com'")
    count = cur.fetchone()[0]

    assert count == 500


# =========================
# DnsStatsDb tests
# =========================

def test_stats_init_and_close():
    DnsStatsDb.init()
    assert DnsStatsDb._conn is not None
    assert DnsStatsDb._cursor is not None

    DnsStatsDb.close()
    assert DnsStatsDb._conn is None
    assert DnsStatsDb._cursor is None


def test_stats_increment_valid_key():
    DnsStatsDb.init()

    DnsStatsDb.increment("request_total", 3)
    DnsStatsDb.increment("request_total", 2)

    cur = DnsStatsDb._cursor
    cur.execute("SELECT request_total FROM stats WHERE id=1")
    value = cur.fetchone()[0]

    assert value == 5


def test_stats_increment_invalid_key_noop():
    DnsStatsDb.init()

    DnsStatsDb.increment("non_existing_metric", 10)

    cur = DnsStatsDb._cursor
    cur.execute("SELECT * FROM stats WHERE id=1")
    row = cur.fetchone()

    # no exception + row still exists
    assert row is not None


def test_stats_save_to_disk(tmp_db_path):
    DnsStatsDb.init()
    DnsStatsDb.increment("request_total", 7)

    DnsStatsDb.save_to_disk(tmp_db_path)

    conn = sqlite3.connect(tmp_db_path)
    cur = conn.cursor()
    cur.execute("SELECT request_total FROM stats WHERE id=1")
    value = cur.fetchone()[0]

    assert value == 7
    conn.close()


def test_stats_thread_safety():
    DnsStatsDb.init()

    def worker():
        for _ in range(100):
            DnsStatsDb.increment("request_total")

    threads = [threading.Thread(target=worker) for _ in range(10)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    cur = DnsStatsDb._cursor
    cur.execute("SELECT request_total FROM stats WHERE id=1")
    value = cur.fetchone()[0]

    assert value == 1000
