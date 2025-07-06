import pytest
from pathlib import Path
import tempfile
from services.dns.db import DnsQueryHistoryDb, DnsStatsDb


def test_dns_query_history_duplicate_count():
    DnsQueryHistoryDb.init(max_size=10)
    DnsQueryHistoryDb.add_query("example.com.")
    DnsQueryHistoryDb.add_query("Example.com")

    assert DnsQueryHistoryDb._cursor is not None

    DnsQueryHistoryDb._cursor.execute(
        "SELECT query_counter FROM history WHERE query = 'example.com'"
    )
    assert DnsQueryHistoryDb._cursor.fetchone()[0] == 2

    DnsQueryHistoryDb.close()


def test_dns_query_history_eviction():
    max_size = 5
    domains = [f"domain-{i}.com" for i in range(10)]
    DnsQueryHistoryDb.init(max_size=max_size)

    for domain in domains:
        DnsQueryHistoryDb.add_query(domain)

    if DnsQueryHistoryDb._cursor:
        DnsQueryHistoryDb._cursor.execute("SELECT COUNT(*) FROM history")
        assert DnsQueryHistoryDb._cursor.fetchone()[0] <= max_size

    if DnsQueryHistoryDb._cursor:
        DnsQueryHistoryDb._cursor.execute(
            "SELECT query FROM history ORDER BY created DESC"
        )
        remaining_domains = [row[0] for row in DnsQueryHistoryDb._cursor.fetchall()]
        expected_domains = [d.lower() for d in domains[-max_size:]]
        assert all(domain in expected_domains for domain in remaining_domains)

    DnsQueryHistoryDb.close()


def test_dns_query_history_save_to_disk():
    DnsQueryHistoryDb.init(max_size=5)
    DnsQueryHistoryDb.add_query("example.com")

    tmpfile = tempfile.NamedTemporaryFile(delete=False)
    tmp_path = Path(tmpfile.name)
    tmpfile.close()

    DnsQueryHistoryDb.save_to_disk(tmp_path)
    assert tmp_path.exists()
    assert tmp_path.stat().st_size > 0

    DnsQueryHistoryDb.close()

    tmp_path.unlink(missing_ok=True)


def test_dns_stats_db_basic():
    # Init
    DnsStatsDb.init()
    valid_key = next(
        iter(
            k
            for k in DnsStatsDb._valid_columns
            if k not in ("id", "start_time", "last_updated")
        )
    )

    # Increment valid key
    DnsStatsDb.increment(valid_key, 1)
    if DnsStatsDb._cursor:
        DnsStatsDb._cursor.execute(f"SELECT {valid_key} FROM stats WHERE id=1")
        val = DnsStatsDb._cursor.fetchone()[0]
        assert val >= 1

    # Increment invalid key (should do nothing, no error)
    DnsStatsDb.increment("invalid_key", 1)

    # Save to disk using tempfile
    tmpfile = tempfile.NamedTemporaryFile(delete=False)
    path = Path(tmpfile.name)
    tmpfile.close()
    DnsStatsDb.save_to_disk(path)
    assert path.exists()
    path.unlink()

    # Close DB
    DnsStatsDb.close()
    assert DnsStatsDb._conn is None
    assert DnsStatsDb._cursor is None


def test_dns_stats_db_double_init_raises():
    DnsStatsDb.init()
    with pytest.raises(RuntimeError):
        DnsStatsDb.init()
    DnsStatsDb.close()


def test_dns_stats_db_increment_without_init_raises():
    with pytest.raises(RuntimeError):
        DnsStatsDb.increment("any_key")
