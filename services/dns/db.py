import time
import threading
import sqlite3
from pathlib import Path
from typing import Optional, Any
from utils.dns_utils import DNSUtils
from config.config import config
from models.models import DBSchemas

PATHS = config.get("paths")
ROOT_PATH = Path(PATHS.get("root"))
DNS_DB = config.get("database").get("dns")
DNS_DB_MAX_HISTORY_SIZE = int(DNS_DB.get("history").get("max_records"))

DNS_DB_STATS_PATH = ROOT_PATH / DNS_DB.get("stats").get("path")
DNS_DB_HISTORY = ROOT_PATH / DNS_DB.get("history").get("path")


class DnsQueryHistoryDb:
    """
    In-memory database for tracking DNS queries, their frequency,
    and the time they were last seen. Supports capped history and disk backup.
    """

    _lock = threading.RLock()
    _conn: Optional[sqlite3.Connection] = None
    _cursor: Optional[sqlite3.Cursor] = None

    @classmethod
    def init(cls):
        """Initializes the class-level SQLite connection and cursor."""

        if cls._cursor or cls._conn:
            raise RuntimeError("Already init.")

        cls._conn = sqlite3.connect(":memory:", check_same_thread=False)
        cls._cursor = cls._conn.cursor()
        cls._create_table()

    @classmethod
    def _create_table(cls):
        """Creates the history table and relevant indexes."""

        if not cls._cursor or not cls._conn:
            raise RuntimeError("DB not initialized.")

        with cls._lock:
            cls._cursor.execute(DBSchemas.dnsHistory)
            cls._cursor.execute("CREATE INDEX IF NOT EXISTS idx_query ON history(query)")
            cls._cursor.execute("CREATE INDEX IF NOT EXISTS idx_created ON history(created)")
            cls._cursor.execute(
                "CREATE INDEX IF NOT EXISTS idx_query_counter ON history(query_counter)"
            )
            cls._conn.commit()

    @classmethod
    def save_to_disk(cls):
        """Backs up the in-memory history database to disk."""

        if not cls._cursor or not cls._conn:
            raise RuntimeError("DB not initialized.")

        with cls._lock:
            _conn_disk: sqlite3.Connection = sqlite3.connect(DNS_DB_HISTORY)
            cls._conn.backup(_conn_disk)
            _conn_disk.close()

    @classmethod
    def add_query(cls, query: str, active: int = 1):
        """
        Adds a DNS query to the history or updates its counter if already present.
        Evicts oldest queries when over max capacity.
        """

        if not cls._cursor or not cls._conn:
            raise RuntimeError("DB not initialized.")

        with cls._lock:

            cls._cursor.execute("SELECT COUNT(*) FROM history")
            _count = int(cls._cursor.fetchone()[0])
            if _count >= DNS_DB_MAX_HISTORY_SIZE:
                _to_delete: int = _count - DNS_DB_MAX_HISTORY_SIZE + 1
                cls._cursor.execute(
                    """
                    DELETE
                    FROM history
                    WHERE query IN (
                        SELECT query
                        FROM history
                        ORDER BY created ASC
                        LIMIT ?
                    )
                    """,
                    (_to_delete,),
                )

            _query: str = DNSUtils.normalize_domain(query.rstrip('.').lower())
            cls._cursor.execute(
                """
                INSERT INTO history (query,query_counter,created)
                VALUES (?,1,?)
                ON CONFLICT (query) DO UPDATE SET
                    query_counter = history.query_counter + 1,
                    created = excluded.created
                """,
                (_query, int(time.time())),
            )
            cls._conn.commit()

    @classmethod
    def close(cls):
        """Closes the in-memory history database and releases resources."""
        with cls._lock:
            if cls._cursor:
                cls._cursor.close()
                cls._cursor = None
            if cls._conn:
                cls._conn.close()
                cls._conn = None


class DnsStatsDb:
    """
    In-memory database for DNS server statistics, such as query counts and errors.
    Supports schema validation and disk backup.
    """

    _lock = threading.RLock()
    _conn: Optional[sqlite3.Connection] = None
    _cursor: Optional[sqlite3.Cursor] = None
    _valid_columns: set[str] = set()

    @classmethod
    def init(cls):
        """Initializes the class-level SQLite connection and cursor."""

        if cls._conn or cls._cursor:
            raise RuntimeError("Already init")

        with cls._lock:
            cls._conn = sqlite3.connect(":memory:", check_same_thread=False)
            cls._cursor = cls._conn.cursor()
            cls._create_table()

    @classmethod
    def _create_table(cls):
        """Creates the stats table and stores valid column names."""

        if not cls._conn or not cls._cursor:
            raise RuntimeError("Init missing.")

        with cls._lock:
            cls._cursor.execute(DBSchemas.dnsStats)
            cls._conn.commit()
            _now = int(time.time())
            cls._cursor.execute(
                """
                INSERT OR IGNORE INTO
                    stats (id,start_time,last_updated)
                VALUES (1,?,?)
                """,
                (_now, _now),
            )
            cls._conn.commit()
            columns_info: list[Any] = cls._cursor.execute("PRAGMA table_info(stats)").fetchall()
            cls._valid_columns.update({col[1] for col in columns_info})

    @classmethod
    def _is_key_valid(cls, key: str) -> bool:
        """Returns True if the given stat key is a valid column in the table."""
        if not cls._valid_columns:
            return False
        return bool(key in cls._valid_columns)

    @classmethod
    def increment(cls, key: str, count: int = 1):
        """
        Increments the specified stat column by count.
        No-op if the column name is invalid.
        """
        if not cls._conn or not cls._cursor:
            raise RuntimeError("Init missing.")
        with cls._lock:
            if not cls._is_key_valid(key):
                return
            cls._cursor.execute(
                f"""
                UPDATE stats
                SET
                    {key} = {key} + ?,
                    last_updated = ?
                WHERE id = 1
                """,
                (count, int(time.time())),
            )
            cls._conn.commit()

    @classmethod
    def save_to_disk(cls):
        """Backs up the in-memory stats database to disk."""
        if not cls._conn or not cls._cursor:
            raise RuntimeError("Init missing.")

        with cls._lock:
            _conn_disk: sqlite3.Connection = sqlite3.connect(DNS_DB_STATS_PATH)
            cls._conn.backup(_conn_disk)
            _conn_disk.close()

    @classmethod
    def close(cls):
        """Closes the in-memory stats database and releases resources."""
        with cls._lock:
            if cls._cursor:
                cls._cursor.close()
                cls._cursor = None
            if cls._conn:
                cls._conn.close()
                cls._conn = None
