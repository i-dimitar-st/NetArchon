import sqlite3
from logging import Logger
from pathlib import Path
from threading import RLock
from time import time
from typing import Any, Optional

from src.config.config import config
from src.models.models import DBSchemas
from src.services.dns.utils import normalize_domain

PATHS = config.get("paths")
ROOT_PATH = Path(PATHS.get("root"))
DB = PATHS.get("database")
DNS_DB = config.get("database").get("dns")

DNS_DB_MAX_HISTORY_SIZE = int(DNS_DB.get("history").get("max_records"))

DNS_DB_STATS_PATH = ROOT_PATH / DB / DNS_DB.get("stats").get("path")
DNS_DB_HISTORY = ROOT_PATH / DB / DNS_DB.get("history").get("path")


class DnsQueryHistoryDb:
    """In-memory database for tracking DNS queries, their frequency,
    and the time they were last seen. Supports capped history and disk backup.
    """

    _lock = RLock()
    _conn: Optional[sqlite3.Connection] = None
    _cursor: Optional[sqlite3.Cursor] = None
    _max_size: int = DNS_DB_MAX_HISTORY_SIZE

    @classmethod
    def init(cls, logger: Logger, max_size=DNS_DB_MAX_HISTORY_SIZE):
        """Initializes the class-level SQLite connection and cursor."""
        if cls._cursor or cls._conn:
            raise RuntimeError("Already init.")

        cls._conn = sqlite3.connect(":memory:", check_same_thread=False)
        cls._cursor = cls._conn.cursor()
        cls._create_table()
        cls._max_size = max_size
        cls.logger = logger

    @classmethod
    def _create_table(cls):
        """Creates the history table and relevant indexes."""
        if not cls._cursor:
            raise RuntimeError("DB cursor not initialized")
        if not cls._conn:
            raise RuntimeError("DB connection not initialized")
        with cls._lock:
            cls._cursor.execute(DBSchemas.dnsHistory)
            cls._cursor.execute(
                """
                CREATE INDEX IF NOT EXISTS
                idx_query ON history(query)
                """
            )
            cls._cursor.execute(
                """
                CREATE INDEX IF NOT EXISTS
                idx_created ON history(created)
                """
            )
            cls._cursor.execute(
                """
                CREATE INDEX IF NOT EXISTS
                idx_query_counter ON history(query_counter)"""
            )
            cls._conn.commit()

    @classmethod
    def save_to_disk(cls, path: Path = DNS_DB_HISTORY) -> None:
        """Backs up the in-memory history database to disk."""
        if not cls._cursor:
            raise RuntimeError("DB cursor not initialized")
        if not cls._conn:
            raise RuntimeError("DB connection not initialized")
        with cls._lock:
            with sqlite3.connect(path) as disk_conn:
                cls._conn.backup(disk_conn)

    @classmethod
    def _insert_query(cls, query: str, active: int) -> None:
        """Inserts a new query record into the history."""
        if not cls._cursor:
            raise RuntimeError("DB not ini cursor missing.")
        with cls._lock:
            cls._cursor.execute(
                """
                INSERT INTO history (query, query_counter, created)
                VALUES (?, ?, ?)
                """,
                (query, active, int(time())),
            )

    @classmethod
    def _update_query(cls, query: str) -> bool:
        """Attempts to update an existing query.
        Returns True if update happened, False if not found.
        """
        with cls._lock:
            if not cls._cursor:
                raise RuntimeError("DB cursor not initialized")
            if cls._cursor:
                cls._cursor.execute(
                    """
                    UPDATE history
                    SET query_counter = query_counter + 1,
                        created = ?
                    WHERE query = ?
                    """,
                    (int(time()), query),
                )
                return bool(cls._cursor.rowcount > 0)
            return False

    @classmethod
    def _evict_queries(cls):
        """Removes the oldest queries if the DB exceeds max size.
        Only triggered before inserting new queries.
        """
        with cls._lock:
            if not cls._cursor:
                raise RuntimeError("DB cursor not initialized")
            if cls._cursor:
                cls._cursor.execute("SELECT COUNT(*) FROM history")
                count = int(cls._cursor.fetchone()[0])

                if count >= cls._max_size:
                    to_delete = count - cls._max_size + 1
                    cls._cursor.execute(
                        """
                        DELETE FROM history
                        WHERE query IN (
                            SELECT query
                            FROM history
                            ORDER BY created ASC
                            LIMIT ?
                        )
                        """,
                        (to_delete,),
                    )

    @classmethod
    def add_query(cls, query: str, active: int = 1):
        """Adds a DNS query to the history or updates its counter if already present.
        Evicts oldest queries only when inserting a new record over max capacity.
        """
        with cls._lock:
            if not cls._cursor:
                raise RuntimeError("DB cursor not initialized")
            if not cls._conn:
                raise RuntimeError("DB connection not initialized")
            _query: str = normalize_domain(query)
            if not cls._update_query(query=_query):
                cls._evict_queries()
                cls._insert_query(query=_query, active=active)
            cls._conn.commit()

    @classmethod
    def clear_history(cls) -> bool:
        """Empties the entire DNS query history table."""
        with cls._lock:
            if not cls._cursor:
                raise RuntimeError("DB cursor not initialized")
            if not cls._conn:
                raise RuntimeError("DB connection not initialized")
            try:
                cls._cursor.execute("DELETE FROM history")
                cls._conn.commit()
                cls.logger.debug("Cleared history")
                return True
            except Exception as err:
                cls.logger.debug(f"Error clearing history {str(err)}")
                return False

    @classmethod
    def close(cls):
        """Closes the in-memory history database and releases resources."""
        if not cls._cursor:
            raise RuntimeError("DB cursor not initialized")
        if not cls._conn:
            raise RuntimeError("DB connection not initialized")

        with cls._lock:
            cls._cursor.close()
            cls._conn.close()
            cls._cursor = None
            cls._conn = None


class DnsStatsDb:
    """In-memory database for DNS server statistics, such as query counts and errors.
    Supports schema validation and disk backup.
    """

    _lock = RLock()
    _valid_columns: set[str] = set()
    _conn: Optional[sqlite3.Connection] = None
    _cursor: Optional[sqlite3.Cursor] = None

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
        if not cls._cursor:
            raise RuntimeError("DB cursor not initialized")
        if not cls._conn:
            raise RuntimeError("DB connection not initialized")

        with cls._lock:
            cls._cursor.execute(DBSchemas.dnsStats)
            cls._conn.commit()
            _now = int(time())
            cls._cursor.execute(
                """
                INSERT OR IGNORE INTO
                    stats (id,start_time,last_updated)
                VALUES (1,?,?)
                """,
                (_now, _now),
            )
            cls._conn.commit()
            columns_info: list[Any] = cls._cursor.execute(
                "PRAGMA table_info(stats)"
            ).fetchall()
            cls._valid_columns.update({col[1] for col in columns_info})

    @classmethod
    def _is_key_valid(cls, key: str) -> bool:
        """Returns True if the given stat key is a valid column in the table."""
        if not cls._valid_columns:
            return False
        return bool(key in cls._valid_columns)

    @classmethod
    def increment(cls, key: str, count: int = 1):
        """Increments the specified stat column by count.
        No-op if the column name is invalid.
        """
        if not cls._cursor:
            raise RuntimeError("DB cursor not initialized")
        if not cls._conn:
            raise RuntimeError("DB connection not initialized")

        with cls._lock:
            if not cls._is_key_valid(key):
                return
            cls._cursor.execute(
                f"""
                UPDATE stats
                SET
                    "{key}" = "{key}" + ?,
                    last_updated = ?
                WHERE id = 1
                """,
                (count, int(time())),
            )
            cls._conn.commit()

    @classmethod
    def save_to_disk(cls, path: Path = DNS_DB_STATS_PATH):
        """Backs up the in-memory stats database to disk."""
        if not cls._cursor:
            raise RuntimeError("DB cursor not initialized")
        if not cls._conn:
            raise RuntimeError("DB connection not initialized")

        with cls._lock:
            with sqlite3.connect(path) as conn_disk:
                cls._conn.backup(conn_disk)

    @classmethod
    def close(cls):
        """Closes the in-memory stats database and releases resources."""
        if not cls._cursor:
            raise RuntimeError("DB cursor not initialized")
        if not cls._conn:
            raise RuntimeError("DB connection not initialized")
        with cls._lock:
            cls._cursor.close()
            cls._conn.close()
            cls._cursor = None
            cls._conn = None
