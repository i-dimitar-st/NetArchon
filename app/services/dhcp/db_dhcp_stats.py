from functools import wraps
from logging import Logger
from pathlib import Path
from sqlite3 import Connection, Cursor, connect
from threading import RLock
from time import time

from app.config.config import config
from app.services.dhcp.models import DHCPStatsSchema

PATHS = config.get("paths")
ROOT_PATH = Path(PATHS.get("root"))
DB_PATH = ROOT_PATH / PATHS.get("database")

DB_CONFIG = config.get("database")
DHCP_DB_CONFIG = DB_CONFIG.get("dhcp")

DB_STATS_PATH = DB_PATH / DHCP_DB_CONFIG.get("stats").get("path")


def is_init(func):
    """
    Decorator to verify DB connection, cursor, and valid columns are initialized.
    """

    @wraps(func)
    def wrapper(cls, *args, **kwargs):
        if not isinstance(getattr(cls, "_conn", None), Connection):
            raise RuntimeError("DB connection not initialized or invalid.")
        if not isinstance(getattr(cls, "_cursor", None), Cursor):
            raise RuntimeError("DB cursor not initialized or invalid.")
        if not isinstance(getattr(cls, "_valid_columns", None), frozenset):
            raise AttributeError("Valid columns missing check init.")
        return func(cls, *args, **kwargs)

    return wrapper


class DHCPStats:
    """
    Purpose:
        Manage DHCP server runtime statistics in an in-memory SQLite DB.
        Tracks counts of DHCP message types and last update times.
        Supports incrementing stats and persisting to disk.
        All statistics are stored in a single-row table with id=1.

    Dependencies:
        - sqlite3 (Python standard library): for in-memory and file DB operations.
        - threading.RLock: to ensure thread-safe DB access.
        - logging.Logger: for error and warning logs.
        - config.config: configuration access for DB paths and lease times.
        - models.models.DBSchemas: provides SQL schema string.

    Usage:
        1. Initialize before use:
            DHCPStats.init(logger)
        2. Increment counters:
            DHCPStats.increment("received_total")
        3. Save stats to disk:
            DHCPStats.save_to_disk(path)
        4. Close connection:
            DHCPStats.close()

    Notes:
        - Must call `init()` once before using other methods.
        - Supports only columns defined in the schema.
    """

    _lock = RLock()

    @classmethod
    def init(cls, logger: Logger):
        """
        Initialize in-memory SQLite DB and prepare schema.
        Crete table.

        Args:
            logger (Logger): Logger instance for debug/warning output.
        """

        if getattr(cls, "_conn", None) is not None or getattr(cls, "_cursor", None) is not None:
            raise RuntimeError("Already init")

        with cls._lock:

            _conn: Connection = connect(":memory:", check_same_thread=False)
            _cursor: Cursor = _conn.cursor()
            _cursor.execute(DHCPStatsSchema.schema)
            _conn.commit()

            cls._valid_columns: frozenset[str] = DHCPStatsSchema.columns
            cls._conn = _conn
            cls._cursor = _cursor

            cls._cursor.execute("INSERT INTO stats (id) VALUES (1)")
            cls._conn.commit()

            cls.logger = logger
            cls.logger.debug("%s initialized.", cls.__name__)

    @classmethod
    @is_init
    def increment(cls, key: str, count: int = 1):
        """
        Increment a numeric stat column by count.
        Args:
            key (str): Stat column to increment.
            count (int): Amount to increment by (default 1).
        """

        with cls._lock:

            if key not in cls._valid_columns:
                raise ValueError(f"Invalid input: {key}")

            cls._cursor.execute(
                f"""
                UPDATE stats
                SET {key} = {key} + ?,
                    last_updated = ?
                WHERE id = 1
                """,
                (count, int(time())),
            )
            cls._conn.commit()

    @classmethod
    @is_init
    def save_to_disk(cls, path: Path = DB_STATS_PATH):
        """
        Persist the in-memory database to disk file.
        Args:
            path (Path): Destination file path (default configured path).
        """
        with cls._lock:
            cls._conn.commit()
            _conn_disk: Connection = connect(path)
            cls._conn.backup(_conn_disk)
            _conn_disk.close()

    @classmethod
    @is_init
    def close(cls):
        """
        Close DB cursor and connection cleanly.
        """
        with cls._lock:
            if cls._cursor:
                cls._cursor.close()
            if cls._conn:
                cls._conn.close()
            cls.logger.debug("%s shutdown.", cls.__name__)
