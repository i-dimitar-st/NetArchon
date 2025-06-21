import time
import threading
import sqlite3
from pathlib import Path
from services.config.config import config
from services.logger.logger import MainLogger
from models.models import DBSchemas


ROOT = Path(config.get("paths", "root"))
DNS_DB = config.get("database", "dns")
DB_STATS_FULLPATH = ROOT / DNS_DB.get("stats").get("path")
DB_HISTORY_FULLPATH = ROOT / DNS_DB.get("history").get("path")
DB_MAX_HISTORY_SIZE = DNS_DB.get("history").get("max_records")

db_logger = MainLogger.get_logger(service_name="DNS_DB", log_level="debug")


class DnsHistoryDb:

    _lock = threading.RLock()
    _conn = None
    _cursor = None
    _running = False

    @classmethod
    def init(cls):
        """Initializes the class-level SQLite connection and cursor."""

        if cls._running:
            raise RuntimeError("Already init")

        cls._conn = sqlite3.connect(":memory:", check_same_thread=False)
        cls._cursor = cls._conn.cursor()
        cls._create_table()
        cls._running = True

    @classmethod
    def _create_table(cls):
        """Creates the history table if it doesn't already exist."""
        if not cls._cursor or not cls._conn:
            return

        with cls._lock:
            cls._cursor.execute(DBSchemas.dnsHistory)
            cls._cursor.execute(f"""
                                CREATE TRIGGER limit_table
                                BEFORE INSERT ON history
                                FOR EACH ROW
                                WHEN (SELECT COUNT(*) FROM history) >= {DB_MAX_HISTORY_SIZE}
                                BEGIN
                                    DELETE FROM history
                                    WHERE created = (SELECT created FROM history ORDER BY created ASC LIMIT 1);
                                END""")
            cls._cursor.execute("CREATE INDEX IF NOT EXISTS idx_query ON history(query)")
            cls._cursor.execute("CREATE INDEX IF NOT EXISTS idx_created ON history(created)")
            cls._cursor.execute("CREATE INDEX IF NOT EXISTS idx_query_counter ON history(query_counter)")
            cls._conn.commit()

    @classmethod
    def save_to_disk(cls):

        if not cls._conn:
            return

        with cls._lock:
            try:
                _conn_disk = sqlite3.connect(DB_HISTORY_FULLPATH)
                cls._conn.backup(_conn_disk)
                _conn_disk.close()
            except Exception as err:
                db_logger.warning(f"Error during cache backup: {str(err)}")

    @classmethod
    def add_query(cls, query: str, active: int = 1):
        """Adds a query to the history or increments its counter if it already exists, and updates the active status."""

        if not cls._running:
            return

        with cls._lock:
            decoded_query = query.rstrip('.').lower()
            if not cls._cursor or not cls._conn:
                return
            cls._cursor.execute("""
                                INSERT INTO history (query,active,query_counter,created)
                                VALUES (?,?,1,?)
                                ON CONFLICT (query) DO UPDATE SET
                                    query_counter = history.query_counter + 1,
                                    active = excluded.active,
                                    created = excluded.created
                                """, (decoded_query, active, int(time.time())))
            cls._conn.commit()

    @classmethod
    def close(cls):
        with cls._lock:
            if cls._conn:
                cls._conn.close()
                cls._conn = None
            if cls._cursor:
                cls._cursor.close()
                cls._cursor = None
            cls._running = False


class DnsStatsDb:

    _lock = threading.RLock()
    _running = False
    _conn = None
    _cursor = None
    _valid_columns = set()

    @classmethod
    def init(cls):
        """Initializes the class-level SQLite connection and cursor."""

        if cls._running:
            raise RuntimeError("Already init")

        with cls._lock:
            cls._conn = sqlite3.connect(":memory:", check_same_thread=False)
            cls._cursor = cls._conn.cursor()
            cls._create_table()
            cls._running = True

    @classmethod
    def _create_table(cls):

        if not cls._conn or not cls._cursor:
            return

        with cls._lock:
            cls._cursor.execute(DBSchemas.dnsStats)
            cls._conn.commit()
            _now = int(time.time())
            cls._cursor.execute("""
                                INSERT OR IGNORE INTO
                                    stats (id,start_time,last_updated)
                                VALUES (1,?,?)
                                """, (_now, _now))
            cls._conn.commit()
            columns_info = cls._cursor.execute("PRAGMA table_info(stats)").fetchall()
            cls._valid_columns.update({col[1] for col in columns_info})

    @classmethod
    def _is_key_valid(cls, key: str) -> bool:

        if (not cls._running or
            not cls._cursor or
            not cls._conn or
                not cls._valid_columns):
            return False

        return bool(key in cls._valid_columns)

    @classmethod
    def increment(cls, key: str, count: int = 1):

        if (not cls._conn or
                not cls._cursor):
            raise ValueError("Connection and Cursor are missing")

        with cls._lock:
            if not cls._is_key_valid(key):
                db_logger.warning(f"Invalid key: {key}")
                return
            cls._cursor.execute(f"""
                                UPDATE stats
                                SET {key} = {key} + ?,
                                    last_updated = ?
                                WHERE id = 1
                                """, (count, int(time.time())))
            cls._conn.commit()

    @classmethod
    def save_to_disk(cls):

        if not cls._conn:
            return

        with cls._lock:
            try:
                _conn_disk = sqlite3.connect(DB_STATS_FULLPATH)
                cls._conn.backup(_conn_disk)
                _conn_disk.close()
            except Exception as err:
                db_logger.warning(f"Error during cache backup: {str(err)}")

    @classmethod
    def close(cls):
        with cls._lock:
            if cls._conn and cls._cursor:
                cls._cursor.close()
                cls._conn.close()
                cls._cursor = None
                cls._conn = None
