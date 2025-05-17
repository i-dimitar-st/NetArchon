import threading
import sqlite3
import time
from scapy.all import DNS # type: ignore
from services.config.config import Config
from services.logger.logger import MainLogger
from services.dns.dns_utilities import extract_min_and_max_ttl

DB_PATH = Config.get_paths().get("db")
DB_CACHE_FULLPATH = DB_PATH / 'dns_cache.sqlite3' # type: ignore
DB_STATS_FULLPATH = DB_PATH / 'dns_stats.sqlite3' # type: ignore
DB_HISTORY_FULLPATH = DB_PATH / 'dns_history.sqlite3' # type: ignore
DB_PERSISTENCE_INTERVAL = 60
DB_MAX_HISTORY_SIZE = 1000

db_logger = MainLogger.get_logger(service_name="DB", log_level="debug")

class DNSCache:

    _lock = threading.RLock()
    _conn = None
    _cursor = None
    _running = False

    @classmethod
    def init(cls):

        if cls._running:
            return

        cls._running = True
        cls._conn = sqlite3.connect(":memory:", check_same_thread=False)
        cls._cursor = cls._conn.cursor()
        cls._create_tables()
        cls._create_triggers()

    @classmethod
    def save_to_disk(cls):

        if not cls._conn:
            return

        with cls._lock:
            try:
                _conn_disk = sqlite3.connect(DB_CACHE_FULLPATH)
                cls._conn.backup(_conn_disk)
                _conn_disk.close()
            except Exception as err:
                db_logger.warning(f"Error during cache backup: {str(err)}")
 
    @classmethod
    def _create_tables(cls):

        if not cls._running or not cls._cursor or not cls._conn:
            return

        with cls._lock:
            cls._cursor.execute("""
                CREATE TABLE IF NOT EXISTS cache (
                    query BLOB PRIMARY KEY,
                    response BLOB NOT NULL,
                    created INTEGER NOT NULL DEFAULT (CAST(strftime('%s','now') AS INTEGER)),
                    modified INTEGER,
                    expiration INTEGER NOT NULL,
                    ttl INTEGER DEFAULT 0,
                    update_counter INTEGER DEFAULT 0
                )
            """)
            cls._cursor.execute("CREATE INDEX IF NOT EXISTS idx_cache_query ON cache(query)")
            cls._cursor.execute("CREATE INDEX IF NOT EXISTS idx_cache_created ON cache(created)")
            cls._cursor.execute("CREATE INDEX IF NOT EXISTS idx_cache_expiration ON cache(expiration)")
            cls._cursor.execute("CREATE INDEX IF NOT EXISTS idx_cache_query_expiration ON cache(query,expiration)")
            cls._conn.commit()

    @classmethod
    def _create_triggers(cls):

        if not cls._running or not cls._conn or not cls._cursor:
            return

        with cls._lock:
            cls._cursor.execute("""
                CREATE TRIGGER IF NOT EXISTS delete_expired_cache
                BEFORE INSERT ON cache
                BEGIN
                    DELETE FROM cache
                    WHERE expiration < CAST(strftime('%s','now') AS INTEGER);
                END;
            """)
            cls._conn.commit()

    @classmethod
    def add_to_cache(cls, query: bytes, response: DNS):

        if not cls._running \
            or not cls._cursor \
            or not cls._conn \
            or not query \
            or not response:
            return

        try:
            with cls._lock:
                min_ttl, _ = extract_min_and_max_ttl(response[DNS].an)
                cls._cursor.execute("""
                    INSERT INTO cache (query, response, expiration, ttl)
                    VALUES (?, ?, ?, ?)
                    ON CONFLICT(query) DO UPDATE SET
                        response = excluded.response,
                        expiration = excluded.expiration,
                        modified = CAST(strftime('%s','now') AS INTEGER),
                        ttl = excluded.ttl,
                        update_counter = cache.update_counter + 1
                """, (query, bytes(response), min_ttl + int(time.time()), min_ttl))
                cls._conn.commit()
        except Exception as err:
            db_logger.warning(f"Error inserting into cache: {str(err)}")

    @classmethod
    def get_cached_response(cls, query: bytes) -> DNS | None:
        
        if not cls._running or not cls._conn or not cls._cursor or not query:
            return None

        with cls._lock:
            try:
                cls._cursor.execute("""
                    SELECT response
                    FROM cache
                    WHERE query = ?
                    AND expiration > CAST(strftime('%s','now') AS INTEGER)
                """, (query,))
                result = cls._cursor.fetchone()
                if result:
                    return DNS(result[0])
                return None
            except Exception as err:
                db_logger.warning(f"Error getting cached response: {str(err)}")
                return None

    @classmethod
    def get_cache_size(cls) -> int:

        if not cls._running \
            or not cls._conn \
            or not cls._cursor:
            return 0

        with cls._lock:
            try:
                cls._cursor.execute("SELECT COUNT(*) FROM cache")
                return  cls._cursor.fetchone()[0]
            except Exception as err:
                db_logger.warning(f"Error getting cache size: {str(err)}")
                return 0

    @classmethod
    def get_whole_cache(cls) -> list:
        
        if not cls._running \
            or not cls._conn \
            or not cls._cursor:
            return []

        with cls._lock:
            try:
                cls._cursor.execute("SELECT * FROM cache")
                result_raw = cls._cursor.fetchall()
                table_columns = [ column_description[0] for column_description in cls._cursor.description ]
                result = []
                for _row in result_raw:
                    _record = { table_columns[_index]: _row[_index] for _index in range(len(table_columns)) }
                    result.append(_record)
                return result
            except Exception as err:
                db_logger.warning(f"Error getting all cache entries: {str(err)}")
                return []

    @classmethod
    def close(cls):
        with cls._lock:
            if cls._conn and cls._cursor:
                cls._cursor.close()
                cls._conn.close()
            cls._cursor = None
            cls._conn = None
            cls._running = False


class DNSHistory:

    _lock = threading.RLock()
    _conn = None
    _cursor = None
    _running = False

    @classmethod
    def init(cls):
        """Initializes the class-level SQLite connection and cursor."""

        if cls._running:
            return

        cls._conn = sqlite3.connect(":memory:", check_same_thread=False)
        cls._cursor = cls._conn.cursor()
        cls._create_table()
        cls._running = True

    @classmethod
    def _create_table(cls):
        """Creates the history table if it doesn't already exist."""

        if cls._running or not cls._cursor or not cls._conn:
            return

        with cls._lock:
            cls._cursor.execute("""
                                CREATE TABLE IF NOT EXISTS history (
                                    query TEXT NOT NULL PRIMARY KEY,
                                    query_counter INTEGER NOT NULL DEFAULT 0,
                                    active INTEGER NOT NULL DEFAULT 1,
                                    created INTEGER NOT NULL)
                                """)
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
    def add_query(cls, query: bytes, active: int = 1):
        """Adds a query to the history or increments its counter if it already exists, and updates the active status."""

        if not cls._running:
            return

        with cls._lock:
            decoded_query = query.decode('utf-8').rstrip('.').lower()
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


class DNSStats:

    _lock = threading.RLock()
    _is_initialised = False
    _conn = None
    _cursor = None
    _valid_columns = None

    @classmethod
    def init(cls):
        """Initializes the class-level SQLite connection and cursor."""

        if cls._is_initialised:
            return

        cls._conn = sqlite3.connect(":memory:", check_same_thread=False)
        cls._cursor = cls._conn.cursor()
        cls._create_table()
        cls._init_table()
        cls._is_initialised = True
        cls._valid_columns = set()

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
    def _create_table(cls):

        if not cls._conn or not cls._cursor:
            raise ValueError("Connection and Cursor are missing")
        
        with cls._lock:
            cls._cursor.execute("""
                CREATE TABLE IF NOT EXISTS stats (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    start_time TEXT DEFAULT CURRENT_TIMESTAMP,
                    last_updated TEXT DEFAULT CURRENT_TIMESTAMP,
                    request_total INTEGER DEFAULT 0,
                    request_total_valid INTEGER DEFAULT 0,
                    request_blacklisted INTEGER DEFAULT 0,
                    request_not_supported INTEGER DEFAULT 0,
                    request_type_a INTEGER DEFAULT 0,
                    request_type_aaaa INTEGER DEFAULT 0,
                    request_type_ptr INTEGER DEFAULT 0,
                    request_type_mx INTEGER DEFAULT 0,
                    request_type_svcb INTEGER DEFAULT 0,
                    request_type_https INTEGER DEFAULT 0,
                    request_type_cname INTEGER DEFAULT 0,
                    request_type_ns INTEGER DEFAULT 0,
                    request_type_soa INTEGER DEFAULT 0,
                    request_type_txt INTEGER DEFAULT 0,
                    request_type_srv INTEGER DEFAULT 0,
                    request_type_any INTEGER DEFAULT 0,
                    response_total INTEGER DEFAULT 0,
                    response_noerror INTEGER DEFAULT 0,
                    response_nxdomain INTEGER DEFAULT 0,
                    response_notimp INTEGER DEFAULT 0,
                    response_servfail INTEGER DEFAULT 0,
                    response_failure INTEGER DEFAULT 0,
                    cache_hit INTEGER DEFAULT 0,
                    cache_negative_hit INTEGER DEFAULT 0,
                    cache_miss INTEGER DEFAULT 0,
                    external_noerror INTEGER DEFAULT 0,
                    external_nxdomain INTEGER DEFAULT 0,
                    external_servfail INTEGER DEFAULT 0,
                    external_failed INTEGER DEFAULT 0
                )
            """)
            cls._conn.commit()

    @classmethod
    def _init_table(cls):

        if not cls._conn or not cls._cursor:
            raise ValueError("Connection and Cursor are missing")

        with cls._lock:
            cls._cursor.execute("DELETE FROM stats")
            cls._cursor.execute(
                "DELETE FROM sqlite_sequence WHERE name='stats'")
            cls._cursor.execute("INSERT INTO stats (id) VALUES (1)")
            cls._conn.commit()

    @classmethod
    def _is_key_valid(cls, key: str) -> bool:
        if not cls._conn or not cls._cursor:
            raise ValueError("Connection and Cursor are missing")
        if not cls._valid_columns:
            with cls._lock:
                cls._cursor.execute("PRAGMA table_info(stats)")
                columns_info = cls._cursor.fetchall()
                cls._valid_columns.update({col[1] for col in columns_info})

        return bool(key in cls._valid_columns)

    @classmethod
    def increment(cls, key: str, count: int = 1):

        if not cls._conn or not cls._cursor:
            raise ValueError("Connection and Cursor are missing")
        
        with cls._lock:
           
            if not cls._is_key_valid(key):
                db_logger.warning(f"Invalid key: {key}")
                return
            cls._cursor.execute(f"""
                                UPDATE stats
                                SET
                                    {key} = {key} + ?,
                                    last_updated = CURRENT_TIMESTAMP
                                WHERE id = 1
                                """, (count,))
            cls._conn.commit()

    @classmethod
    def close(cls):
        with cls._lock:
            if cls._conn and cls._cursor:
                cls._cursor.close()
                cls._conn.close()
                cls._cursor = None
                cls._conn = None
