import threading
import time
import sqlite3
from pathlib import Path
from typing import Optional
from config.config import config
from services.logger.logger import MainLogger
from models.models import DBSchemas

PATHS = config.get("paths")
ROOT_PATH = Path(PATHS.get("root"))
DB_PATH = ROOT_PATH / PATHS.get("database")

DHCP_CONFIG = config.get("dhcp")
DB_CONFIG = config.get("database")
DHCP_DB_CONFIG = DB_CONFIG.get("dhcp")

DB_LEASES_FULLPATH = DB_PATH / DHCP_DB_CONFIG.get("leases").get("path")
DB_STATS_FULLPATH = DB_PATH / DHCP_DB_CONFIG.get("stats").get("path")

LEASE_TIME = int(DHCP_CONFIG.get("lease_time_seconds"))

_logger = MainLogger.get_logger(service_name="DHCP_DB", log_level="debug")


class DHCPStorage:

    _lock = threading.RLock()
    _conn: Optional[sqlite3.Connection] = None
    _cursor: Optional[sqlite3.Cursor] = None
    _running = False

    @classmethod
    def init(cls):

        if cls._running:
            return

        with cls._lock:
            cls._conn = sqlite3.connect(":memory:", check_same_thread=False)
            cls._cursor = cls._conn.cursor()
            cls._create_tables()
            cls._running = True

    @classmethod
    def _is_init(cls):
        return bool(cls._running and cls._conn and cls._cursor)

    @classmethod
    def _create_tables(cls):

        with cls._lock:
            try:
                if cls._cursor and cls._conn:
                    cls._cursor.execute(DBSchemas.dhcpLeases)
                    cls._conn.commit()
                    _logger.debug("Leases DB initialized")
            except Exception as err:
                _logger.error(f"Failed to initialize DHCP Leases: {str(err)}")

    @classmethod
    def save_to_disk(cls):

        with cls._lock:
            try:
                if cls._conn:
                    with sqlite3.connect(DB_LEASES_FULLPATH) as _conn_disk:
                        cls._conn.backup(_conn_disk)
            except Exception as err:
                _logger.warning(f"Error during cache backup: {str(err)}")

    @classmethod
    def add_lease(
        cls,
        mac: str,
        ip: str,
        hostname: str = 'unknown',
        lease_time: int = LEASE_TIME,
        lease_type: str = 'dynamic',
    ) -> None:

        with cls._lock:
            try:
                _current_time = int(time.time())
                _expiry_time = int(_current_time + lease_time)

                _statement = """
                    INSERT OR REPLACE INTO 
                    leases (mac, ip, hostname, timestamp, expiry_time, type)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """
                _values = (mac, ip, hostname, _current_time, _expiry_time, lease_type)
                if cls._cursor and cls._conn:
                    cls._cursor.execute(_statement, _values)
                    cls._conn.commit()
                    _logger.debug(f"Added MAC:{mac} IP:{ip}")

            except Exception as err:
                _logger.error(f"Failed to add lease: {str(err)}")

    @classmethod
    def get_lease_by_mac(cls, mac: str) -> tuple | None:
        """Get the IP address assigned to a given MAC address."""

        with cls._lock:
            try:
                _statement = """
                            SELECT *
                            FROM leases
                            WHERE mac = ?
                            """
                _values = (mac,)
                if cls._cursor:
                    return cls._cursor.execute(_statement, _values).fetchone()

            except Exception as err:
                _logger.error(f"Failed to get lease for {mac} {str(err)}")

            return None

    @classmethod
    def get_mac_by_ip(cls, ip: str) -> str | None:
        """Get the MAC address assigned to a given IP address."""

        with cls._lock:
            try:
                _statement = "SELECT mac FROM leases WHERE ip = ?"
                _value = (ip,)

                if cls._cursor:
                    cls._cursor.execute(_statement, _value)
                    result = cls._cursor.fetchone()
                    return result[0] if result else None
                else:
                    return None

            except Exception as err:
                _logger.error(f"Failed to get lease for {ip} {str(err)}")
                return None

    @classmethod
    def get_all_leased_ips(cls) -> set:
        """Get a list of currently leased IPs."""

        with cls._lock:
            try:
                if cls._cursor:
                    _result = cls._cursor.execute('SELECT ip FROM leases').fetchall()
                    return {lease[0] for lease in _result}
                else:
                    return set()
            except Exception as e:
                _logger.error(f"Failed to get active leases: {e}")
                return set()

    @classmethod
    def get_all_leases(cls) -> list:
        """Get all leases"""

        with cls._lock:
            try:
                if cls._cursor:
                    return cls._cursor.execute('SELECT * FROM leases').fetchall()
                else:
                    return []
            except Exception as err:
                _logger.error(f"Failed to get active leases: {str(err)}")
                return []

    @classmethod
    def remove_lease_by_mac(cls, mac: str):
        """Remove a lease from the database."""

        with cls._lock:
            try:

                if cls._cursor and cls._conn:
                    _result = cls._cursor.execute("""DELETE FROM leases WHERE mac = ?""", (mac,))
                    cls._conn.commit()
                    if _result.rowcount:
                        _logger.debug(f"Lease DB removed {_result.rowcount} MAC:{mac}")

            except Exception as err:
                _logger.error(f"DB -> failed to remove lease: {str(err)}")

    @classmethod
    def remove_leases_by_mac(cls, macs: set):
        """Remove multiple leases from the database based on a set of MAC addresses."""

        if not macs:
            return

        with cls._lock:
            try:
                _value = tuple(macs)
                _statement = f"""
                    DELETE
                    FROM leases
                    WHERE mac IN ({",".join(["?"] * len(_value))})
                    """
                if cls._cursor and cls._conn:
                    _result = cls._cursor.execute(_statement, _value)
                    cls._conn.commit()
                    if _result.rowcount:
                        _logger.debug(
                            f"DB -> Deleted {_result.rowcount} lease(s). Removed MACs: {set(macs)}."
                        )

            except Exception as err:
                _logger.error(f"DB -> failed to remove leases: {str(err)}")

    @classmethod
    def remove_expired_leases(cls):
        """Remove expired leases."""

        with cls._lock:
            try:
                if cls._cursor and cls._conn:
                    cls._cursor.execute(
                        "DELETE FROM leases WHERE expiry_time < ?", (int(time.time()),)
                    )
                    cls._conn.commit()
                    if cls._cursor.rowcount:
                        _logger.debug(f"Found/deleted {cls._cursor.rowcount} expired leases.")
            except Exception as err:
                _logger.error(f"Error during lease cleanup: {str(err)}")

    @classmethod
    def close(cls):
        with cls._lock:
            if cls._cursor:
                cls._cursor.close()
            if cls._conn:
                cls._conn.close()
            cls._running = False
            _logger.debug("DHCPStorage shutdown completed")


class DHCPStats:

    _lock = threading.RLock()
    _conn: Optional[sqlite3.Connection] = None
    _cursor: Optional[sqlite3.Cursor] = None
    _running = False
    _valid_columns = set()

    @classmethod
    def init(cls):

        if cls._running:
            return
        with cls._lock:
            if not cls._conn:
                cls._conn = sqlite3.connect(database=":memory:", check_same_thread=False)
            if not cls._cursor:
                cls._cursor = cls._conn.cursor()
            cls._create_table()
            cls._running = True

    @classmethod
    def _create_table(cls):

        with cls._lock:
            if cls._cursor and cls._conn:
                cls._cursor.execute(DBSchemas.dhcpStats)
                cls._conn.commit()
                cls._cursor.execute(
                    """
                                    INSERT OR IGNORE
                                    INTO stats (id,start_time)
                                    VALUES (1, ?)
                                    """,
                    (int(time.time()),),
                )
                cls._conn.commit()
                columns_info = cls._cursor.execute("PRAGMA table_info(stats)").fetchall()
                cls._valid_columns.update({col[1] for col in columns_info})

    @classmethod
    def _is_key_valid(cls, key: str) -> bool:

        if not cls._valid_columns:
            return False
        return bool(key in cls._valid_columns)

    @classmethod
    def increment(cls, key: str, count: int = 1):

        if not cls._is_key_valid(key):
            return

        with cls._lock:
            if cls._cursor and cls._conn:
                cls._cursor.execute(
                    f"""
                                    UPDATE stats
                                    SET {key} = {key} + ?,
                                        last_updated = ?
                                    WHERE id = 1
                                    """,
                    (count, int(time.time())),
                )
                cls._conn.commit()

    @classmethod
    def save_to_disk(cls):
        with cls._lock:
            try:
                if cls._conn:
                    with sqlite3.connect(DB_STATS_FULLPATH) as _disk_conn:
                        cls._conn.backup(_disk_conn)
            except Exception as err:
                _logger.warning(f"Error during cache backup: {str(err)}")

    @classmethod
    def close(cls):
        cls._running = False
        with cls._lock:
            if cls._cursor:
                cls._cursor.close()
            if cls._conn:
                cls._conn.close()
