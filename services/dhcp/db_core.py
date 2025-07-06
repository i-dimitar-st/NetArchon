from sqlite3 import Connection, Cursor, connect
from functools import wraps
from time import time
from logging import Logger
from threading import RLock
from pathlib import Path
from config.config import config
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


def is_init(func):
    @wraps(func)
    def wrapper(cls, *args, **kwargs):
        if not isinstance(getattr(cls, "_conn", None), Connection):
            raise RuntimeError("DB connection not initialized or invalid.")
        if not isinstance(getattr(cls, "_cursor", None), Cursor):
            raise RuntimeError("DB cursor not initialized or invalid.")
        return func(cls, *args, **kwargs)

    return wrapper


class DHCPStorage:

    _lock = RLock()

    @classmethod
    def init(cls, logger: Logger):
        if (
            getattr(cls, "_conn", None) is not None
            or getattr(cls, "_cursor", None) is not None
        ):
            raise RuntimeError("Already init")

        with cls._lock:
            try:
                _conn: Connection = connect(":memory:", check_same_thread=False)
                _cursor: Cursor = _conn.cursor()
                _cursor.execute(DBSchemas.dhcpLeases)
                _conn.commit()
                cls._conn: Connection = _conn
                cls._cursor: Cursor = _cursor
                cls.logger: Logger = logger
                cls.logger.debug("%s initialized.", cls.__name__)
            except Exception as _err:
                if _conn:
                    _conn.close()
                cls.logger.debug("Faild to initialize %s : %s.", cls.__name__, _err)

    @classmethod
    @is_init
    def save_to_disk(cls, path=DB_LEASES_FULLPATH):
        with cls._lock:
            _conn_disk: Connection = connect(path)
            cls._conn.backup(_conn_disk)
            _conn_disk.close()

    @classmethod
    @is_init
    def add_lease(
        cls,
        mac: str,
        ip: str,
        hostname: str = "unknown",
        lease_time: int = LEASE_TIME,
        lease_type: str = "dynamic",
    ) -> None:

        with cls._lock:
            try:
                _current_time = int(time())
                _expiry_time = int(_current_time + lease_time)

                _statement = """
                    INSERT OR REPLACE INTO 
                    leases (mac, ip, hostname, timestamp, expiry_time, type)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """
                _values = (mac, ip, hostname, _current_time, _expiry_time, lease_type)
                cls._cursor.execute(_statement, _values)
                cls._conn.commit()
                cls.logger.debug(f"Added MAC:{mac} IP:{ip}")

            except Exception as err:
                cls.logger.error(f"Failed to add lease: {str(err)}")

    @classmethod
    @is_init
    def get_lease_by_mac(cls, mac: str) -> tuple | None:
        """Get the IP address assigned to a given MAC address."""

        with cls._lock:
            try:
                return cls._cursor.execute(
                    """
                    SELECT *
                    FROM leases
                    WHERE mac = ?
                    """,
                    (mac,),
                ).fetchone()

            except Exception as err:
                cls.logger.error(f"Failed to get lease for {mac} {str(err)}")

            return None

    @classmethod
    @is_init
    def get_mac_by_ip(cls, ip: str) -> str | None:
        """Get the MAC address assigned to a given IP address."""
        with cls._lock:
            try:
                _statement = "SELECT mac FROM leases WHERE ip = ?"
                _value = (ip,)

                cls._cursor.execute(_statement, _value)
                result = cls._cursor.fetchone()
                return result[0] if result else None

            except Exception as err:
                cls.logger.error(f"Failed to get lease for {ip} {str(err)}")
                return None

    @classmethod
    @is_init
    def get_all_leased_ips(cls) -> set:
        """Get a list of currently leased IPs."""

        with cls._lock:
            try:
                return {
                    lease[0]
                    for lease in cls._cursor.execute("SELECT ip FROM leases").fetchall()
                }
            except Exception as e:
                cls.logger.error(f"Failed to get active leases: {e}")
                return set()

    @classmethod
    @is_init
    def get_all_leases(cls) -> list:
        """Get all leases"""

        with cls._lock:
            try:
                return cls._cursor.execute("SELECT * FROM leases").fetchall()
            except Exception as err:
                cls.logger.error(f"Failed to get active leases: {str(err)}")
                return []

    @classmethod
    @is_init
    def remove_lease_by_mac(cls, mac: str):
        """Remove a lease from the database."""

        with cls._lock:
            try:
                _result: Cursor = cls._cursor.execute(
                    """
                    DELETE
                    FROM leases
                    WHERE mac = ?
                    """,
                    (mac,),
                )
                cls._conn.commit()
                if _result.rowcount:
                    cls.logger.debug(f"Lease DB removed {_result.rowcount} MAC:{mac}")

            except Exception as err:
                cls.logger.error(f"DB -> failed to remove lease: {str(err)}")

    @classmethod
    @is_init
    def remove_leases_by_macs(cls, macs: set):
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
                _result: Cursor = cls._cursor.execute(_statement, _value)
                cls._conn.commit()
                if _result.rowcount:
                    cls.logger.debug(
                        f"DB -> Deleted {_result.rowcount} lease(s). Removed MACs: {set(macs)}."
                    )
            except Exception as err:
                cls.logger.error(f"DB -> failed to remove leases: {str(err)}")

    @classmethod
    @is_init
    def remove_expired_leases(cls):
        """Remove expired leases."""
        with cls._lock:
            try:
                cls._cursor.execute(
                    "DELETE FROM leases WHERE expiry_time < ?", (int(time()),)
                )
                cls._conn.commit()
                if cls._cursor.rowcount:
                    cls.logger.debug("Deleted %s expired leases.", cls._cursor.rowcount)
            except Exception as err:
                cls.logger.error("Error during lease cleanup: %s", err)

    @classmethod
    @is_init
    def close(cls):
        with cls._lock:
            if cls._cursor:
                cls._cursor.close()
            if cls._conn:
                cls._conn.close()
            cls.logger.debug("DHCPStorage shutdown completed")


class DHCPStats:

    _lock = RLock()
    _valid_columns = set()

    @staticmethod
    def _is_init(func):
        def wrapper(cls, *args, **kwargs):
            if not isinstance(getattr(cls, "_conn", None), Connection):
                raise RuntimeError("DB connection not initialized or invalid.")
            if not isinstance(getattr(cls, "_cursor", None), Cursor):
                raise RuntimeError("DB cursor not initialized or invalid.")
            return func(cls, *args, **kwargs)

        return wrapper

    @classmethod
    def init(cls, logger: Logger):

        if (
            getattr(cls, "_conn", None) is not None
            or getattr(cls, "_cursor", None) is not None
        ):
            raise RuntimeError("Already init")

        with cls._lock:
            cls.logger: Logger = logger
            cls._conn: Connection = connect(
                database=":memory:", check_same_thread=False
            )
            cls._cursor: Cursor = cls._conn.cursor()
            cls._create_table()

    @classmethod
    @_is_init
    def _create_table(cls):

        with cls._lock:
            cls._cursor.execute(DBSchemas.dhcpStats)
            cls._conn.commit()
            cls._cursor.execute(
                """
                INSERT OR IGNORE
                INTO stats (id,start_time)
                VALUES (1, ?)
                """,
                (int(time()),),
            )
            cls._conn.commit()
            cls._valid_columns.update(
                {
                    col[1]
                    for col in cls._cursor.execute(
                        "PRAGMA table_info(stats)"
                    ).fetchall()
                }
            )

    @classmethod
    @_is_init
    def _is_key_valid(cls, key: str) -> bool:
        if not cls._valid_columns:
            return False
        return bool(key in cls._valid_columns)

    @classmethod
    @_is_init
    def increment(cls, key: str, count: int = 1):

        if not cls._is_key_valid(key):
            return

        with cls._lock:
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
    @_is_init
    def save_to_disk(cls, path: Path = DB_STATS_FULLPATH):
        with cls._lock:
            _conn_disk: Connection = connect(path)
            cls._conn.backup(_conn_disk)
            _conn_disk.close()

    @classmethod
    @_is_init
    def close(cls):
        with cls._lock:
            if cls._cursor:
                cls._cursor.close()
            if cls._conn:
                cls._conn.close()
