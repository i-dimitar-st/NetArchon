from functools import wraps
from logging import Logger
from pathlib import Path
from sqlite3 import Connection, Cursor, connect
from threading import RLock
from time import time

from app.config.config import config, dhcp_static_config
from app.services.dhcp.models import DHCPLeasesSchema, DHCPLeaseType

PATHS = config.get("paths")
ROOT_PATH = Path(PATHS.get("root"))
DB_PATH = ROOT_PATH / PATHS.get("database")

DHCP_CONFIG = config.get("dhcp").get("config")
DB_CONFIG = config.get("database")

DEFAULT_HOSTNAME = DHCP_CONFIG.get("default_hostname")
LEASE_TIME = int(DHCP_CONFIG.get("lease_time_seconds"))

DHCP_DB_CONFIG = DB_CONFIG.get("dhcp")
DB_LEASES_PATH = DB_PATH / DHCP_DB_CONFIG.get("leases").get("path")


def is_init(func):
    """
    Decorator to verify DB connection, cursor are initialized.
    """

    @wraps(func)
    def wrapper(cls, *args, **kwargs):
        if not isinstance(getattr(cls, "_conn", None), Connection):
            raise RuntimeError("DB connection not initialized or invalid.")
        if not isinstance(getattr(cls, "_cursor", None), Cursor):
            raise RuntimeError("DB cursor not initialized or invalid.")
        return func(cls, *args, **kwargs)

    return wrapper


class DHCPStorage:
    """
    Purpose:
        Manage DHCP lease records in an in-memory SQLite database.
        Supports adding, querying, removing, and cleaning up DHCP leases.
        Ensures thread-safe operations with a class-level lock.

    Dependencies:
        - sqlite3 (Python standard library): in-memory + file-based database ops.
        - threading.RLock: to guarantee thread-safe access to the database.
        - logging.Logger: for logging events, errors, and debugging info.
        - config.config: configurations like default lease time and hostname.
        - models.models.DBSchemas: provides the SQL schema for the leases table.
        - LeaseType (enum): defines lease types as 'static' or 'dynamic'.

    Usage:
        1. Initialize the storage before use:
            DHCPStorage.init(logger)
        2. Add or update leases:
            DHCPStorage.add_lease(mac, ip, hostname, lease_time, lease_type)
        3. Query leases by MAC or IP:
            DHCPStorage.get_lease_by_mac(mac)
            DHCPStorage.get_mac_by_ip(ip)
        4. Get all leases or all leased IPs:
            DHCPStorage.get_all_leases()
            DHCPStorage.get_all_leased_ips()
        5. Remove leases by MAC or multiple MACs:
            DHCPStorage.remove_lease_by_mac(mac)
            DHCPStorage.remove_leases_by_macs(set_of_macs)
        6. Cleanup expired leases:
            DHCPStorage.remove_expired_leases()
        7. Persist in-memory DB to disk:
            DHCPStorage.save_to_disk(path)
        8. Close the database cleanly:
            DHCPStorage.close()

    Notes:
        - Must call `init()` before using any other method.
        - All database operations are thread-safe.
        - Lease types are stored as strings derived from the LeaseType enum.
    """

    _lock = RLock()

    @classmethod
    def init(cls, logger: Logger):
        """
        Initialize in-memory SQLite DB and prepare schema.
        Create table.
        Args:
            logger (Logger): Logger instance for debug/warning output.
        """
        if getattr(cls, "_conn", None) is not None or getattr(cls, "_cursor", None) is not None:
            raise RuntimeError("Already init")

        with cls._lock:

            _conn: Connection = connect(":memory:", check_same_thread=False)
            _cursor: Cursor = _conn.cursor()
            _cursor.execute(DHCPLeasesSchema.schema)
            _conn.commit()

            cls.logger: Logger = logger
            cls._conn: Connection = _conn
            cls._cursor: Cursor = _cursor
            cls.logger.debug("%s initialized.", cls.__name__)

    @classmethod
    @is_init
    def save_to_disk(cls, path=DB_LEASES_PATH):
        """
        Persist the in-memory database to disk file.
        Args:
            path (Path): Destination file path (default configured path).
        """
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
        lease_type: DHCPLeaseType = DHCPLeaseType.STATIC,
    ):
        """
        Add or update a DHCP lease entry in the database.

        Args:
            mac (str): MAC address of the client device.
            ip (str): IP address assigned to the client.
            hostname (str, optional): Client hostname, def to DEFAULT_HOSTNAME.
            lease_time (int, optional): Lease duration (sec), def to LEASE_TIME.
            lease_type (LeaseType, optional): Lease type, static or dynamicm def static.

        Behavior:
            - Inserts a new lease or replaces existing entry matching MAC/IP.
            - Sets current timestamp and calculates expiry time.
            - Stores lease_type as string value in DB.
            - Thread-safe; uses class-level lock.
            - Logs success or errors, with error stack trace on failure.
        """

        with cls._lock:
            try:

                if dhcp_static_config.get_config().get(mac.upper()):
                    lease_type = DHCPLeaseType.STATIC

                _current_time = int(time())
                _expiry_time = int(_current_time + lease_time)

                _statement = """
                    INSERT OR REPLACE INTO
                    leases (mac, ip, hostname, timestamp, expiry_time, type)
                    VALUES (?, ?, ?, ?, ?, ?)
                """

                _values: tuple[str, str, str, int, int, str] = (
                    mac,
                    ip,
                    hostname,
                    _current_time,
                    _expiry_time,
                    lease_type.value,
                )
                cls._cursor.execute(_statement, _values)
                cls._conn.commit()
                cls.logger.info("Added MAC:%s IP:%s.", mac, ip)

            except Exception as err:
                cls.logger.error("Error adding lease %s.", err)

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
                cls.logger.info(f"Lease DB removed {_result.rowcount} MAC:{mac}")

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
                    cls.logger.info(
                        f"DB: Deleted {_result.rowcount} leases, del MACs: {set(macs)}."
                    )
            except Exception as err:
                cls.logger.error(f"DB -> failed to remove leases: {str(err)}")

    @classmethod
    @is_init
    def remove_expired_leases(cls):
        """Remove expired leases."""
        with cls._lock:
            try:
                cls._cursor.execute("DELETE FROM leases WHERE expiry_time < ?", (int(time()),))
                cls._conn.commit()
                if cls._cursor.rowcount:
                    cls.logger.info("Deleted %s expired leases.", cls._cursor.rowcount)
            except Exception as err:
                cls.logger.error("Error during lease cleanup: %s", err)

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
    def get_all_leased_ips(cls) -> set[str]:
        """Get a list of currently leased IPs."""

        with cls._lock:
            try:
                return {
                    lease[0] for lease in cls._cursor.execute("SELECT ip FROM leases").fetchall()
                }
            except Exception as _err:
                cls.logger.error("Failed to get active leases: %s.", _err)
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
