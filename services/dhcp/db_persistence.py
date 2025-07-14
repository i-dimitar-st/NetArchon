from functools import wraps
from logging import Logger
from threading import Event, RLock, Thread

from config.config import config
from services.dhcp.client_discovery import ClientDiscoveryService
from services.dhcp.db_dhcp_leases import DHCPStorage
from services.dhcp.db_dhcp_stats import DHCPStats
from services.dhcp.models import DHCPLeaseType

DB_CONFIG = config.get("database")
PERSISTANCE_INTERVAL = float(DB_CONFIG.get("persistence_interval"))
WORKER_JOIN_TIMEOUT = float(DB_CONFIG.get("persistance_worker_join_timeout"))


def is_init(func):
    """Is service initialized"""

    @wraps(func)
    def wrapper(cls, *args, **kwargs):
        if not getattr(cls, "initialized", False):
            raise RuntimeError("Init first")
        return func(cls, *args, **kwargs)

    return wrapper


def is_running(func):
    """Is service running"""

    @wraps(func)
    def wrapper(cls, *args, **kwargs):
        if not getattr(cls, "running", False):
            raise RuntimeError("Not running")
        return func(cls, *args, **kwargs)

    return wrapper


class DbPersistanceService:
    """
    Background worker persists DHCP lease and statistics data to disk at defined intervals.

    Responsibilities:
        - Periodically save in-memory DHCP lease data and client discovery results to db.
        - Removes expired leases and adds static entries for live clients not already recorded.
        - Runs a background thread to perform the above operations at configured intervals.
        - Supports lifecycle control via `init`, `start`, and `stop` classmethods.

    Dependencies:
        - config.config: Provides DHCP configuration values (intervals, timeouts).
        - services.dhcp.db_core.DHCPStorage: Interface to in-memory and persistent lease storage.
        - services.dhcp.db_core.DHCPStats: Interface to persistent statistics storage.
        - services.dhcp.client_discovery.ClientDiscoveryService: list of live DHCP clients.
        - Python stdlib: threading (RLock, Event, Thread), logging, functools (wraps)

    Usage:
        1. Call `DbPersistanceService.init(logger)` to configure the service.
        2. Call `DbPersistanceService.start()` to begin periodic sync.
        3. Call `DbPersistanceService.stop()` to cleanly shut down the background worker.

    Raises:
        RuntimeError if `start` or `stop` is called without initialization, or if misuse occurs.
    """

    _lock = RLock()
    _stop_event = Event()
    _worker: Thread | None = None
    _interval: float
    initialized: bool = False
    running: bool = False
    logger: Logger

    @classmethod
    def init(cls, logger: Logger, interval: float = PERSISTANCE_INTERVAL):
        """
        Initialize the db sync worker service.
        Args:
            logger: Logger instance for logging events.
            interval: float time in sec for which data will be synced to local db.
        """
        with cls._lock:
            cls._worker = None
            cls._interval = interval
            cls.logger = logger
            cls.initialized = True
            cls.logger.debug("%s initialized.", cls.__name__)

    @classmethod
    @is_init
    def start(cls):
        """
        Start db persistance worker.
        Raises:
            RuntimeError: If already running or not initialized.
        """
        with cls._lock:
            if cls.running:
                raise RuntimeError("Already running")
            if cls._worker is not None:
                raise RuntimeError("Already running")

            cls._stop_event.clear()
            cls.running = True
            cls._worker = Thread(target=cls._work, daemon=True)
            cls._worker.start()
            cls.logger.debug("%s started.", cls.__name__)

    @classmethod
    @is_init
    @is_running
    def stop(cls):
        """
        Stop db persistance worker.
        Raises:
            RuntimeError: If not running or not initialized.
        """
        with cls._lock:
            cls._stop_event.set()
            if cls._worker is not None:
                cls._worker.join(timeout=WORKER_JOIN_TIMEOUT)
                if cls._worker.is_alive():
                    cls.logger.warning("%s didnt respect timeout.", cls.__name__)
                else:
                    cls.logger.debug("%s stopped.", cls.__name__)
            cls._worker = None
            cls.running = False

    @classmethod
    @is_init
    @is_running
    def _work(cls):

        if cls._stop_event is None:
            raise RuntimeError("Stop event missing")

        while not cls._stop_event.is_set():
            try:
                with cls._lock:

                    DHCPStorage.remove_expired_leases()

                    _active_macs = {lease[0] for lease in DHCPStorage.get_all_leases()}

                    for _live_client in ClientDiscoveryService.get_live_clients():
                        if _live_client.mac not in _active_macs:
                            DHCPStorage.add_lease(
                                mac=_live_client.mac,
                                ip=_live_client.ip,
                                lease_type=DHCPLeaseType.STATIC,
                            )

                    DHCPStorage.save_to_disk()
                    DHCPStats.save_to_disk()

            except Exception as err:
                cls.logger.warning("Error: %s", err)

            cls._stop_event.wait(cls._interval)
