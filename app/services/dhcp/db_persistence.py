from functools import wraps
from logging import Logger
from threading import Event, RLock, Thread

from app.config.config import config
from app.services.dhcp.client_discovery import ClientDiscoveryService
from app.services.dhcp.db_dhcp_leases import DHCPStorage
from app.services.dhcp.db_dhcp_stats import DHCPStats
from app.services.dhcp.models import DHCPArpClient, DHCPLeaseType

DB_CONFIG = config.get("database")
PERSISTANCE_INTERVAL = float(DB_CONFIG.get("persistence_interval"))
WORKER_JOIN_TIMEOUT = float(DB_CONFIG.get("persistance_worker_join_timeout"))


def _get_stale_leases_by_type(
    live_macs: set[str], lease_type=DHCPLeaseType.MANUAL.value
) -> set:
    """
    Checks current leased macs agaisn the current db leases.

    Args:
        live_macs (set[str]): Set of currently live MAC addresses.
    """
    return {
        _lease[0]
        for _lease in DHCPStorage.get_all_leases()
        if _lease[5] == lease_type and _lease[0] not in live_macs
    }


def get_active_macs() -> set:
    """Retrieve all MAC addresses currently stored in DHCP leases."""
    return {_lease[0] for _lease in DHCPStorage.get_all_leases()}


def _add_manual_leases(active_macs: set[str], live_clients: set[DHCPArpClient]):
    """
    Add manual DHCP leases for live clients not already in active leases.

    Args:
        active_macs (set[str]): Set of MAC addresses currently leased.
        live_clients (set[DHCPArpClient]): Set of live DHCP clients to potentially add.
    """
    for client in live_clients:
        if client.mac not in active_macs:
            DHCPStorage.add_lease(
                mac=client.mac,
                ip=client.ip,
                lease_type=DHCPLeaseType.MANUAL,
            )


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
    Background worker saves DHCP lease + stats data to disk at intervals.

    Responsibilities:
        - Periodically save in-memory DHCP lease + client discovery results to db.
        - Removes expired leases
        - Adds static entries for live clients not already recorded.
        - Supports lifecycle control via `init`, `start`, and `stop` classmethods.

    Dependencies:
        - config.config: Provides DHCP configuration values (intervals, timeouts).
        - services.dhcp.db_core.DHCPStorage: In-memory and persistent lease storage.
        - services.dhcp.db_core.DHCPStats: Persistent statistics storage.
        - services.dhcp.client_discovery.ClientDiscoveryService: Live DHCP clients.
        - Python stdlib: threading (RLock, Event, Thread), logging, functools (wraps)

    Usage:
        1. Call `DbPersistanceService.init(logger)` Configure service.
        2. Call `DbPersistanceService.start()` Periodic sync.
        3. Call `DbPersistanceService.stop()` Shutdown background worker.
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
                cls.logger.debug("%s stopped.", cls.__name__)
            cls._worker = None
            cls.running = False

    @classmethod
    @is_init
    @is_running
    def _work(cls):

        while not cls._stop_event.is_set():
            try:
                with cls._lock:

                    # Clean expired
                    DHCPStorage.remove_expired_leases()

                    _live_clients: set[DHCPArpClient] = (
                        ClientDiscoveryService.get_live_clients()
                    )
                    _live_macs: set[str] = {client.mac for client in _live_clients}

                    # Remove stale manual leases first, then re-fetch active ones
                    # to ensure we don't re-add just-removed entries
                    DHCPStorage.remove_leases_by_macs(
                        macs=_get_stale_leases_by_type(live_macs=_live_macs)
                    )
                    _add_manual_leases(
                        active_macs=get_active_macs(), live_clients=_live_clients
                    )

                    DHCPStorage.save_to_disk()
                    DHCPStats.save_to_disk()

            except Exception as err:
                cls.logger.warning("Error: %s", err)

            cls._stop_event.wait(cls._interval)
