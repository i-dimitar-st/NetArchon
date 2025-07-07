from logging import Logger
from threading import RLock, Event, Thread
from services.dhcp.db_core import DHCPStorage, DHCPStats
from services.dhcp.client_discovery import ClientDiscoveryService
from functools import wraps
from config.config import config

DHCP_CONFIG = config.get("dhcp")
DB_PERSISTANCE = DHCP_CONFIG.get("db_persistance")
DB_PERSISTENCE_INTERVAL = DB_PERSISTANCE.get("interval")
WORKER_JOIN_TIMEOUT = DB_PERSISTANCE.get("worker_join_timeout")


def is_init(func):
    @wraps(func)
    def wrapper(cls, *args, **kwargs):
        if not getattr(cls, "initialized", False):
            raise RuntimeError("Init first")
        return func(cls, *args, **kwargs)

    return wrapper


def is_running(func):
    @wraps(func)
    def wrapper(cls, *args, **kwargs):
        if not getattr(cls, "running", False):
            raise RuntimeError("Not running")
        return func(cls, *args, **kwargs)

    return wrapper


class DbPersistanceService:
    _lock = RLock()
    _stop_event = Event()
    _worker = None
    _interval = None
    initialized = False
    running = False

    @classmethod
    def init(cls, logger: Logger, interval=float(DB_PERSISTENCE_INTERVAL)):
        with cls._lock:
            cls._worker = None
            cls._interval = interval
            cls.logger: Logger = logger
            cls.initialized = True

    @classmethod
    @is_init
    def start(cls):
        with cls._lock:
            if cls.running:
                raise RuntimeError("Already running")
            if cls._worker is not None:
                raise RuntimeError("Already running")

            cls._stop_event.clear()
            cls.running = True
            cls._worker = Thread(target=cls._work, daemon=True)
            cls._worker.start()
            cls.logger.debug("%s Started.", cls.__name__)

    @classmethod
    @is_init
    @is_running
    def stop(cls):
        with cls._lock:
            cls._stop_event.set()
            if cls._worker is not None:
                cls._worker.join(timeout=WORKER_JOIN_TIMEOUT)
                if cls._worker.is_alive():
                    cls.logger.warning("%s did not stop after timeout.", cls.__name__)
                else:
                    cls.logger.debug("%s Stopped.", cls.__name__)
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
                                lease_type="static",
                            )

                    DHCPStorage.save_to_disk()
                    DHCPStats.save_to_disk()

            except Exception as err:
                cls.logger.warning("Error: %s", err)

            cls._stop_event.wait(cls._interval)
