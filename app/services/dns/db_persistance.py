from threading import Event, Lock, Thread
from typing import Optional

from app.config.config import config
from app.services.dns.db import DnsQueryHistoryDb, DnsStatsDb

DNS_CONFIG = config.get("dns").get("config")
DB_FLUSH_INTERVAL = int(DNS_CONFIG.get("db_flush_interval", 30))

TIMEOUTS = config.get("dns").get("timeouts")
WORKER_JOIN_TIMEOUT = float(TIMEOUTS.get("worker_join", 1))


class DbPersistanceService:
    """
    Background service that periodically flushes in-memory DNS databases to disk.
    Runs as dedicated thread saving of DnsStatsDb and DnsQueryHistoryDb
        at a configured interval.
    """

    _lock = Lock()
    _stop_event = Event()
    _worker: Optional[Thread] = None
    _interval: Optional[int] = None

    @classmethod
    def init(cls, logger, interval: int = DB_FLUSH_INTERVAL):
        """
        Initialize the flush service with the given interval (seconds).
        """
        with cls._lock:
            cls.logger = logger
            cls._interval = interval

    @classmethod
    def start(cls):
        """
        Fresh start of new background worker.
        """
        with cls._lock:
            if not cls._interval:
                raise RuntimeError("Not init")
            if cls._worker and cls._worker.is_alive():
                raise RuntimeError("Already started")
            cls._stop_event.clear()
            cls._worker = Thread(target=cls._work, daemon=True)
            cls._worker.start()
            cls.logger.info("%s started.", cls.__name__)

    @classmethod
    def stop(cls):
        """
        Stop the background flush thread and wait for it to finish.
        Resets worker.
        """
        with cls._lock:
            cls._stop_event.set()
            if cls._worker:
                cls._worker.join(timeout=WORKER_JOIN_TIMEOUT)
                cls._worker = None
        cls.logger.info("%s stopped.", cls.__name__)

    @classmethod
    def restart(cls):
        """
        Restart the flush service
        """
        cls.stop()
        cls.start()

    @classmethod
    def _work(cls):
        """
        Main worker.
        Periodically calls save_to_disk on DnsStatsDb and DnsQueryHistoryDb,
        catching and logging any exceptions.
        """
        while not cls._stop_event.is_set():
            try:
                DnsStatsDb.save_to_disk()
                DnsQueryHistoryDb.save_to_disk()
            except Exception as _err:
                cls.logger.warning("Persistence error: %s.", _err)
            cls._stop_event.wait(cls._interval)
