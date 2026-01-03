import threading
from typing import Optional

from src.config.config import config
from src.services.dns.db import DnsQueryHistoryDb, DnsStatsDb

DNS_CONFIG = config.get("dns").get("config")
DB_FLUSH_INTERVAL = int(DNS_CONFIG.get("db_flush_interval", 30))

class DbPersistanceService:
    """Background service that periodically flushes in-memory DNS databases to disk.
    Runs as dedicated thread saving of DnsStatsDb and DnsQueryHistoryDb
        at a configured interval.
    """

    _lock = threading.Lock()
    _stop_event = threading.Event()
    _worker: Optional[threading.Thread] = None
    _interval: Optional[int] = None

    @classmethod
    def init(cls, logger, interval: int = DB_FLUSH_INTERVAL):
        """Initialize the flush service with the given interval (seconds).
        """
        with cls._lock:
            cls.logger = logger
            cls._interval = interval

    @classmethod
    def start(cls):
        """Fresh start of new background worker."""
        with cls._lock:
            if not cls._interval:
                raise RuntimeError("Not init")
            if cls._worker and cls._worker.is_alive():
                raise RuntimeError("Already started")
            cls._stop_event.clear()
            cls._worker = threading.Thread(target=cls._run, daemon=True)
            cls._worker.start()
            cls.logger.info(f"{cls.__name__} started.")

    @classmethod
    def stop(cls):
        """Stop the background flush thread and wait for it to finish.
        Resets worker.
        """
        with cls._lock:
            cls._stop_event.set()
            if cls._worker and cls._worker.is_alive():
                cls._worker.join(timeout=1)
                cls._worker = None
        cls.logger.info(f"{cls.__name__} stopped.")

    @classmethod
    def restart(cls):
        """Restart the flush service."""
        cls.stop()
        cls.start()

    @classmethod
    def _run(cls):
        """Main worker.
        Periodically calls save_to_disk on DnsStatsDb and DnsQueryHistoryDb,
        catching and logging any exceptions.
        """
        while not cls._stop_event.is_set():
            try:
                DnsStatsDb.save_to_disk()
                DnsQueryHistoryDb.save_to_disk()
            except Exception as err:
                cls.logger.warning(f"DB persistence error: {str(err)}.")
            cls._stop_event.wait(cls._interval)
