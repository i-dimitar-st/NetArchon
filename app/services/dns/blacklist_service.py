from fnmatch import fnmatch
from functools import lru_cache
from pathlib import Path
from threading import Event, RLock, Thread

from app.config.config import config, dns_blacklists

PATHS = config.get("paths")
ROOT_PATH = Path(PATHS.get("root"))

BLACKLISTS_CONFIG = config.get("dns").get("blacklists_config")
# BLACKLIST_PATH = ROOT_PATH / BLACKLISTS_CONFIG.get("path")
CACHE_SIZE = int(BLACKLISTS_CONFIG.get("cache_size", 100))
LOAD_INTERVAL = int(BLACKLISTS_CONFIG.get("loading_interval", 30))

TIMEOUTS = config.get("dns").get("timeouts")
WRKR_JOIN_TIMEOUT = float(TIMEOUTS.get("worker_join", 1))


class BlacklistService:
    """
    Loads and refreshes blacklist rules from a JSON file in a background thread.
    """

    _lock = RLock()
    _stop_event = Event()
    _worker: Thread | None = None
    _interval: int | None = None
    _blacklists = {"blacklist": set(), "blacklist_rules": set()}

    @classmethod
    def init(cls, logger, interval: int = LOAD_INTERVAL):
        """
        Set refresh interval in seconds.
        """
        with cls._lock:
            cls.logger = logger
            cls._interval = interval

    @classmethod
    def start(cls):
        """
        Start background thread to reload blacklists periodically.
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
        Stop, wait and reset for worker.
        """
        with cls._lock:
            cls._stop_event.set()
            if cls._worker:
                cls._worker.join(timeout=WRKR_JOIN_TIMEOUT)
                cls._worker = None
            cls.logger.info("%s stopped.", cls.__name__)

    @classmethod
    def restart(cls):
        """
        Stop and start worker.
        """
        cls.stop()
        cls.start()
        cls.logger.info("%s restarted.", cls.__name__)

    @classmethod
    def _load_blacklists_from_mem(cls):
        """
        Load blacklist data from JSON file.
        """
        _blacklist = dns_blacklists.get_config()
        return {
            "blacklist": set(url.strip().lower() for url in _blacklist.get("urls", [])),
            "blacklist_rules": set(
                rule.strip().lower() for rule in _blacklist.get("rules", [])
            ),
        }

    @classmethod
    def _work(cls):
        """
        Background thread: reload blacklist periodically.
        """
        while not cls._stop_event.is_set():
            try:
                _new_blacklists = cls._load_blacklists_from_mem()
                with cls._lock:
                    if _new_blacklists != cls._blacklists:
                        cls._blacklists = _new_blacklists
                        cls.logger.info(
                            "blacklist:%d, blacklist_rules:%d.",
                            len(_new_blacklists["blacklist"]),
                            len(_new_blacklists["blacklist_rules"]),
                        )
                        cls.is_blacklisted_cache_if_hit.cache_clear()
            except Exception as err:
                cls.logger.error("Failed processing control lists %s.", err)
            cls._stop_event.wait(cls._interval)

    @staticmethod
    @lru_cache(maxsize=CACHE_SIZE)
    def is_blacklisted_cache_if_hit(qname: str) -> bool:
        """
        Check if domain matches blacklist or wildcard rules.
        Uses LRU cache.
        """
        if not qname:
            return False
        if qname in BlacklistService._blacklists["blacklist"]:
            return True
        for _rule in BlacklistService._blacklists["blacklist_rules"]:
            if fnmatch(qname, _rule):
                return True
        return False
