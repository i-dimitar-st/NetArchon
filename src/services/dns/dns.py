from threading import RLock
from time import time

from src.services.dns.blacklist_service import BlacklistService
from src.services.dns.db import DnsQueryHistoryDb, DnsStatsDb
from src.services.dns.db_persistance import DbPersistanceService
from src.services.dns.external_resolver import ExternalResolverService
from src.services.dns.resolver_service import ResolverService
from src.services.logger.logger import MainLogger

dns_logger = MainLogger.get_logger(service_name="DNS", log_level="debug")


class DNSServer:
    _lock = RLock()
    initialised = False
    running = False
    timestamp: float

    @classmethod
    def init(cls) -> None:
        with cls._lock:
            if cls.initialised:
                raise RuntimeError("Already Init")
            DnsStatsDb.init()
            DnsQueryHistoryDb.init(logger=dns_logger)
            DbPersistanceService.init(logger=dns_logger)
            BlacklistService.init(logger=dns_logger)
            ExternalResolverService.init(logger=dns_logger)
            ResolverService.init(logger=dns_logger)
            cls.initialised = True

    @classmethod
    def start(cls) -> None:
        if cls.running:
            raise RuntimeError("DNS server already running.")
        with cls._lock:
            BlacklistService.start()
            DbPersistanceService.start()
            ExternalResolverService.start()
            ResolverService.start()
            cls.running = True
            cls.timestamp = time()
            dns_logger.info("DNS server started.")

    @classmethod
    def stop(cls) -> None:
        if not cls.running:
            raise RuntimeError("Server not running.")
        with cls._lock:
            DbPersistanceService.stop()
            BlacklistService.stop()
            ExternalResolverService.stop()
            ResolverService.stop()
            dns_logger.info("Server stopped.")
            cls.running = False
