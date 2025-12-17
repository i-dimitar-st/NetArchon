# Native
from threading import RLock
from time import time

from src.services.dns.blacklist_service import BlacklistService
from src.services.dns.db import DnsQueryHistoryDb, DnsStatsDb
from src.services.dns.db_persistance import DbPersistanceService
from src.services.dns.external_resolver import ExternalResolverService

# from src.services.dns.external_resolver_async import AsyncExternalResolverService
from src.services.dns.resolver_service import ResolverService

# Local
from src.services.logger.logger import MainLogger

dns_logger = MainLogger.get_logger(service_name="DNS", log_level="debug")


class DNSServer:
    _lock = RLock()
    _initialised = False
    running = False
    timestamp: float

    @classmethod
    def init(cls):
        with cls._lock:
            if cls._initialised:
                raise RuntimeError("Already Init")
            DnsStatsDb.init()
            DnsQueryHistoryDb.init(logger=dns_logger)
            DbPersistanceService.init(logger=dns_logger)
            ExternalResolverService.init(logger=dns_logger)
            # AsyncExternalResolverService.init(logger=dns_logger)
            BlacklistService.init(logger=dns_logger)
            ResolverService.init(logger=dns_logger)
            cls._initialised = True

    @classmethod
    def start(cls):
        if cls.running:
            raise RuntimeError("Server already running.")
        with cls._lock:
            BlacklistService.start()
            DbPersistanceService.start()
            ResolverService.start()
            ExternalResolverService.start()
            cls.running = True
            cls.timestamp = time()
            dns_logger.info("DNS server started.")

    @classmethod
    def stop(cls):
        if not cls.running:
            raise RuntimeError("Server not running.")
        with cls._lock:
            DbPersistanceService.stop()
            ExternalResolverService.stop()
            BlacklistService.stop()
            ResolverService.stop()
            dns_logger.info("Server stopped.")
            cls.running = False
