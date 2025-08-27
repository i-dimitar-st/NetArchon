# Native
from threading import RLock

from app.services.dns.blacklist_service import BlacklistService
from app.services.dns.db import DnsQueryHistoryDb, DnsStatsDb
from app.services.dns.db_persistance import DbPersistanceService
from app.services.dns.external_resolver import ExternalResolverService
from app.services.dns.resolver_service import ResolverService

# Local
from app.services.logger.logger import MainLogger

dns_logger = MainLogger.get_logger(service_name="DNS", log_level="debug")


class DNSServer:
    _lock = RLock()
    _initialised = False
    _running = False

    @classmethod
    def init(cls):
        with cls._lock:
            if cls._initialised:
                raise RuntimeError("Already Init")
            DnsStatsDb.init()
            DnsQueryHistoryDb.init()
            DbPersistanceService.init(logger=dns_logger)
            ExternalResolverService.init(logger=dns_logger)
            BlacklistService.init(logger=dns_logger)
            ResolverService.init(logger=dns_logger)
            cls._initialised = True

    @classmethod
    def start(cls):
        if cls._running:
            raise RuntimeError("Server already running.")
        with cls._lock:
            BlacklistService.start()
            DbPersistanceService.start()
            ExternalResolverService.start()
            ResolverService.start()
            cls._running = True
            dns_logger.info("DNS server started.")

    @classmethod
    def stop(cls):
        if not cls._running:
            raise RuntimeError("Server not running.")
        with cls._lock:
            DbPersistanceService.stop()
            ExternalResolverService.stop()
            BlacklistService.stop()
            ResolverService.stop()
            dns_logger.info("Server stopped.")
            cls._running = False
