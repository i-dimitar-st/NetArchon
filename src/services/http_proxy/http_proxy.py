"""HTTP Proxy Service.
This module sets up and manages an HTTP proxy server using the proxy.py library.
"""

import logging
import threading
from ipaddress import ip_address
from multiprocessing import Manager, Process
from os import cpu_count
from pathlib import Path
from queue import Empty, Full
from typing import Optional

from proxy import main
from proxy.http.parser import HttpParser
from proxy.http.proxy import HttpProxyBasePlugin

from src.config.config import config
from src.services.dns.blacklist_service import BlacklistService
from src.services.dns.db import DnsQueryHistoryDb, DnsStatsDb
from src.services.http_proxy.metrics import http_proxy_metrics
from src.services.http_proxy.models import (
    HttpRequestRejectedBadRequest,
    HttpRequestRejectedForbidden,
    ProxyStatsType,
)
from src.services.http_proxy.utils import extract_hostname, is_in_subnet, is_ip_address
from src.services.logger.logger import MainLogger

PATHS = config.get("paths")
ROOT_PATH = Path(PATHS.get("root"))
CERTIFICATES = config.get("certificates")
CERT_PATH = ROOT_PATH / PATHS.get("certificates")
PEM_PATH = CERT_PATH / CERTIFICATES.get("cert")
KEY_PATH = CERT_PATH / CERTIFICATES.get("key")

PROXY_CONF = config.get("proxy").get("config",{})
PROXY_HOST = str(PROXY_CONF.get("host"))
PROXY_HOST_EXTERNAL = str(PROXY_CONF.get("host_external"))
PROXY_PORT = int(PROXY_CONF.get("port"))
PROXY_BACKLOG = PROXY_CONF.get("backlog")
PROXY_LOG_LEVEL = str(PROXY_CONF.get("log_level"))
PROXY_THREADLESS = bool(PROXY_CONF.get("threadless"))
PROXY_ENABLE_WEB_SERVER =  bool(PROXY_CONF.get("web_server"))
PROXY_ENABLE_STATIC_SERVER = bool(PROXY_CONF.get("static_server"))
PROXY_ENABLE_METRICS = bool(PROXY_CONF.get("internal_metrics"))

# PROXY_CONF_WORKERS = config.get("proxy").get("worker_config",{})
PROXY_NUM_WORKERS = cpu_count() or 4
PROXY_NUM_ACCEPTORS = cpu_count() or 4


PROXY_CONF_TIMEOUTS = config.get("proxy").get("timeouts",{})
PROXY_TIMEOUT = float(PROXY_CONF_TIMEOUTS.get("client_read"))
PXY_WRKR_JOIN_TIMEOUT = float(PROXY_CONF_TIMEOUTS.get("worker_join"))
PXY_WRKR_GET_TIMEOUT = float(PROXY_CONF_TIMEOUTS.get("queue_worker_get"))

PROXY_DAP_SERVER_CONF = config.get("proxy").get("dap_server_config",{})

DAP_SERVER_HOST = str(PROXY_DAP_SERVER_CONF.get("host"))
DAP_SERVER_HOST_EXTERNAL = str(PROXY_DAP_SERVER_CONF.get("host_external"))
DAP_SERVER_PORT = int(PROXY_DAP_SERVER_CONF.get("port"))
DAP_SERVER_DAP_PATH = str(PROXY_DAP_SERVER_CONF.get("dap_wpad_path"))

PROXY_RESOURCES_LIMITS_CONF = config.get("proxy").get("resource_limits",{})
QUEUE_MAX_SIZE = int(PROXY_RESOURCES_LIMITS_CONF.get("rcvd_queue_size"))
MAX_CACHE_SIZE = int(PROXY_RESOURCES_LIMITS_CONF.get("max_cache_size"))


logging.getLogger("proxy.http.handler").setLevel(logging.ERROR)
logging.getLogger("proxy.common.plugins").setLevel(logging.ERROR)
logging.getLogger("proxy.core.base.tcp").setLevel(logging.ERROR)
logging.getLogger("proxy.http.handler").setLevel(logging.ERROR)

logger = MainLogger.get_logger(service_name="HTTP_PROXY")


class LoggingPlugin(HttpProxyBasePlugin):
    """Proxy addon logging plugin."""

    def on_access_log(self, context: dict) -> None:
        """Override proxy.py access log.

        Args:
            context (dict): Access log context, has the following:
            - client_ip
            - server_host
            - request_method
            - request_path
            - response_code
            - response_bytes
            - connection_time_ms

        """
        HttpProxy.add_duration(float(context.get("connection_time_ms",0.0))/1000.0)
        return None


class BlockSitesPlugin(HttpProxyBasePlugin):
    """Proxy addon blocked plugin."""

    def handle_client_request(self, request: HttpParser) -> Optional[HttpParser]:
        """Handle client requests."""
        HttpProxy.add_hit(ProxyStatsType.PROXY_RECEIVED)
        _host:str = extract_hostname(request.host)

        if not _host:
            HttpProxy.add_hit(ProxyStatsType.PROXY_BAD_REQUEST)
            raise HttpRequestRejectedBadRequest()

        if is_in_subnet(_host,PROXY_HOST_EXTERNAL):
            return request

        if BlacklistService.is_blacklisted(_host):
            HttpProxy.add_hit(ProxyStatsType.PROXY_BLOCKED_HIT)
            raise HttpRequestRejectedForbidden()

        if not is_ip_address(_host):
            HttpProxy.add_history(_host)
        HttpProxy.add_hit(ProxyStatsType.PROXY_HIT)
        return request


class HttpProxy:
    """Run proxy.py in a separate process with start/stop control."""

    _proxy_worker: Optional[Process] = None
    _metrics_worker: Optional[threading.Thread] = None
    _stop_event: threading.Event = threading.Event()

    _manager = Manager()
    _data_queue = _manager.Queue(maxsize=QUEUE_MAX_SIZE)

    @classmethod
    def init(cls) -> None:
        """Initialize the HTTP proxy service & WPADDatServer."""
        if (cls._proxy_worker is not None and cls._proxy_worker.is_alive()):
            return
        if (cls._metrics_worker is not None and cls._metrics_worker.is_alive()):
            return
        cls._proxy_worker = None
        cls._metrics_worker = None
        cls._stop_event.clear()
        logger.info(f"{cls.__name__} initialized.")

    @classmethod
    def _run_proxy(
        cls,
        hostname: str = PROXY_HOST,
        port: int = PROXY_PORT,
        num_workers: int = PROXY_NUM_WORKERS,
        num_acceptors: int = PROXY_NUM_ACCEPTORS,
        threadless: bool = PROXY_THREADLESS,
        backlog: int = PROXY_BACKLOG,
        timeout: float = PROXY_TIMEOUT,
        certfile: Path = CERT_PATH,
        keyfile: Path = KEY_PATH,
        log_level: str = PROXY_LOG_LEVEL,
        enable_web_server: bool = PROXY_ENABLE_WEB_SERVER,
        enable_static_server: bool = PROXY_ENABLE_STATIC_SERVER,
        enable_metrics: bool = PROXY_ENABLE_METRICS,
        plugins = [LoggingPlugin, BlockSitesPlugin], # noqa: B006
    ) -> None:
        """Target function for the thread."""
        logger.debug("Proxy started.")
        main(
            hostname=ip_address(hostname),
            port=port,
            num_workers=num_workers,
            num_acceptors=num_acceptors,
            threadless=threadless,
            backlog=backlog,
            timeout=timeout,
            certfile=certfile,
            keyfile=keyfile,
            log_level=log_level,
            enable_web_server=enable_web_server,
            enable_static_server=enable_static_server,
            enable_metrics=enable_metrics,
            plugins=plugins,
        )


    @classmethod
    def _enqueue(cls, item: dict) -> None:
        """Enqueue data to be processed by the metrics worker.

        Args:
            item (dict): Data item to enqueue.

        """
        if cls._stop_event.is_set():
            return
        try:
            cls._data_queue.put_nowait(item)
        except Full:
            logger.warning("Data queue is full")
        except Exception:
            logger.error("Failed to enqueue data item")

    @classmethod
    def _consume_data(cls) -> None:
        """Consume data from the queue and update thread-safe metrics dict."""
        while not cls._stop_event.is_set():
            try:
                _item: dict | None = cls._data_queue.get(timeout=PXY_WRKR_GET_TIMEOUT)
            except Empty:
                continue
            if not _item:
                continue

            if "type" in _item:
                DnsStatsDb.increment(key=_item["type"])

            if "duration" in _item:
                http_proxy_metrics.add_sample(_item["duration"])

            if "domain" in _item:
                DnsQueryHistoryDb.add_query(_item["domain"])

            cls._data_queue.task_done()

    @classmethod
    def add_duration(cls,duration:float) -> None:
        """Add connection duration to metrics.

        Args:
            duration (float): Connection duration in milliseconds.

        """
        cls._enqueue({"duration": duration})

    @classmethod
    def add_hit(cls,type:str)->None:
        """Add hit or blocked hit to metrics.

        Args:
            type (str): Type of hit, either "proxy_hit" or "proxy_blocked_hit".

        """
        cls._enqueue({"type": type})

    @classmethod
    def add_history(cls,domain:str)->None:
        """Add domain to history database.

        Args:
            domain (str): Domain name to add.

        """
        if domain:
            cls._enqueue({"domain": domain})

    @classmethod
    def start(cls) -> None:
        """Start the HTTP proxy service & WPADDatServer."""
        if cls._proxy_worker and cls._proxy_worker.is_alive():
            raise RuntimeError("Proxy already running.")

        cls._stop_event.clear()

        cls._proxy_worker = Process(target=cls._run_proxy, daemon=True)
        cls._proxy_worker.start()

        cls._metrics_worker = threading.Thread(target=cls._consume_data, daemon=True)
        cls._metrics_worker.start()

        logger.info(f"HTTP PROXY running on http://{PROXY_HOST}:{PROXY_PORT}")

    @classmethod
    def stop(cls) -> None:
        """Stop the HTTP proxy service & WPADDatServer."""
        logger.info("Stopped HTTP PROXY.")
        cls._stop_event.set()
        cls._data_queue.join()


        if cls._proxy_worker and cls._proxy_worker.is_alive():
            cls._proxy_worker.terminate()
            cls._proxy_worker.join(timeout=PXY_WRKR_JOIN_TIMEOUT)
            if cls._proxy_worker.is_alive():
                cls._proxy_worker.kill()
                cls._proxy_worker.join()


        if cls._metrics_worker and cls._metrics_worker.is_alive():
            cls._metrics_worker.join(timeout=PXY_WRKR_JOIN_TIMEOUT)

        cls._proxy_worker = None
        cls._metrics_worker = None

        logger.info("HTTP PROXY stopped.")

    @classmethod
    def restart(cls) -> None:
        """Restart the HTTP proxy service & WPADDatServer."""
        cls.stop()
        cls.start()
        logger.info("HTTP PROXY restarting.")
