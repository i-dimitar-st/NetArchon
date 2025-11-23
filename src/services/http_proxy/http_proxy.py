import logging
import threading
from ipaddress import ip_address
from multiprocessing import Manager
from pathlib import Path
from queue import Empty, Full
from typing import Optional

from proxy import main
from proxy.http.exception import HttpRequestRejected
from proxy.http.parser import HttpParser
from proxy.http.proxy import HttpProxyBasePlugin

from src.config.config import config
from src.services.dns.blacklist_service import BlacklistService
from src.services.dns.db import DnsQueryHistoryDb, DnsStatsDb
from src.services.http_proxy.dap_server import WPADDatServer
from src.services.http_proxy.metrics import http_proxy_metrics
from src.services.http_proxy.utils import extract_hostname_from_proxy_request
from src.services.logger.logger import MainLogger

PATHS = config.get("paths")
ROOT_PATH = Path(PATHS.get("root"))
CERTIFICATES = config.get("certificates")
CERT_PATH = ROOT_PATH / PATHS.get("certificates")
PEM_PATH = CERT_PATH / CERTIFICATES.get("cert")
KEY_PATH = CERT_PATH / CERTIFICATES.get("key")

PROXY_HOST = ip_address("0.0.0.0")
PROXY_PORT = 8899
PROXY_NUM_WORKERS = 50
PROXY_THREADLESS = False
PROXY_TIMEOUT = 10
PROXY_BACKLOG = 1024
PROXY_LOG_LEVEL = 'WARNING'
PROXY_ENABLE_WEB_SERVER = False
PROXY_ENABLE_STATIC_SERVER = False
PROXY_ENABLE_METRICS = False

DAP_SERVER_HOST = "0.0.0.0"
DAP_SERVER_PORT = 8080

WORKER_JOIN_TIMEOUT = 1
MAX_LRU_BLACKLISTED_CACHE_SIZE = 1024
QUEUE_WORKER_GET_TIMEOUT = 0.1
QUEUE_MAX_SIZE = 100


logger = MainLogger.get_logger(service_name="HTTP_PROXY")

logging.getLogger("proxy.http.handler").setLevel(logging.CRITICAL)
logging.getLogger("proxy.common.plugins").setLevel(logging.CRITICAL)


class LoggingPlugin(HttpProxyBasePlugin):
    def on_access_log(self, context: dict) -> None:
        """Override proxy.py access log."""
        HttpProxy.add_duration(float(context.get("connection_time_ms",0.0)))
        # print(f"Proxy request: ip:{context.get("client_ip")} host:{context.get("server_host")} time:{context.get("connection_time_ms")} res_bytes:{context.get("response_bytes")} | {context.get("request_method")} {context.get("request_path")}")
        return None


class BlockSitesPlugin(HttpProxyBasePlugin):
    """Proxy addon blocked plugin."""

    def handle_client_request(self, request: HttpParser) -> Optional[HttpParser]:
        """Handles client requests."""
        _host = extract_hostname_from_proxy_request(request.host)
        if _host:
            HttpProxy.add_history(_host)
            if BlacklistService.is_blacklisted(_host):
                HttpProxy.add_hit("proxy_blocked_hit")
                # return None
                raise HttpRequestRejected(
                        status_code=403,
                        reason=b"Forbidden",
                        headers={b"Content-Type": b"text/plain"},
                        body=b"This site is blocked by the proxy."
                    )

        HttpProxy.add_hit("proxy_hit")
        return request


class HttpProxy:
    """Run proxy.py in a separate process with start/stop control."""

    _proxy_worker: Optional[threading.Thread] = None
    _metrics_worker: Optional[threading.Thread] = None
    _stop_event: threading.Event = threading.Event()

    _manager = Manager()
    _metrics = _manager.dict()
    _data_queue = _manager.Queue(maxsize=QUEUE_MAX_SIZE)

    @classmethod
    def init(cls) -> None:
        if (cls._proxy_worker is not None and cls._proxy_worker.is_alive()):
            return
        if (cls._metrics_worker is not None and cls._metrics_worker.is_alive()):
            return
        cls._proxy_worker = None
        cls._metrics_worker = None
        cls._stop_event.clear()
        WPADDatServer.init(
            logger=logger,
            host=DAP_SERVER_HOST,
            port=DAP_SERVER_PORT,
            proxy_host=str(PROXY_HOST),
            proxy_port=PROXY_PORT
        )
        logger.info("cls.__name__ initialized.")

    @classmethod
    def _run_proxy(cls) -> None:
        """Target function for the thread."""
        main(
            hostname=PROXY_HOST,
            port=PROXY_PORT,
            num_workers=PROXY_NUM_WORKERS,
            num_acceptors=PROXY_NUM_WORKERS,
            threadless=PROXY_THREADLESS,
            backlog=PROXY_BACKLOG,
            timeout=PROXY_TIMEOUT,
            certfile=CERT_PATH,
            keyfile=KEY_PATH,
            log_level=PROXY_LOG_LEVEL,
            enable_web_server=PROXY_ENABLE_WEB_SERVER,
            enable_static_server=PROXY_ENABLE_STATIC_SERVER,
            enable_metrics=PROXY_ENABLE_METRICS,
            plugins=[BlockSitesPlugin, LoggingPlugin]
        )

    @classmethod
    def _consume_metrics(cls) -> None:
        """Consume metrics from the queue and update thread-safe metrics dict."""
        while not cls._stop_event.is_set():
            try:
                _item = cls._data_queue.get(timeout=QUEUE_WORKER_GET_TIMEOUT)
                if _item:
                    _type = _item.get("type")
                    _duration = _item.get("duration")
                    _domain = _item.get("domain")
                    if _type:
                        cls._metrics[_type] = cls._metrics.get(_type, 0) + 1
                        if _type == "proxy_blocked_hit":
                            DnsStatsDb.increment(key=_type)
                        if _type == "proxy_hit":
                            DnsStatsDb.increment(key=_type)
                    if _duration:
                        http_proxy_metrics.add_sample(_duration)
                    if _domain:
                        try:
                            ip_address(_domain)
                        except ValueError:
                            DnsQueryHistoryDb.add_query(_domain)

                cls._data_queue.task_done()
            except Empty:
                continue
            except Full:
                logger.warning("Metrics queue is full")

    @classmethod
    def add_duration(cls,duration:float)->None:
        try:
            cls._data_queue.put_nowait({"duration":duration})
        except:
            pass

    @classmethod
    def add_hit(cls,type:str)->None:
        try:
            if "proxy_blocked_hit" == type:
                cls._data_queue.put_nowait({"type":"proxy_blocked_hit"})
            if "proxy_hit" == type:
                cls._data_queue.put_nowait({"type":"proxy_hit"})
        except:
            pass

    @classmethod
    def add_history(cls,domain:str)->None:
        if domain:
            cls._data_queue.put_nowait({"domain":domain})

    @classmethod
    def start(cls) -> None:
        if cls._proxy_worker and cls._proxy_worker.is_alive():
            raise RuntimeError("Proxy already running.")

        cls._stop_event.clear()

        cls._proxy_worker = threading.Thread(target=cls._run_proxy, daemon=True)
        cls._proxy_worker.start()

        cls._metrics_worker = threading.Thread(target=cls._consume_metrics, daemon=True)
        cls._metrics_worker.start()
        WPADDatServer.start()

        logger.info(f"HTTP PROXY running on http://{PROXY_HOST}:{PROXY_PORT}")

    @classmethod
    def stop(cls) -> None:
        logger.info("Stopped HTTP PROXY.")
        cls._stop_event.set()

        if cls._proxy_worker and cls._proxy_worker.is_alive():
            cls._proxy_worker.join(timeout=WORKER_JOIN_TIMEOUT)

        if cls._metrics_worker and cls._metrics_worker.is_alive():
            cls._metrics_worker.join(timeout=WORKER_JOIN_TIMEOUT)

        cls._proxy_worker = None
        cls._metrics_worker = None

        WPADDatServer.stop()
        logger.info("HTTP PROXY stopped.")

    @classmethod
    def restart(cls) -> None:
        WPADDatServer.restart()
        cls.stop()
        cls.start()
        logger.info("HTTP PROXY restarting.")
