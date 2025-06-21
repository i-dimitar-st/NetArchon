import sys
import signal
from pathlib import Path
from threading import Event

from services.config.config import config
from services.logger.logger import MainLogger
from services.dhcp.dhcp import DHCPServer
from services.dns.dns import DNSServer
from services.app.app import App
from services.garbage_collection.service import GCMonitorService

HOST = config.get("app", "host")
PORT = config.get("app", "port")

ROOT = Path(config.get("paths", "root"))
PEM = ROOT / config.get("certificates", "cert")
KEY = ROOT / config.get("certificates", "key")


logger = MainLogger.get_logger(service_name="MAIN")
shutdown_event = Event()


def shutdown_handler(signum, frame):
    logger.info(f"Received {signum}.")
    shutdown_event.set()


def register_shutdown_signals():
    signal.signal(signal.SIGINT, shutdown_handler)
    signal.signal(signal.SIGTERM, shutdown_handler)
    signal.signal(signal.SIGQUIT, shutdown_handler)
    signal.signal(signal.SIGABRT, shutdown_handler)


if __name__ == "__main__":

    logger.info("Starting services")
    register_shutdown_signals()

    DHCPServer.start()
    DNSServer.start()
    GCMonitorService.start(interval=600)
    App.start(port=PORT, host=HOST, ssl_context=(PEM, KEY))

    shutdown_event.wait()
    logger.info("Stopping services")

    DHCPServer.stop()
    DNSServer.stop()
    GCMonitorService.stop()
    App.stop()

    logger.info("Shutdown complete")
    sys.exit(0)
