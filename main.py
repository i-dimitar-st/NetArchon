import sys
import signal
from pathlib import Path
from threading import Event

from config.config import config
from services.logger.logger import MainLogger
from services.dhcp.dhcp import DHCPServer
from services.dns.dns import DNSServer
from services.app.app import App
from services.memory.memory import MemoryManager

APP = config.get("app")
HOST = APP.get("host")
PORT = APP.get("port")

PATHS = config.get("paths")
ROOT_PATH = Path(PATHS.get("root"))
CERT_PATH = ROOT_PATH / PATHS.get("certificates")

CERTIFICATES = config.get("certificates")
PEM_PATH = CERT_PATH / CERTIFICATES.get("cert")
KEY_PATH = CERT_PATH / CERTIFICATES.get("key")


_logger = MainLogger.get_logger(service_name="MAIN")
shutdown_event = Event()


def shutdown_handler(signum, frame):
    _logger.info(f"Received {signum}.")
    shutdown_event.set()


def _register_shutdown_signals():
    signal.signal(signal.SIGINT, shutdown_handler)
    signal.signal(signal.SIGTERM, shutdown_handler)
    signal.signal(signal.SIGQUIT, shutdown_handler)
    signal.signal(signal.SIGABRT, shutdown_handler)


if __name__ == "__main__":

    _logger.info("Starting services")
    _register_shutdown_signals()

    App.init(port=PORT, host=HOST, ssl_context=(PEM_PATH, KEY_PATH))
    MemoryManager.init()

    DHCPServer.start()
    DNSServer.start()
    MemoryManager.start()
    App.start()

    shutdown_event.wait()
    _logger.info("Stopping services")

    DHCPServer.stop()
    DNSServer.stop()
    MemoryManager.stop()
    App.stop()

    _logger.info("Shutdown complete")
    sys.exit(0)
