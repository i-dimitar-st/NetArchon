from logging import Logger
from sys import exit
from signal import signal, SIGINT, SIGTERM, SIGQUIT, SIGABRT
from threading import Event

from config.config import config
from services.logger.logger import MainLogger
from services.dhcp.server import DHCPServer
from services.dns.dns import DNSServer
from services.app.app import App
from services.memory.memory import MemoryManager


_logger: Logger = MainLogger.get_logger(service_name="MAIN")
_shutdown_event = Event()


def _shutdown_handler(signum, frame):
    _logger.info("Received %s.", signum)
    _shutdown_event.set()


def _register_shutdown_signals():
    signal(SIGINT, _shutdown_handler)
    signal(SIGTERM, _shutdown_handler)
    signal(SIGQUIT, _shutdown_handler)
    signal(SIGABRT, _shutdown_handler)


if __name__ == "__main__":

    _logger.info("Starting services")
    _register_shutdown_signals()

    App.init()
    MemoryManager.init()
    DNSServer.init()
    DHCPServer.init()

    DHCPServer.start()
    DNSServer.start()
    MemoryManager.start()
    App.start()

    _shutdown_event.wait()
    _logger.info("Stopping services")

    DHCPServer.stop()
    DNSServer.stop()
    MemoryManager.stop()
    App.stop()

    _logger.info("Shutdown complete")
    exit(0)
