from logging import Logger
from signal import SIGABRT, SIGINT, SIGQUIT, SIGTERM, signal
from threading import Event

from app.services.dhcp.server import DHCPServer
from app.services.dns.dns import DNSServer
from app.services.gui.gui import App
from app.services.logger.logger import MainLogger
from app.services.memory.memory import MemoryManager

logger: Logger = MainLogger.get_logger(service_name="MAIN")
shutdown_event = Event()


def shutdown_handler(signum, frame):
    """Handles app shutdown calls"""
    logger.info("Received %s.", signum)
    shutdown_event.set()


def register_shutdowns():
    """Registers shutdown handler for common interrupt signals"""
    signal(SIGINT, shutdown_handler)
    signal(SIGTERM, shutdown_handler)
    signal(SIGQUIT, shutdown_handler)
    signal(SIGABRT, shutdown_handler)


if __name__ == "__main__":

    logger.info("Starting services")
    register_shutdowns()

    App.init()
    MemoryManager.init()
    DNSServer.init()
    DHCPServer.init()

    DHCPServer.start()
    DNSServer.start()
    MemoryManager.start()
    App.start()

    shutdown_event.wait()
    logger.info("Stopping services")

    DHCPServer.stop()
    DNSServer.stop()
    MemoryManager.stop()
    App.stop()

    logger.info("Shutdown complete")
