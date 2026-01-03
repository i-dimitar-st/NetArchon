import signal
from logging import Logger
from threading import Event

from src.services.dhcp.dhcp import DHCPServer
from src.services.dns.dns import DNSServer
from src.services.gui.app import App
from src.services.http_proxy.http_proxy import HttpProxy
from src.services.logger.logger import MainLogger
from src.services.memory.memory import MemoryManager
from src.services.neural_net.neural_net import NNDomainClassifierService

logger: Logger = MainLogger.get_logger(service_name="MAIN")
shutdown_event = Event()


def shutdown_handler(signum: int, frame):
    """Handles app shutdown calls.

    Args:
        signum (int): The signal number received.
        frame (frame object): Current stack frame.

    """
    logger.debug(f"Received {signum}.")
    shutdown_event.set()


def register_shutdowns():
    """Registers shutdown handler for common interrupt signals"""
    signal.signal(signal.SIGINT, shutdown_handler)
    signal.signal(signal.SIGTERM, shutdown_handler)
    signal.signal(signal.SIGQUIT, shutdown_handler)
    signal.signal(signal.SIGABRT, shutdown_handler)


if __name__ == "__main__":
    logger.info("Starting services")
    register_shutdowns()

    MemoryManager.init()
    DNSServer.init()
    DHCPServer.init()
    HttpProxy.init()
    NNDomainClassifierService.init()
    App.init()

    DHCPServer.start()
    DNSServer.start()
    MemoryManager.start()
    HttpProxy.start()
    NNDomainClassifierService.start()
    App.start()

    logger.info("Services Started")
    shutdown_event.wait()
    logger.info("Stopping services.")

    DHCPServer.stop()
    DNSServer.stop()
    MemoryManager.stop()
    HttpProxy.stop()
    NNDomainClassifierService.stop()
    App.stop()

    logger.info("Shutdown complete.")
