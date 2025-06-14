import time
import signal
import sys
from pathlib import Path

from services.config.config import config
from services.logger.logger import MainLogger
from services.dhcp.dhcp_server import DHCPServer
from services.dns.server import DNSServer
from services.app.app import App
from services.garbage_collection.service import GCMonitorService

logger = MainLogger.get_logger(service_name="MAIN")

HOST = config.get("app", "host")
PORT = config.get("app", "port")

ROOT = Path(config.get("paths", "root"))
PEM = ROOT / config.get("certificates", "cert")
KEY = ROOT / config.get("certificates", "key")
SHUTDOWN_FLAG = False


def shutdown_handler(signum, frame):
    logger.info(f"Received signal {signum}, shutting down.")
    global SHUTDOWN_FLAG
    SHUTDOWN_FLAG = True


if __name__ == "__main__":
    logger.info("Starting Main")

    dhcp = DHCPServer()
    dhcp.start()

    dns = DNSServer()
    dns.start()

    gc_metrics = GCMonitorService(interval=600)
    gc_metrics.start()

    app_gui = App(port=PORT,
                  host=HOST,
                  ssl_context=(PEM, KEY))
    app_gui.start()

    signal.signal(signal.SIGINT, shutdown_handler)
    signal.signal(signal.SIGTERM, shutdown_handler)

    while not SHUTDOWN_FLAG:
        time.sleep(1)

    dns.stop()
    dhcp.stop()
    gc_metrics.stop()
    app_gui.stop()
    logger.info("Shutdown complete.")
    sys.exit(0)
