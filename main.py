#!/usr/bin/env python3.12
import os
import threading
import time
from services.service_logger import MainLogger
from services.dhcp_server import DHCPServer
from services.dns.dns_server import DNSServer
from services.rabbitmq_service import RabbitMqConsumer
from services.app.app import app

NETARCHON_APP_MODE = os.environ.get("NETARCHON_MODE", "development")
NETARCHON_LOG_LEVEL = os.environ.get("NETARCHON_LOG_LEVEL", "debug")

CERT_PEM_PATH = './services/app/certificates/cert.pem'
CERT_KEY_PATH = './services/app/certificates/key.pem'


main_logger = MainLogger.get_logger(service_name="MAIN", log_level=NETARCHON_LOG_LEVEL)


def run_gui():
    """Starts the Flask GUI."""
    main_logger.info("Starting GUI")
    app.run(
        host="0.0.0.0",
        port=5000,
        debug=True,
        use_reloader=False,
        ssl_context=(CERT_PEM_PATH, CERT_KEY_PATH),
        threaded=True,
        processes=1
    )


def run_dhcp():
    main_logger.info("Starting DCHP Server")
    dhcp = DHCPServer()
    dhcp.start()


def run_dns():
    main_logger.info("Starting DNS Server")
    dns = DNSServer()
    dns.start()


if __name__ == "__main__":
    main_logger.info("starting")

    dhcp_thread = threading.Thread(target=run_dhcp, name="DHCP-Thread", daemon=True)
    dhcp_thread.start()

    dns_thread = threading.Thread(target=run_dns, name="DNS-Thread", daemon=True)
    dns_thread.start()

    gui_thread = threading.Thread(target=run_gui, name="GUI-Thread", daemon=True)
    gui_thread.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        main_logger.info("Stopping services")
