#!/usr/bin/env python3.12
import threading
import logging
import os
import time
import sys
from services import MainLogger
from services import DHCPServer
from services import DNSServer
from services import RabbitMqConsumer
from services import app


CERT_PEM_PATH = './services/app/certificates/cert.pem'
CERT_KEY_PATH = './services/app/certificates/key.pem'

main_logger = MainLogger.get_logger(service_name="MAIN", log_level=logging.INFO)


def run_gui():
    """Starts the Flask GUI."""
    main_logger.info("Starting GUI")
    app.run(
        host="0.0.0.0",
        port=5000,
        debug=True,
        use_reloader=False,
        ssl_context=(CERT_PEM_PATH, CERT_KEY_PATH),
        threaded=False,
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
