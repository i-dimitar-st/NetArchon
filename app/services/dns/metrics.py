"""
Singleton-like instance of Metrics for DNS service.

This is a module-level object intended to be shared across the app.
"""

from ipaddress import IPv4Address

from app.config.config import config
from app.libs.libs import Metrics

PATHS = config.get("paths")

DNS_CONFIG = config.get("dns").get("config")
EXTERNAL_DNS_SERVERS = list(DNS_CONFIG.get("external_dns_servers"))

dns_metrics = Metrics()
dns_metrics_external = Metrics()
dns_per_server_metrics = {IPv4Address(ip): Metrics() for ip in EXTERNAL_DNS_SERVERS}
