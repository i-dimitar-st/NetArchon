"""Singleton-like instance of Metrics for DNS service.

This is a module-level object intended to be shared across the app.
"""

from src.libs.libs import Metrics

http_proxy_metrics = Metrics()
