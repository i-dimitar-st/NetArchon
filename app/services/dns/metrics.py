"""
Singleton-like instance of Metrics for DNS service.

This is a module-level object intended to be shared across the app.
"""

from app.libs.libs import Metrics

dns_metrics = Metrics()
