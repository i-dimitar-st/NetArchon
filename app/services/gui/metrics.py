"""
Singleton-like instance of Metrics for DHCP service.

This is a module-level object intended to be shared across the app.
"""

from app.libs.libs import Metrics

http_response_metrics = Metrics()
api_metrics = Metrics()
