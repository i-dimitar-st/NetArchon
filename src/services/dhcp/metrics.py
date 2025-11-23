"""Singleton-like instance of Metrics for DHCP service.

This is a module-level object intended to be shared across the app.
"""

from src.libs.libs import Metrics

dhcp_metrics = Metrics()
