import logging.config

from app.config.config import config
from app.models.models import LogLevel

LOGGER_CONFIG = config.get("logging")
logging.config.dictConfig(LOGGER_CONFIG)


class MainLogger:
    """Aplication wide logging def"""

    @classmethod
    def get_logger(
        cls, service_name: str = "MAIN", log_level: str = "DEBUG"
    ) -> logging.Logger:
        """Logging instance getter, configurable by service name and level"""
        logger = logging.getLogger(service_name)
        if log_level:
            logger.setLevel(LogLevel(log_level).value)
        return logger
