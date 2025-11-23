import logging.config

from src.config.config import config
from src.models.models import LogLevel

LOGGER_CONFIG = config.get("logging")
logging.config.dictConfig(LOGGER_CONFIG)


class MainLogger:
    """Aplication wide logging."""

    @classmethod
    def get_logger(
        cls, service_name: str = "MAIN", log_level: str = "DEBUG"
    ) -> logging.Logger:
        """Logging instance getter, configurable by service name and level
        Args:
            service_name(str): Logger instance
            log_level(str): Log level desired for your instance
        Returns:
            logging.Logger: Configured logger instance.
        """
        logger = logging.getLogger(service_name)
        logger.setLevel(LogLevel(log_level).value)
        return logger
