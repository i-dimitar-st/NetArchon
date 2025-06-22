import logging.config
from config.config import config
from models.models import LogLevel

LOGGER_CONFIG = config.get("logging")
logging.config.dictConfig(LOGGER_CONFIG)


class MainLogger:
    @classmethod
    def get_logger(cls, service_name: str = "MAIN", log_level: str = "DEBUG") -> logging.Logger:
        logger = logging.getLogger(service_name)
        if log_level:
            logger.setLevel(LogLevel(log_level).value)
        return logger
