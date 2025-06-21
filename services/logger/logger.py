import os
import logging
from models.models import LogLevel
from logging.handlers import RotatingFileHandler


LOG_DIR = "logs"
LOG_FILE = "main.log"
LOG_FILE_SIZE = 50 * 1024 * 1024
LOG_FILE_BACKUP_COUNT = 0
LOG_MODE = "a"
LOG_PATH = os.path.join(LOG_DIR, LOG_FILE)
LOG_FORMAT = '%(asctime)s.%(msecs)03d | %(levelname)s | %(name)s | %(message)s'
LOG_DATE_FORMAT = '%Y-%m-%d %H:%M:%S'
LOG_ENCODING = "utf-8"


# Typically we dont want this ok for now
os.makedirs(LOG_DIR, exist_ok=True)

# # Delete main.log on startup during dev only
# if os.path.exists(LOG_PATH):
#     os.remove(LOG_PATH)


class MainLogger:

    @classmethod
    def _get_logger_formatter(cls):
        return logging.Formatter(LOG_FORMAT, datefmt=LOG_DATE_FORMAT)

    @classmethod
    def _get_logger_level(cls, level: str = "") -> int:
        return LogLevel.from_string(level)

    @classmethod
    def get_logger(cls, service_name="MAIN", log_level="debug"):
        """Returns a logger for the given service, using the main log file."""

        logger = logging.getLogger(service_name)
        logger.setLevel(cls._get_logger_level(log_level))

        if not logger.hasHandlers():
            file_handler = RotatingFileHandler(LOG_PATH,
                                               maxBytes=LOG_FILE_SIZE,
                                               backupCount=LOG_FILE_BACKUP_COUNT,
                                               encoding=LOG_ENCODING,
                                               mode=LOG_MODE)
            file_handler.setLevel(cls._get_logger_level(log_level))
            formatter = cls._get_logger_formatter()
            file_handler.setFormatter(formatter)
            logger.addHandler(file_handler)

        return logger
