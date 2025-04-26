import os
import logging


class MainLogger:
    LOG_DIR = "logs"
    LOG_FILE = os.path.join(LOG_DIR, "main.log")
    LOG_PATH = os.path.join(LOG_DIR, LOG_FILE)
    LOG_FORMAT = '%(asctime)s.%(msecs)03d | %(levelname)s | %(name)s | %(message)s'

    @classmethod
    def get_logger(cls, service_name="MAIN", log_level=logging.DEBUG):
        """Returns a logger for the given service, using the main log file."""
        os.makedirs(cls.LOG_DIR, exist_ok=True)
        logger = logging.getLogger(service_name)
        logger.setLevel(log_level)

        if not logger.hasHandlers():
            file_handler = logging.FileHandler(cls.LOG_FILE, mode='a')
            file_handler.setLevel(log_level)
            formatter = logging.Formatter(cls.LOG_FORMAT, datefmt='%Y-%m-%d %H:%M:%S')
            file_handler.setFormatter(formatter)
            logger.addHandler(file_handler)

        console_handler = next((_console_handler for _console_handler in logger.handlers if isinstance(
            _console_handler, logging.StreamHandler)), None)
        if console_handler is None:
            console_handler = None

        return logger
