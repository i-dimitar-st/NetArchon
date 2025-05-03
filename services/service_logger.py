import os
import logging

LOG_DIR = "logs"
LOG_FILE = "main.log"
LOG_PATH = os.path.join(LOG_DIR, LOG_FILE)
LOG_FORMAT = '%(asctime)s.%(msecs)03d | %(levelname)s | %(name)s | %(message)s'


# Typically we dont want this ok for now
os.makedirs(LOG_DIR, exist_ok=True)

# Delete main.log on startup during dev only
if os.path.exists(LOG_PATH):
    os.remove(LOG_PATH)


class MainLogger:

    @classmethod
    def get_logger(cls, service_name="MAIN", log_level=logging.DEBUG):
        """Returns a logger for the given service, using the main log file."""

        logger = logging.getLogger(service_name)
        logger.setLevel(log_level)

        if not logger.hasHandlers():
            file_handler = logging.FileHandler(LOG_PATH, mode='a', encoding='utf-8')
            file_handler.setLevel(log_level)
            formatter = logging.Formatter(LOG_FORMAT, datefmt='%Y-%m-%d %H:%M:%S')
            file_handler.setFormatter(formatter)
            logger.addHandler(file_handler)

        return logger
