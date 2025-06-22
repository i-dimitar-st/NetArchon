import os
import gc
import threading
import psutil
from config.config import config
from services.logger.logger import MainLogger

MEMORY_MANAGEMENT = config.get("memory_management")
INTERVAL = MEMORY_MANAGEMENT.get("interval")

_logger = MainLogger.get_logger(service_name="MEMORY")


class MemoryManager:

    @classmethod
    def init(cls, interval: int = INTERVAL):
        """Init."""
        if not hasattr(cls, "_worker"):
            cls._interval = interval
            cls._stop_event = threading.Event()
            cls._worker = threading.Thread(target=cls._work, daemon=True)

    @classmethod
    def start(cls):
        if cls._worker and cls._worker.is_alive():
            raise RuntimeError(f"{cls.__name__} already running.")
        if isinstance(cls._worker, threading.Thread):
            cls._stop_event.clear()
            cls._worker.start()
            _logger.info(f"{cls.__name__} started.")

    @classmethod
    def stop(cls):
        if cls._worker and cls._worker.is_alive():
            cls._stop_event.set()
            cls._worker.join(timeout=1)
            cls._worker = None
            _logger.info(f"{cls.__name__} stopped.")

    @classmethod
    def _work(cls):
        while not cls._stop_event.is_set():
            try:
                gc.collect()
                cls._log_stats()
            except Exception as err:
                _logger.warning(f"{str(err)}.")
            cls._stop_event.wait(cls._interval)

    @classmethod
    def _log_stats(cls):
        _message = ""
        _rss_memory_used = psutil.Process(os.getpid()).memory_info().rss / 1024 / 1024
        for _index, _generation in enumerate(gc.get_stats()):
            _message += (
                f"gen({_index}): "
                f"co:{_generation.get('collections', 0)}, "
                f"c:{_generation.get('collected', 0)}, "
                f"u:{_generation.get('uncollectable', 0)} "
            )
        _message += f" memory:{_rss_memory_used:.2f} MB."
        _logger.debug(_message)
