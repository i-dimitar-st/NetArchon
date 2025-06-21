import os
import gc
import threading
import psutil
from services.logger.logger import MainLogger

INTERVAL = 300
logger = MainLogger.get_logger(service_name="GC")


class GCMonitorService:

    @classmethod
    def _init(cls, interval: int = INTERVAL):
        """GCMonitorService instance."""
        cls._interval = interval
        cls._stop_event = threading.Event()
        cls._worker = threading.Thread(target=cls._work, daemon=True)

    @classmethod
    def start(cls, interval: int = INTERVAL):

        if not hasattr(cls, "_worker"):
            cls._init(interval)

        if cls._worker and cls._worker.is_alive():
            raise RuntimeError("GCMonitorService already running")

        if isinstance(cls._worker, threading.Thread) and not cls._worker.is_alive():
            cls._stop_event.clear()
            cls._worker.start()
            logger.info("GCMonitorService started.")

    @classmethod
    def stop(cls):
        if (hasattr(cls, "_worker") and cls._worker and cls._worker.is_alive()):
            cls._stop_event.set()
            cls._worker.join(timeout=1)
            cls._worker = None
            logger.info("GCMonitorService stopped.")

    @classmethod
    def _work(cls):
        while not cls._stop_event.is_set():
            try:
                gc.collect()
                cls._log_stats()
            except Exception as err:
                logger.warning(f"{str(err)}.")
            cls._stop_event.wait(cls._interval)

    @classmethod
    def _log_stats(cls):
        _message = ""
        _mem_used = psutil.Process(os.getpid()).memory_info().rss / 1024 / 1024
        for _index, _generation in enumerate(gc.get_stats()):
            _message += (f"gen({_index}): "
                         f"co:{_generation.get('collections', 0)}, "
                         f"c:{_generation.get('collected', 0)}, "
                         f"u:{_generation.get('uncollectable', 0)} ")
        _message += f" memory:{_mem_used:.2f} MB."
        logger.debug(_message)
