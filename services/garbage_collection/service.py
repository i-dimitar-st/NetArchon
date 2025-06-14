import os
import gc
import threading
import psutil
from services.logger.logger import MainLogger

logger = MainLogger.get_logger(service_name="GC")

class GCMonitorService:
    def __init__(self, interval: int = 300):
        """GCMonitorService instance."""
        self._interval = interval
        self._event_stop = threading.Event()
        self._worker = threading.Thread(target=self._work, daemon=True)

    def start(self):
        if self._worker.is_alive():
            raise RuntimeError("GCMonitorService already running")
        self._worker.start()
        logger.info("GCMonitorService started.")

    def stop(self):
        self._event_stop.set()
        self._worker.join(timeout=1)
        logger.info("GCMonitorService stopped.")

    def _work(self):
        while not self._event_stop.is_set():
            try:
                self._log_gc_stats()
            except Exception as err:
                logger.warning(f"GC monitoring error: {str(err)}")
            self._event_stop.wait(self._interval)

    def _log_gc_stats(self):
        _mem_used = psutil.Process(os.getpid()).memory_info().rss / 1024 / 1024
        logger.debug(
            f"GC: {', '.join(
                f"Gen{_generation} c:{_stats['collected']}, uc:{_stats['uncollectable']}"
                for _generation, _stats in enumerate(gc.get_stats()))} "
            f"Tracked: {len(gc.get_objects())}, "
            f"Memory: {_mem_used:.2f} MB.")
        self.force_gc()

    def force_gc(self):
        collected = gc.collect()
        logger.debug(f"Cleaning GC: collected {collected} unreachable objects.")
