from collections import defaultdict
from datetime import datetime
from gc import collect, get_objects, get_stats
from os import getpid
from sys import getsizeof
from threading import Event, Thread
from typing import Any

from objgraph import show_growth
from psutil import Process

from src.config.config import config
from src.services.logger.logger import MainLogger

WORKER_JOIN_TIMEOUT = 1
MEMORY_MANAGEMENT = config.get("memory_management")
INTERVAL = int(MEMORY_MANAGEMENT.get("interval"))

logger = MainLogger.get_logger(service_name="MEMORY")


class MemoryManager:
    @classmethod
    def init(cls, interval: int = INTERVAL) -> None:
        """Init.

        Args:
            interval(int): Time in seconds between memory checks.

        """
        if hasattr(cls, "_worker"):
            return

        cls._interval = int(interval)
        cls._stop_event = Event()
        cls._worker = Thread(target=cls._work, daemon=True)

    @classmethod
    def start(cls) -> None:
        if cls._worker and cls._worker.is_alive():
            raise RuntimeError("Already running.")

        cls._stop_event.clear()
        cls._worker = Thread(target=cls._work, daemon=True)
        cls._worker.start()
        logger.info("%s started.", cls.__name__)

    @classmethod
    def stop(cls) -> None:
        if cls._worker and cls._worker.is_alive():
            cls._stop_event.set()
            cls._worker.join(timeout=WORKER_JOIN_TIMEOUT)
        cls._worker = None
        logger.info("%s stopped.", cls.__name__)

    @classmethod
    def restart(cls) -> None:
        logger.info("%s restarting...", cls.__name__)
        cls.stop()
        cls.start()
        logger.info("%s restarted.", cls.__name__)

    @classmethod
    def _work(cls) -> None:
        while not cls._stop_event.is_set():
            try:
                collect()
                cls._log()
            except Exception as err:
                logger.warning("%s.", err)
            cls._stop_event.wait(cls._interval)

    @classmethod
    def _log(cls) -> None:
        rss_mb = int(Process(getpid()).memory_info().rss / 1024 / 1024)
        gen_stats: list[dict[str, Any]] = get_stats()
        print("\n--- Memory Check ---", datetime.now().isoformat())
        print(f"RSS Memory: {rss_mb} MB")
        print("Garbage Collector Stats:")

        for idx, gen in enumerate(gen_stats):
            print(
                f"  Generation {idx}: "
                f"Collections={gen.get('collections',0)}, "
                f"Collected={gen.get('collected',0)}, "
                f"Uncollectable={gen.get('uncollectable',0)}"
            )

        print_top_object_types()
        print("\n--- Showing growth of top object types ---")
        print("Type                           Count   Growth since last check")
        print("---------------------------------------------------------------")
        show_growth(limit=5)


def print_top_object_types(limit: int = 10) -> None:
    objs = get_objects()
    total_count = len(objs)

    print("\nTop object types:")
    print(f"{'Type':<25} {'Count':>10} {'% of total':>10} {'Approx. Size (KB)':>18}")
    print("-" * 65)

    type_map = defaultdict(list)
    for obj in objs:
        type_map[type(obj).__name__].append(obj)

    for typename, objs_of_type in sorted(
        type_map.items(), key=lambda x: len(x[1]), reverse=True
    )[:limit]:
        size_kb = sum(getsizeof(o) for o in objs_of_type) / 1024
        percent = (len(objs_of_type) / total_count) * 100
        print(
            f"{typename:<25} {len(objs_of_type):>10} {percent:>9.2f}% {size_kb:>16.1f} KB"
        )

        if typename == 'function':
            sample = objs_of_type[0]
            print(
                f"  Sample function: {sample.__qualname__} in module {sample.__module__}"
            )
