import os
import gc
import threading
import time
from collections import Counter
import psutil
from config.config import config
from services.logger.logger import MainLogger
import objgraph
import inspect
import types

WORKER_JOIN_TIMEOUT = 1
MEMORY_MANAGEMENT = config.get("memory_management")
INTERVAL = int(MEMORY_MANAGEMENT.get("interval"))

_logger = MainLogger.get_logger(service_name="MEMORY")


class MemoryManager:

    @classmethod
    def init(cls, interval: int = INTERVAL):
        """Init."""
        if not hasattr(cls, "_worker"):
            cls._interval = int(interval)
            cls._stop_event = threading.Event()
            cls._worker = threading.Thread(target=cls._work, daemon=True)

    @classmethod
    def start(cls):
        if cls._worker and cls._worker.is_alive():
            raise RuntimeError("Already running.")
        if isinstance(cls._worker, threading.Thread):
            cls._stop_event.clear()
            cls._worker.start()
            _logger.info("%s started.", cls.__name__)

    @classmethod
    def stop(cls):
        if cls._worker and cls._worker.is_alive():
            cls._stop_event.set()
            cls._worker.join(timeout=WORKER_JOIN_TIMEOUT)
            cls._worker = None
            _logger.info("%s stopped.", cls.__name__)

    @classmethod
    def _work(cls):
        while not cls._stop_event.is_set():
            try:
                gc.collect()
                cls._log()
            except Exception as err:
                _logger.warning("%s.", err)
            cls._stop_event.wait(cls._interval)

    @classmethod
    def _log(cls):
        _message = ""
        _rss_memory_used = int(
            psutil.Process(os.getpid()).memory_info().rss / 1024 / 1024
        )
        for _index, _generation in enumerate(gc.get_stats()):
            _message += (
                f"gen({_index}): "
                f"co:{_generation.get('collections', 0)}, "
                f"c:{_generation.get('collected', 0)}, "
                f"u:{_generation.get('uncollectable', 0)} "
            )
        _message += f" memory:{_rss_memory_used} MB."
        _logger.debug(_message)
        print("--- mem check ---", time.time())
        objgraph.show_growth(limit=5)
        print_top_object_types()
        # lists = [obj for obj in gc.get_objects() if type(obj) is list]
        # lists.sort(key=len, reverse=True)
        # objgraph.show_backrefs(lists[0], filename="backrefs-lists.dot", max_depth=3)
        # explore_referents(lists[0])
        # tuples = [obj for obj in gc.get_objects() if type(obj) is tuple]
        # tuples.sort(key=len, reverse=True)
        # objgraph.show_backrefs(tuples[0], filename="backrefs-tuples.svg", max_depth=5)
        # explore_live_functions()
        # objgraph.show_backrefs(tuples[0], filename="backrefs-tuples.dot", max_depth=3)
        # explore_referents(tuples[0])


def explore_referents(obj, depth=1, _visited=None):
    if _visited is None:
        _visited = set()
    if id(obj) in _visited or depth == 0:
        return
    _visited.add(id(obj))

    referents = gc.get_referents(obj)
    print(f"Object id={id(obj)} type={type(obj)} refers to {len(referents)} objects")

    for ref in referents:
        print(f"  -> id={id(ref)} type={type(ref)}")

    # Recursively explore down
    for ref in referents:
        explore_referents(ref, depth=depth - 1, _visited=_visited)


def print_top_object_types(limit=5):
    objs = gc.get_objects()
    type_counter = Counter(type(obj).__name__ for obj in objs)

    print("Top object types (absolute counts):")
    for typename, count in type_counter.most_common(limit):
        print(f"{typename:<20} {count}")


def explore_live_functions():
    functions = [obj for obj in gc.get_objects() if inspect.isfunction(obj)]
    print(f"Total live functions: {len(functions)}\n")

    for fn in functions:
        try:
            code = fn.__code__
            filename = code.co_filename

            # Only inside your project and exclude site-packages
            if (
                "/projects/gitlab/netarchon" not in filename
                or "site-packages" in filename
            ):
                continue

            name = fn.__name__
            lineno = code.co_firstlineno
            closure = fn.__closure__

            # print(f"[FUNC] {name} — {filename}:{lineno}")

            if closure:
                print(
                    f"  └─ Closure: {[c.cell_contents for c in closure if hasattr(c, 'cell_contents')]}"
                )
        except Exception as e:
            print(f"[ERROR accessing function info] {e}")
