from json import load
from os import getenv
from pathlib import Path
from signal import SIGINT, SIGTERM, signal
from sys import exit
from threading import RLock
from types import MappingProxyType
from typing import Any

from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer
from watchdog.observers.api import BaseObserver
from yaml import safe_load


ROOT_PATH = Path(getenv("ROOT_PATH", "."))
CONFIG_FOLDER = ROOT_PATH / "config"
CONFIG_FILEPATH = CONFIG_FOLDER / "config.yaml"
DHCP_STATIC_MAP = CONFIG_FOLDER / "dhcp_static_map.json"


class Config:
    """Defines application level Config"""

    def __init__(self, path: Path = CONFIG_FILEPATH):
        self._lock = RLock()
        self._path: Path = path
        self._config = {}
        self._load()

    @classmethod
    def _is_json(cls, path: Path) -> bool:
        return path.suffix.lower() == ".json"

    def _load(self):
        with self._lock:
            with open(self._path, mode="r", encoding="utf-8") as _file_handle:
                if self._is_json(self._path):
                    self._config = load(_file_handle).get("payload")
                else:
                    self._config = safe_load(_file_handle)

    def reload(self):
        """Reload"""
        self._load()

    def get(self, key: str) -> Any:
        """
        Get parameter from config obj
        Args:
            key(str): Name for which config is required.
        """

        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty str.")

        if key not in self._config:
            raise RuntimeError("Unknown key.")

        with self._lock:
            return MappingProxyType(self._config[key])

    def get_config(self) -> MappingProxyType:
        """
        Get config dict as Proxy.
        """
        with self._lock:
            return MappingProxyType(self._config)


class OnFileChangeConfigHandler(FileSystemEventHandler):
    """
    Handles file modification events for config-related files.
    It has to be instance of FileSystemEventHandler and it has to implement on_modified.
    """

    def on_modified(self, event):
        if event.src_path == str(CONFIG_FILEPATH):
            config.reload()
            print("Reloaded config")
        if event.src_path == str(DHCP_STATIC_MAP):
            dhcp_static_config.reload()


def _shutdown(signum, frame):
    print("Stopping observer")
    _observer.stop()
    _observer.join()
    exit(0)


signal(SIGINT, _shutdown)
signal(SIGTERM, _shutdown)


config = Config()
dhcp_static_config = Config(path=DHCP_STATIC_MAP)


def _start_observer_watchdog() -> BaseObserver:
    observer: BaseObserver = Observer()
    observer.schedule(
        OnFileChangeConfigHandler(), path=str(CONFIG_FOLDER), recursive=False
    )
    observer.start()
    return observer


_observer: BaseObserver = _start_observer_watchdog()
