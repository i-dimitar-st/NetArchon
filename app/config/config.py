from copy import deepcopy
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
DNS_CONTROL_LIST = CONFIG_FOLDER / "dns_control_list.json"


class Config:
    """Defines application level Config"""

    def __init__(self, path: Path = CONFIG_FILEPATH):
        self._lock = RLock()
        self._path: Path = path
        self._config = {}
        self._load()

    def _load(self):
        with self._lock:
            with open(self._path, mode="r", encoding="utf-8") as _file_handle:
                # ConfigSchema.model_validate(raw)
                self._config = safe_load(_file_handle)

    def reload(self):
        """Reload config"""
        self._load()

    def get(self, key: str) -> Any:
        """Get parameter from config obj"""

        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty str.")

        if key not in self._config:
            raise RuntimeError("Unknown key.")

        with self._lock:
            return deepcopy(self._config[key])


def _load_static_dhcp_mapping(path: Path = DHCP_STATIC_MAP) -> MappingProxyType:
    """Loads DHCP mac to ip static mapping table."""
    with open(path, encoding="utf-8", mode="r") as file_handle:
        return MappingProxyType(load(file_handle).get("payload", {}))


def _load_dns_control_list(path: Path = DNS_CONTROL_LIST) -> MappingProxyType:
    with open(path, encoding="utf-8", mode="r") as file_handle:
        return MappingProxyType(load(file_handle).get("blacklist", {}))


class SimpleHandler(FileSystemEventHandler):
    def on_modified(self, event):
        src = event.src_path
        if src == str(DHCP_STATIC_MAP):
            try:
                global dhcp_static_config
                dhcp_static_config = _load_static_dhcp_mapping()
                print(f"Reloaded {DHCP_STATIC_MAP}")
            except:
                print(f"Failed reloading {DHCP_STATIC_MAP}")

        elif src == str(DNS_CONTROL_LIST):
            try:
                global dns_control_list
                dns_control_list = _load_dns_control_list()
                print(f"Reloaded {DNS_CONTROL_LIST}")
            except:
                print(f"Failed reloaded {DNS_CONTROL_LIST}")
        elif src == str(CONFIG_FILEPATH):
            try:
                global config
                config.reload()
                print("Reloaded config")
            except:
                print("Failed reloaded config")


def _start_observer_watchdog() -> BaseObserver:
    observer: BaseObserver = Observer()
    observer.schedule(SimpleHandler(), path=str(CONFIG_FOLDER), recursive=False)
    observer.start()
    return observer


def _shutdown(signum, frame):
    print("Stopping observer")
    observer.stop()
    observer.join()
    exit(0)


signal(SIGINT, _shutdown)
signal(SIGTERM, _shutdown)


config = Config()
dhcp_static_config = _load_static_dhcp_mapping()
dns_control_list = _load_dns_control_list()
observer: BaseObserver = _start_observer_watchdog()
