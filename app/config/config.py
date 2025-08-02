from os import getenv
from pathlib import Path
from signal import SIGINT, SIGTERM, signal
from sys import exit

from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer
from watchdog.observers.api import BaseObserver

from app.models.models import Config

ROOT_PATH = Path(getenv("ROOT_PATH", "."))
CONFIG_FOLDER = ROOT_PATH / "config"
CONFIG_FILEPATH = CONFIG_FOLDER / "config.yaml"
DNS_BLACKLIST_FILEPATH = CONFIG_FOLDER / "blacklists.json"
DHCP_STATIC_MAP = CONFIG_FOLDER / "dhcp_static_map.json"


class OnFileChangeConfigHandler(FileSystemEventHandler):
    """
    Handles file modification events for config-related files.
    It has to be instance of FileSystemEventHandler and it has to implement on_modified.
    """

    def on_modified(self, event):
        if event.src_path == str(CONFIG_FILEPATH):
            config.reload()
        if event.src_path == str(DNS_BLACKLIST_FILEPATH):
            dns_blacklists.reload()
        if event.src_path == str(DHCP_STATIC_MAP):
            dhcp_static_config.reload()


def _shutdown(signum, frame):
    print("Stopping observer")
    _observer.stop()
    _observer.join()
    exit(0)


signal(SIGINT, _shutdown)
signal(SIGTERM, _shutdown)


config = Config(path=CONFIG_FILEPATH)
dns_blacklists = Config(path=DNS_BLACKLIST_FILEPATH)
dhcp_static_config = Config(path=DHCP_STATIC_MAP)


def _start_observer_watchdog() -> BaseObserver:
    observer: BaseObserver = Observer()
    observer.schedule(
        OnFileChangeConfigHandler(), path=str(CONFIG_FOLDER), recursive=False
    )
    observer.start()
    return observer


_observer: BaseObserver = _start_observer_watchdog()
