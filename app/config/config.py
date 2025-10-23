from os import getenv
from pathlib import Path
from signal import SIGINT, SIGTERM, signal
from sys import exit
from threading import RLock

from dotenv import load_dotenv
from watchdog.observers import Observer
from watchdog.observers.api import BaseObserver

from app.models.models import Config, OnFileChangeConfigHandler

load_dotenv()

RELOAD_DEBOUNCE_DELAY = float(getenv("RELOAD_DEBOUNCE_DELAY", 3.0))

ROOT_PATH = Path(getenv("ROOT_PATH", "."))
CONFIG_DIR = getenv("CONFIG_DIR", "config")
CONFIG_PATH: Path = ROOT_PATH / CONFIG_DIR

CONFIG_FILE = getenv("CONFIG_FILE", "config.yaml")
CONFIG_FILEPATH: Path = CONFIG_PATH / CONFIG_FILE

DNS_BLACKLIST = getenv("DNS_BLACKLIST_FILE", "blacklists.json")
DNS_BLACKLIST_FILEPATH: Path = CONFIG_PATH / DNS_BLACKLIST

DHCP_STATIC_MAP_FILE = getenv("DHCP_STATIC_MAP_FILE", "dhcp_static_map.json")
DHCP_STATIC_CONFIG: Path = CONFIG_PATH / DHCP_STATIC_MAP_FILE


_global_timer_lock = RLock()
config = Config(path=CONFIG_FILEPATH)
dns_blacklists = Config(path=DNS_BLACKLIST_FILEPATH)
dhcp_static_config = Config(path=DHCP_STATIC_CONFIG)


def _start_file_watcher(file_path: Path, reload_delay: float, reload_function) -> BaseObserver:
    observer: BaseObserver = Observer()
    observer.schedule(
        event_handler=OnFileChangeConfigHandler(
            file_path=file_path,
            reload_delay=reload_delay,
            reload_function=reload_function,
        ),
        path=str(file_path.parent),
        recursive=False,
    )
    observer.start()
    return observer


_config_file_observer: BaseObserver = _start_file_watcher(
    file_path=CONFIG_FILEPATH,
    reload_delay=RELOAD_DEBOUNCE_DELAY,
    reload_function=config.reload,
)

_dns_blacklists_file_observer: BaseObserver = _start_file_watcher(
    file_path=DNS_BLACKLIST_FILEPATH,
    reload_delay=RELOAD_DEBOUNCE_DELAY,
    reload_function=dns_blacklists.reload,
)

_dhcp_static_config: BaseObserver = _start_file_watcher(
    file_path=DHCP_STATIC_CONFIG,
    reload_delay=RELOAD_DEBOUNCE_DELAY,
    reload_function=dhcp_static_config.reload,
)


def _shutdown(signum, frame):
    with _global_timer_lock:
        print("Stopping observer")
        _config_file_observer.stop()
        _config_file_observer.join()
        _dns_blacklists_file_observer.stop()
        _dns_blacklists_file_observer.join()
        _dhcp_static_config.stop()
        _dhcp_static_config.join()
        exit(0)


signal(SIGINT, _shutdown)
signal(SIGTERM, _shutdown)
