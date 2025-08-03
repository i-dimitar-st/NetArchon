from os import getenv
from pathlib import Path
from signal import SIGINT, SIGTERM, signal
from sys import exit
from threading import RLock, Timer

from dotenv import load_dotenv
from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer
from watchdog.observers.api import BaseObserver

from app.models.models import Config

load_dotenv()

ROOT_PATH = Path(getenv("ROOT_PATH", "."))
CONFIG_PATH: Path = ROOT_PATH / getenv("CONFIG_DIR", "config")
RELOAD_DEBOUNCE_DELAY = float(getenv("RELOAD_DEBOUNCE_DELAY", 5.0))
CONFIG_FILEPATH: Path = CONFIG_PATH / getenv("CONFIG_FILE", "config.yaml")
DNS_BLACKLIST_FILEPATH: Path = CONFIG_PATH / getenv(
    "DNS_BLACKLIST_FILE", "blacklist.json"
)
DHCP_STATIC_MAP: Path = CONFIG_PATH / getenv(
    "DHCP_STATIC_MAP_FILE", "dhcp_static_map.json"
)


_timer_lock = RLock()
config_reload_timer: Timer | None = None
dns_blacklists_reload_timer: Timer | None = None
dhcp_static_config_reload_timer: Timer | None = None
config = Config(path=CONFIG_FILEPATH)
dns_blacklists = Config(path=DNS_BLACKLIST_FILEPATH)
dhcp_static_config = Config(path=DHCP_STATIC_MAP)


def _cancelAliveTimer(timer: Timer | None):
    if timer and timer.is_alive():
        timer.cancel()


class OnFileChangeConfigHandler(FileSystemEventHandler):
    """
    Handles file modification events for config-related files.
    It has to be instance of FileSystemEventHandler and it has to implement on_modified.
    """

    def on_modified(self, event):

        if event.src_path == str(CONFIG_FILEPATH):
            with _timer_lock:
                global config_reload_timer, config
                _cancelAliveTimer(config_reload_timer)
                config_reload_timer = Timer(RELOAD_DEBOUNCE_DELAY, config.reload)
                config_reload_timer.start()

        elif event.src_path == str(DNS_BLACKLIST_FILEPATH):
            with _timer_lock:
                global dns_blacklists_reload_timer, dns_blacklists
                _cancelAliveTimer(dns_blacklists_reload_timer)
                dns_blacklists_reload_timer = Timer(
                    RELOAD_DEBOUNCE_DELAY, dns_blacklists.reload
                )
                dns_blacklists_reload_timer.start()

        elif event.src_path == str(DHCP_STATIC_MAP):
            with _timer_lock:
                global dhcp_static_config_reload_timer, dhcp_static_config
                _cancelAliveTimer(dhcp_static_config_reload_timer)
                dhcp_static_config_reload_timer = Timer(
                    RELOAD_DEBOUNCE_DELAY, dhcp_static_config.reload
                )
                dhcp_static_config_reload_timer.start()


def _shutdown(signum, frame):
    print("Stopping observer")
    _observer.stop()
    _observer.join()
    for _timer in [
        config_reload_timer,
        dns_blacklists_reload_timer,
        dhcp_static_config_reload_timer,
    ]:
        if _timer:
            _timer.cancel()
    exit(0)


signal(SIGINT, _shutdown)
signal(SIGTERM, _shutdown)


def _start_observer_watchdog(dir_path: Path = CONFIG_PATH) -> BaseObserver:
    observer: BaseObserver = Observer()
    observer.schedule(OnFileChangeConfigHandler(), path=str(dir_path), recursive=False)
    observer.start()
    return observer


_observer: BaseObserver = _start_observer_watchdog()
