import threading
import json
import time
import copy
from pathlib import Path
from services.service_logger import MainLogger

ROOT_PATH = Path(__file__).resolve().parents[1]
CONFIG_PATH = ROOT_PATH / 'config'
DNS_CONFIG_FULLPATH = CONFIG_PATH / 'config.json'

config_logger = MainLogger.get_logger(service_name="CONFIG", log_level="debug")


class Config:
    _lock = threading.RLock()
    _is_init = False

    @classmethod
    def _init(cls):
        with cls._lock:

            if cls._is_init:
                return

            try:

                with open(DNS_CONFIG_FULLPATH, mode="r", encoding='utf-8') as file_handle:
                    _config = json.load(file_handle)

                    cls.timestamp = _config.get("timestamp", time.time())
                    cls.server = _config.get("server", {})
                    cls.dns = _config.get("dns", {})
                    cls.dhcp = _config.get("dhcp", {})
                    cls.paths = {
                        "root": ROOT_PATH,
                        "db": ROOT_PATH / "db",
                        "config": ROOT_PATH / "config"
                    }
                    cls._is_init = True
                    config_logger.debug("Config loaded successfully")

            except Exception as err:
                config_logger.error(f"Error loading config {str(err)}")
                cls.timestamp = time.time()
                cls.server = {}
                cls.dns = {}
                cls.dhcp = {}
                cls._is_init = True

    @classmethod
    def get_dns(cls):
        with cls._lock:
            return copy.deepcopy(cls.dns)

    @classmethod
    def get_dhcp(cls):
        with cls._lock:
            return copy.deepcopy(cls.dhcp)

    @classmethod
    def get_server(cls):
        with cls._lock:
            return copy.deepcopy(cls.server)

    @classmethod
    def get_paths(cls):
        with cls._lock:
            return copy.deepcopy(cls.paths)

    @classmethod
    def reload(cls):
        with cls._lock:
            cls._is_init = False
            cls._init()


Config._init()
