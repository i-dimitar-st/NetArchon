import threading
import yaml
from copy import deepcopy
from pathlib import Path
from typing import Any
from services.logger.logger import MainLogger


ROOT_PATH = Path(__file__).resolve().parents[2]
CONFIG_FULLPATH = ROOT_PATH / 'config.yaml'


logger = MainLogger.get_logger(service_name="CONFIG", log_level="debug")


class Config:
    _self = None
    _lock = threading.RLock()

    def __new__(cls):
        with cls._lock:
            if cls._self is None:
                cls._self = super().__new__(cls)
                cls._self._lock = threading.RLock()
                cls._self._config = {}
                cls._self._load_config()
        return cls._self

    def _load_config(self, path: Path = CONFIG_FULLPATH):
        with self._lock:
            try:
                with path.open("r", encoding="utf-8") as _fileHandle:
                    self._config = yaml.safe_load(_fileHandle)
                logger.debug(f"Config loaded from {path}")
            except Exception as e:
                logger.exception(f"Unexpected error loading config: {e}")
                self._config = {}

    def reload(self, path: Path = CONFIG_FULLPATH):
        self._load_config(path)

    def get(self, section: str, key: str = "") -> Any:
        with self._lock:
            if not section:
                raise ValueError("Section missing.")

            if not isinstance(section, str) or not isinstance(key, str):
                raise TypeError("Strings expected")

            section_data = self._config.get(section)
            if section_data is None:
                raise KeyError(f"{section} not found.")

            # If key is empty, return the whole section regardless of type
            if key == "":
                return deepcopy(section_data)

            # Now key is non-empty, so section_data must be a dict to get the key
            if not isinstance(section_data, dict):
                raise ValueError(f"Section '{section}' is not a dictionary, cannot get key '{key}'.")

            value = section_data.get(key)
            if value is None:
                raise KeyError(f"Key '{key}' not found in section '{section}'.")

            return deepcopy(value)


config = Config()
