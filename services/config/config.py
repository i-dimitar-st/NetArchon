import threading
import yaml
from copy import deepcopy
from pathlib import Path
from typing import Any
from services.logger.logger import MainLogger


ROOT_PATH = Path(__file__).resolve().parent.parent.parent
CONFIG_FULLPATH = ROOT_PATH / "config.yaml"

logger = MainLogger.get_logger(service_name="CONFIG", log_level="debug")


class Config:
    def __init__(self):
        if hasattr(self, "_initialized"):
            return

        self._lock = threading.RLock()
        self._config = {}
        self._load_config()
        self._initialized = True

    def _load_config(self, path: Path = CONFIG_FULLPATH):
        with self._lock:
            try:
                with path.open("r", encoding="utf-8") as f:
                    self._config = yaml.safe_load(f)
                logger.debug(f"Config loaded from {path}")
            except Exception as err:
                logger.exception(f"Unexpected error loading config: {err}")
                self._config = {}

    def reload(self, path: Path = CONFIG_FULLPATH):
        self._load_config(path)

    def get(self, section: str, key: str = "") -> Any:

        if not section:
            raise ValueError("Section missing.")

        if not isinstance(section, str) or not isinstance(key, str):
            raise TypeError("Strings expected")

        with self._lock:
            section_data = self._config.get(section)
            if section_data is None:
                raise KeyError(f"{section} not found.")

            if key == "":
                return deepcopy(section_data)

            if not isinstance(section_data, dict):
                raise ValueError(f"Section '{section}' is not a dictionary, cannot get key '{key}'.")

            value = section_data.get(key)
            if value is None:
                raise KeyError(f"Key '{key}' not found in section '{section}'.")

            return deepcopy(value)


config = Config()
