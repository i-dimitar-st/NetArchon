import threading
from copy import deepcopy
from pathlib import Path
from typing import Any
import yaml


DEFAULT_CONFIG_PATH = Path(__file__).parent / "config.yaml"


class Config:
    def __init__(self, path: Path = DEFAULT_CONFIG_PATH):
        self._lock = threading.RLock()
        self._path: Path = path
        self._config = {}
        self._load_config()

    def _load_config(self):
        with self._lock:
            with open(self._path, mode="r", encoding="utf-8") as _file_handle:
                _raw = yaml.safe_load(_file_handle)
                # ConfigSchema.model_validate(raw)
                self._config = _raw

    def reload(self):
        self._load_config()

    def get(self, key: str) -> Any:

        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty str.")

        if key not in self._config:
            raise RuntimeError("Unknown key.")

        with self._lock:
            return deepcopy(self._config[key])


config = Config()
