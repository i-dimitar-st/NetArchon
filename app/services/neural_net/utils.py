import json
import sqlite3
from pathlib import Path

from torch import cuda, load as torchLoad


def filter_unknown_chars_from_domain(domain: str, allowed_chars: str) -> str:
    """
    filter unallowed chars in domain.
    Args:
        domain (str): The input string (e.g., a domain name).
        allowed_chars (str): Characters to keep.
    Returns:
        str: The filtered string.
    """
    if not isinstance(domain, str):
        raise TypeError("domain must be a str")
    if not domain:
        raise ValueError("domain must not be empty")
    if not isinstance(allowed_chars, str):
        raise TypeError("allowed_chars must be a str")
    if not allowed_chars:
        raise ValueError("allowed_chars must not be empty")
    return "".join(_char for _char in domain if _char in allowed_chars)


def generate_char2idx(allowed_chars: str) -> dict:
    if not isinstance(allowed_chars, str):
        raise TypeError("allowed_chars must be a str")
    if not allowed_chars:
        raise ValueError("allowed_chars must not be empty")
    # 0 must not be used as its used for padding
    return {_char: _index + 1 for _index, _char in enumerate(allowed_chars)}


def get_dns_history(file_path: Path) -> list:
    if not isinstance(file_path, Path):
        raise TypeError("file_path must be a pathlib.Path object")
    if not file_path.exists():
        raise FileNotFoundError(f"{file_path} does not exist")
    if not file_path.is_file():
        raise ValueError(f"{file_path} is not a file")
    try:
        with sqlite3.connect(file_path) as conn:
            cursor = conn.cursor()

            cursor.execute("PRAGMA table_info(history)")
            columns: list[str] = [column[1] for column in cursor.fetchall()]

            cursor.execute("SELECT * FROM history")
            query_result: list[tuple] = cursor.fetchall()

            history_record = []
            for each in query_result:
                history_record.append(dict(zip(columns, each)))

            return sorted({each["query"] for each in history_record})

    except Exception as e:
        print(f"Error: Failed to read {file_path} - {e}")
        return []


def get_device() -> str:
    return "cuda" if cuda.is_available() else "cpu"


def clean_device_cache(device: str = ''):
    if device.startswith("cuda") and cuda.is_available():
        cuda.empty_cache()


def get_allowed_devices() -> list[str]:
    allowed = ["cpu"]
    cuda_devices = [f"cuda:{_index}" for _index in range(cuda.device_count())]
    allowed.extend(cuda_devices)
    return allowed


def get_local_file(file_path: Path) -> dict:
    if not isinstance(file_path, Path):
        raise TypeError("file_path must be a pathlib.Path object")
    if not file_path.exists():
        raise FileNotFoundError(f"{file_path} does not exist")
    if not file_path.is_file():
        raise ValueError(f"{file_path} is not a file")
    with file_path.open("r", encoding="utf-8") as f:
        return json.load(f)


def load_model_timestamp_from_disk(file_path: Path) -> str:
    """
    Load a DomainClassifier from disk, including its configuration and parameters.
    Args:
        file_path(Path): Location to load from
    """
    if not isinstance(file_path, Path):
        raise TypeError("file_path must be a pathlib.Path object")
    if not file_path.exists():
        raise FileNotFoundError(f"{file_path} does not exist")
    if not file_path.is_file():
        raise ValueError(f"{file_path} is not a file")

    _temp_data = torchLoad(file_path, map_location="cpu")
    return _temp_data["timestamp"]
