from json import dumps as jsonDumps
from pathlib import Path
from shutil import rmtree
from time import sleep

import pytest
from watchdog.observers.api import BaseObserver

from src.config.config import _start_file_watcher
from src.models.models import Config

TEST_DIR = Path("./tests/config/")
YAML_FILE = TEST_DIR / "config.yaml"
JSON_FILE = TEST_DIR / "blacklist.json"


def setup_temp():
    if TEST_DIR.exists():
        rmtree(TEST_DIR)
    TEST_DIR.mkdir(parents=True)

    YAML_FILE.write_text("TEST_KEY: TEST_VALUE")


def destroy_temp():
    rmtree(TEST_DIR)


def test_file_reload_yaml():
    setup_temp()
    _reload_delay = 3.0

    test_config = Config(path=YAML_FILE)
    temp_observer: BaseObserver = _start_file_watcher(
        file_path=YAML_FILE,
        reload_delay=_reload_delay,
        reload_function=test_config.reload,
    )

    YAML_FILE.write_text("TEST_KEY_2: NEW_VALUE_2")
    assert "NEW_VALUE_2" in YAML_FILE.read_text()
    with pytest.raises(RuntimeError):
        assert test_config.get("TEST_KEY_2") is None

    sleep(_reload_delay + 1)
    assert test_config.get("TEST_KEY_2") == "NEW_VALUE_2"

    temp_observer.stop()
    temp_observer.join()

    destroy_temp()


def test_burst_file_reload_yaml():
    setup_temp()
    _reload_delay = 3.0

    test_config = Config(path=YAML_FILE)
    temp_observer: BaseObserver = _start_file_watcher(
        file_path=YAML_FILE,
        reload_delay=_reload_delay,
        reload_function=test_config.reload,
    )
    YAML_FILE.write_text("TEST_KEY_2: NEW_VALUE_2")
    sleep(0.1)
    YAML_FILE.write_text("TEST_KEY_3: NEW_VALUE_3")
    sleep(0.1)
    YAML_FILE.write_text("TEST_KEY_4: NEW_VALUE_4")
    sleep(0.1)

    assert "NEW_VALUE_4" in YAML_FILE.read_text()
    with pytest.raises(RuntimeError):
        assert test_config.get("TEST_KEY_4")
    with pytest.raises(RuntimeError):
        assert test_config.get("TEST_KEY_3")
    with pytest.raises(RuntimeError):
        assert test_config.get("TEST_KEY_2")

    sleep(_reload_delay + 1)
    assert test_config.get("TEST_KEY_4") == "NEW_VALUE_4"

    temp_observer.stop()
    temp_observer.join()

    destroy_temp()
