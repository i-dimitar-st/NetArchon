import os
import copy
import yaml
import pytest
from pathlib import Path
from config.config import Config


APP_ROOT_PATH = Path(os.environ.get("APP_ROOT_PATH", "."))
CONFIG_PATH: Path = APP_ROOT_PATH / "config" / "config.yaml"


@pytest.fixture
def real_config():
    try:
        config = Config(path=CONFIG_PATH)
    except yaml.YAMLError as e:
        pytest.fail(f"Error parsin YAML {e}.")
    except Exception as e:
        pytest.fail(f"Failed loading config {e}.")
    return config


def test_config_path(real_config):
    # Negative
    assert real_config._path is not None, "config path None."
    assert isinstance(
        real_config._path, Path
    ), f"Invalid type: {type(real_config._path).__name__}."

    # Positive
    assert real_config._path.exists(), f"Path does not exist: {real_config._path}."
    assert real_config._path.is_file(), f"Not a filepath: {real_config._path}."


def test_config_is_valid(real_config):
    # Negative
    assert real_config._config is not None, "Config dictionary is None"
    assert isinstance(
        real_config._config, dict
    ), f"Wrong type {type(real_config._config).__name__}."

    # Positive
    assert real_config._config != {}, "Config dictionary is empty"


def test_config_reload(real_config):
    _previous_config = copy.deepcopy(real_config._config)
    real_config.reload()

    test_config_is_valid(real_config)
    if real_config._config == _previous_config:
        message = "Reload => same config."
    else:
        message = "Reload => config changed."
    print(message)
