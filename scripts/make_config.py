#!/usr/bin/python3

import os
import yaml
from pathlib import Path

ROOT_PATH = Path(os.getenv("ROOT_PATH", Path(__file__).resolve().parents[1]))
CONFIG_DIR = ROOT_PATH / 'config'
CONFIG_DIR.mkdir(exist_ok=True)

with open(
    ROOT_PATH / 'scripts' / 'default_config.yaml', 'r', encoding='utf-8'
) as file_handle:
    config_data = yaml.safe_load(file_handle)

with open(CONFIG_DIR / 'config.yaml', 'w', encoding='utf-8') as file_handle:
    yaml.dump(config_data, file_handle, default_flow_style=False)
