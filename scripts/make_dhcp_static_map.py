#!/usr/bin/python3
import os
import json
from pathlib import Path
from datetime import datetime, timezone

ROOT_PATH = Path(os.getenv("ROOT_PATH", Path(__file__).resolve().parents[1]))
CONFIG_DIR = ROOT_PATH / 'config'
CONFIG_DIR.mkdir(exist_ok=True)

dhcp_static_map = {
    "timestamp": datetime.now(timezone.utc).isoformat(),
    "payload": {
        "D0:DB:B7:6A:2C:98": "192.168.20.1",
        "3C:2A:F4:10:24:2F": "192.168.20.10",
        "E4:C3:2A:03:19:3E": "192.168.20.20",
        "68:3E:C0:A4:C5:6E": "192.168.20.30",
        "2C:FE:E2:E8:74:76": "192.168.20.40",
        "A4:55:90:18:DD:5E": "192.168.20.80",
        "3C:9C:0F:4C:84:8E": "192.168.20.95",
    },
}

with open(CONFIG_DIR / 'dhcp_static_map.json', 'w', encoding='utf-8') as f:
    json.dump(dhcp_static_map, f, indent=4, ensure_ascii=False)
