#!/usr/bin/python3
import os
import json
from pathlib import Path
from datetime import datetime, timezone

ROOT_PATH = Path(os.getenv("ROOT_PATH", Path(__file__).resolve().parents[1]))
CONFIG_DIR = ROOT_PATH / 'config'
CONFIG_DIR.mkdir(exist_ok=True)

blacklists = {
    "timestamp": datetime.now(timezone.utc).isoformat(),
    "payload": {"rules": ["*.smartadserver.com"], "urls": ["sync.screencore.io"]},
}

with open(CONFIG_DIR / 'blacklists.json', 'w', encoding='utf-8') as f:
    json.dump(blacklists, f, indent=4, ensure_ascii=False)

