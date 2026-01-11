import hashlib
from datetime import datetime
from pathlib import Path
from typing import Dict

LOG_DIR = Path("/var/log/sidecar")
LOG_DIR.mkdir(parents=True, exist_ok=True)

def append_event(event: Dict):
    line = f"{datetime.utcnow().isoformat()}|{event}\n"
    # Hash for chain integrity – basic MVP
    h = hashlib.sha256(line.encode("utf-8")).hexdigest()
    with open(LOG_DIR / "events.log", "a", encoding="utf-8") as f:
        f.write(f"{h}|{line}")
