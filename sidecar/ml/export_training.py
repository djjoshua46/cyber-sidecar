# sidecar/ml/export_training.py
import json
import os
from datetime import datetime
from typing import Dict, Iterator, List, Tuple


def _default_training_path() -> str:
    """
    Default training path:
      <repo_root>/training/policy_training_YYYYMMDD.jsonl
    """
    repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
    out_dir = os.path.join(repo_root, "training")
    os.makedirs(out_dir, exist_ok=True)
    fname = f"policy_training_v2_{datetime.utcnow().strftime('%Y%m%d')}.jsonl"
    return os.path.join(out_dir, fname)


def append_training_row(row: Dict, path: str = None) -> None:
    path = path or _default_training_path()
    os.makedirs(os.path.dirname(path), exist_ok=True)

    line = json.dumps(row, ensure_ascii=False) + "\n"

    # Cross-platform lock:
    # - Windows: msvcrt.locking
    # - Linux/Mac: fcntl.flock
    try:
        import msvcrt  # type: ignore

        with open(path, "a", encoding="utf-8") as f:
            f.seek(0)
            msvcrt.locking(f.fileno(), msvcrt.LK_LOCK, 1)
            try:
                f.seek(0, os.SEEK_END)
                f.write(line)
                f.flush()
                os.fsync(f.fileno())
            finally:
                f.seek(0)
                msvcrt.locking(f.fileno(), msvcrt.LK_UNLCK, 1)

    except ImportError:
        import fcntl  # type: ignore

        with open(path, "a", encoding="utf-8") as f:
            fcntl.flock(f.fileno(), fcntl.LOCK_EX)
            try:
                f.write(line)
                f.flush()
                os.fsync(f.fileno())
            finally:
                fcntl.flock(f.fileno(), fcntl.LOCK_UN)


def iter_jsonl_rows(path: str) -> Iterator[Tuple[int, Dict]]:
    with open(path, "r", encoding="utf-8") as f:
        for i, line in enumerate(f, start=1):
            line = line.strip()
            if not line:
                continue
            yield i, json.loads(line)


def validate_row(row: Dict) -> List[str]:
    """
    This validator matches the schema YOU ARE CURRENTLY WRITING from proxy.py.

    Required keys based on your JSONL sample:
      tenant_id
      user_present, session_present, device_present
      method
      status_code, byte_size, row_count
      behavior_score, drift_score, tone_risk
      deception_used, session_tainted
      target_url
      label_action, label_outcome

    Optional but recommended:
      schema_version
      synthetic
    """
    required = [
        "tenant_id",
        "user_present",
        "session_present",
        "device_present",
        "method",
        "status_code",
        "byte_size",
        "row_count",
        "behavior_score",
        "drift_score",
        "tone_risk",
        "deception_used",
        "session_tainted",
        "target_url",
        "label_action",
        "label_outcome",
    ]

    missing = [k for k in required if k not in row]
    problems: List[str] = []
    if missing:
        problems.append(f"missing_keys:{missing}")

    # lightweight type sanity checks (don’t over-enforce yet)
    for k in ["status_code"]:
        if k in row and not isinstance(row[k], int):
            problems.append(f"type:{k}:expected_int")
    for k in ["byte_size", "row_count", "behavior_score", "drift_score", "tone_risk"]:
        if k in row and not isinstance(row[k], (int, float)):
            problems.append(f"type:{k}:expected_number")

    return problems
