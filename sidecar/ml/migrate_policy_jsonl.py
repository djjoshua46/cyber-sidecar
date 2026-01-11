import json
import sys
from datetime import datetime

REQUIRED_ADD_DEFAULTS = {
    "ts_utc": None,          # we’ll fill
    "status_other": None,    # we’ll fill
}

def compute_status_other(row: dict) -> int:
    # Prefer existing one-hot fields if present
    s2 = int(row.get("status_2xx", 0) or 0)
    s4 = int(row.get("status_4xx", 0) or 0)
    s5 = int(row.get("status_5xx", 0) or 0)
    if (s2 + s4 + s5) > 0:
        return 0
    # Fallback to status_code if present
    sc = row.get("status_code", None)
    try:
        sc = int(sc)
    except Exception:
        sc = 0
    if 200 <= sc < 300 or 400 <= sc < 500 or 500 <= sc < 600:
        return 0
    return 1

def coerce_types(row: dict) -> dict:
    """
    Your validator expects:
      - method_get/method_post/is_export/status_* fields as floats or ints consistently
    We’ll normalize to int for 0/1 flags and float for continuous values.
    """
    int01_keys = [
        "method_get","method_post","is_export",
        "status_2xx","status_4xx","status_5xx","status_other",
        "deception_used","session_tainted",
        "user_present","session_present","device_present",
        "big_bytes","big_rows"
    ]
    float_keys = [
        "byte_size","row_count",
        "risk_score","behavior_score","drift_score","tone_risk"
    ]

    for k in int01_keys:
        if k in row:
            try:
                row[k] = int(row[k])
            except Exception:
                row[k] = 0

    for k in float_keys:
        if k in row:
            try:
                row[k] = float(row[k])
            except Exception:
                row[k] = 0.0

    return row

def main():
    if len(sys.argv) < 3:
        print("Usage: python -m sidecar.ml.migrate_policy_jsonl <input.jsonl> <output.jsonl>")
        raise SystemExit(2)

    in_path = sys.argv[1]
    out_path = sys.argv[2]

    now_iso = datetime.utcnow().isoformat() + "Z"
    total = 0
    written = 0

    with open(in_path, "r", encoding="utf-8") as fin, open(out_path, "w", encoding="utf-8") as fout:
        for line in fin:
            total += 1
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except Exception:
                continue

            # Add ts_utc if missing
            if not row.get("ts_utc"):
                row["ts_utc"] = now_iso

            # Add status_other if missing
            if "status_other" not in row or row.get("status_other") is None:
                row["status_other"] = compute_status_other(row)

            # Ensure schema_version exists
            if not row.get("schema_version"):
                row["schema_version"] = "policy_v1"

            row = coerce_types(row)

            fout.write(json.dumps(row, ensure_ascii=False) + "\n")
            written += 1

    print(f"Done. total={total} written={written} -> {out_path}")

if __name__ == "__main__":
    main()
