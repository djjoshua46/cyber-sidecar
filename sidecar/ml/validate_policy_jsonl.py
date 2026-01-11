# sidecar/ml/validate_policy_jsonl.py
import json
import sys

REQUIRED_KEYS = [
    "schema_version",
    "tenant_id",

    # core numeric inputs
    "risk_score",
    "behavior_score",
    "drift_score",
    "tone_risk",
    "row_count",
    "byte_size",

    # categorical strings (kept as strings)
    "risk_level",
    "behavior_level",

    # feature flags (0/1 OR bool)
    "method_get",
    "method_post",
    "is_export",
    "status_2xx",
    "status_4xx",
    "status_5xx",
    "status_other",
    "deception_used",
    "session_tainted",

    # presence flags (0/1 OR bool)
    "user_present",
    "device_present",
    "session_present",

    # time
    "ts_utc",

    # labels
    "label_action",
    "label_outcome",
]

BOOLISH_KEYS = {
    "method_get",
    "method_post",
    "is_export",
    "status_2xx",
    "status_4xx",
    "status_5xx",
    "status_other",
    "deception_used",
    "session_tainted",
    "user_present",
    "device_present",
    "session_present",
}

NUM_KEYS = {
    "risk_score",
    "behavior_score",
    "drift_score",
    "tone_risk",
    "row_count",
    "byte_size",
}

def _is_boolish(v):
    # allow True/False or 0/1 ints
    if isinstance(v, bool):
        return True
    if isinstance(v, int) and v in (0, 1):
        return True
    return False

def validate_row(obj):
    problems = []

    missing = [k for k in REQUIRED_KEYS if k not in obj]
    if missing:
        problems.append(f"missing_keys:{missing}")

    # types
    for k in BOOLISH_KEYS:
        if k in obj and not _is_boolish(obj[k]):
            problems.append(f"bad_type:{k}={type(obj[k]).__name__}")

    for k in NUM_KEYS:
        if k in obj and not isinstance(obj[k], (int, float)):
            problems.append(f"bad_type:{k}={type(obj[k]).__name__}")

    if "ts_utc" in obj and not isinstance(obj["ts_utc"], str):
        problems.append(f"bad_type:ts_utc={type(obj['ts_utc']).__name__}")

    if "tenant_id" in obj and not isinstance(obj["tenant_id"], str):
        problems.append(f"bad_type:tenant_id={type(obj['tenant_id']).__name__}")

    if "risk_level" in obj and not isinstance(obj["risk_level"], str):
        problems.append(f"bad_type:risk_level={type(obj['risk_level']).__name__}")

    if "behavior_level" in obj and not isinstance(obj["behavior_level"], str):
        problems.append(f"bad_type:behavior_level={type(obj['behavior_level']).__name__}")

    if "label_action" in obj and not isinstance(obj["label_action"], str):
        problems.append(f"bad_type:label_action={type(obj['label_action']).__name__}")

    if "label_outcome" in obj and not isinstance(obj["label_outcome"], str):
        problems.append(f"bad_type:label_outcome={type(obj['label_outcome']).__name__}")

    return problems

def iter_jsonl_rows(path):
    with open(path, "r", encoding="utf-8") as f:
        for i, line in enumerate(f, start=1):
            line = line.strip()
            if not line:
                continue
            yield i, json.loads(line)

def main():
    if len(sys.argv) < 2:
        print("Usage: python -m sidecar.ml.validate_policy_jsonl <path_to_jsonl>")
        sys.exit(2)

    path = sys.argv[1]
    ok = 0
    bad = 0
    total = 0

    for line_no, obj in iter_jsonl_rows(path):
        total += 1
        probs = validate_row(obj)
        if probs:
            bad += 1
            print(f"[BAD] line={line_no} problems={probs}")
        else:
            ok += 1

    print(f"Done. ok={ok} bad={bad} total={total}")
    sys.exit(0 if bad == 0 else 1)

if __name__ == "__main__":
    main()
