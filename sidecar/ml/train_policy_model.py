# sidecar/ml/train_policy_model.py
from __future__ import annotations
import glob, json, os, math
from typing import Any, Dict, List

TRAIN_DIR = os.getenv("SIDECAR_TRAIN_DIR", os.path.join(os.getcwd(), "training"))
MODEL_PATH = os.getenv("SIDECAR_POLICY_MODEL_PATH", os.path.join(os.getcwd(), "policy_model.joblib"))
# Keys we never want fed into ML (labels, debug, nested metadata)
DROP_KEYS = {
    "label",
    "label_action",
    "label_outcome",
    "label_source",
    "synthetic",
    "schema_version",

    # raw decision/debug fields
    "status_effective",
    "decision_action",
    "debug_action",
    "debug_action_raw",
    "debug_emitter",
    "debug_status_code_outer",
    "debug_status_code_inner",
    "debug_status_code_effective",
    "debug_deception_used",

    # nested objects that should never reach DictVectorizer
    "reason_detail",
    "reason_codes",

    # headers / trace metadata
    "trace_id",
    "export_id",
    "headers",

    # timestamps
    "ts",

    # post-decision / post-response derived (do NOT train policy on these)
    "status_2xx", "status_4xx", "status_5xx", "status_other",
    "byte_size", "row_count",
    "big_bytes", "huge_bytes", "big_rows", "action_raw",
    "status_code_effective", "status_code_outer", "status_code_inner",

}

DROP_PREFIXES = ("debug_",)  # drop any debug_* field automatically

def load_rows():
    rows = []
    patterns = [
        os.path.join(TRAIN_DIR, "policy_training_*.jsonl"),
        os.path.join(TRAIN_DIR, "policy_training_v2_*.jsonl"),
    ]
    paths = []
    for pat in patterns:
        paths.extend(glob.glob(pat))

    for path in sorted(set(paths)):
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    rows.append(json.loads(line))
                except Exception:
                    continue
    return rows


def _sanitize_row(o: dict) -> dict:
    feats = {}

    for k, v in o.items():
        # Drop hard leakers by name
        if k in DROP_KEYS:
            continue

        # Drop any debug_* fields (covers future ones too)
        if any(k.startswith(p) for p in DROP_PREFIXES):
            continue

        # Drop nested stuff (DictVectorizer can't take dict/list here anyway)
        if isinstance(v, (dict, list)):
            continue

        # Drop Nones
        if v is None:
            continue

        # Drop NaN/Inf
        if isinstance(v, float) and (not math.isfinite(v)):
            continue

        feats[k] = v

    return feats


def train() -> None:
    rows = load_rows()
    if len(rows) < 200:
        raise SystemExit(f"Not enough training rows yet: {len(rows)} (need ~200+)")

    # label is what we actually enforced
    y = [r["label_action"] for r in rows]

    # Build features then sanitize (drops nested dict/list like reason_detail)
    X = [
        _sanitize_row({k: v for k, v in r.items() if k not in ("label_action", "label_outcome")})
        for r in rows
    ]

    from sklearn.feature_extraction import DictVectorizer
    from sklearn.linear_model import LogisticRegression
    from sklearn.pipeline import Pipeline
    from sklearn.preprocessing import MaxAbsScaler
    import joblib

    clf = Pipeline([
        ("vec", DictVectorizer(sparse=True)),
        ("scale", MaxAbsScaler()),  # huge help for sparse + mixed-scale numeric
        ("lr", LogisticRegression(
            solver="saga",
            max_iter=20000,
            tol=1e-3,       # slightly looser tolerance helps stop appropriately
            n_jobs=-1,
            random_state=42,
        )),
    ])

    clf.fit(X, y)
    joblib.dump(clf, MODEL_PATH)
    print(f"Saved model -> {MODEL_PATH}")

if __name__ == "__main__":
    train()
