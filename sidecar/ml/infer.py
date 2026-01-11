# sidecar/ml/infer.py
from __future__ import annotations
import os
from pathlib import Path
from typing import Any, Dict, Optional

# Trained model path (joblib pipeline from train_policy_model.py)
JOBLIB_PATH = Path(os.getenv("SIDECAR_POLICY_MODEL_PATH", "policy_model.joblib"))

# Backwards-compatible fallback params (only used if no joblib yet)
DEFAULTS = {
    # "biometric_threshold": 0.70,
    # "deception_threshold": 0.85,
    "biometric_threshold": 9999,
    "deception_threshold": 9999,
}

_MODEL: Optional[Any] = None
_MODEL_KIND: str = "v1_threshold"

def _load_joblib_if_present() -> None:
    global _MODEL, _MODEL_KIND
    if _MODEL is not None:
        return
    if JOBLIB_PATH.exists():
        import joblib
        _MODEL = joblib.load(str(JOBLIB_PATH))
        _MODEL_KIND = "v1_joblib_lr"
    else:
        _MODEL = None
        _MODEL_KIND = "v1_threshold"

def _fallback_predict(features: Dict[str, Any]) -> Dict[str, Any]:
    # Fallback uses only stable numeric signals that exist in policy features.
    # (These keys come from build_policy_features.)
    behavior = float(features.get("behavior_score", 0.0))
    drift = float(features.get("drift_score", 0.0))
    tone = float(features.get("tone_risk", 0.0))
    tainted = int(features.get("session_tainted", 0))

    # Map to [0..1] approximate risk
    risk = 0.0
    risk += min(0.50, 0.01 * behavior)
    risk += min(0.30, 0.02 * drift)
    risk += min(0.30, 1.00 * tone)
    risk += 0.40 if tainted else 0.0
    risk += 0.15 if int(features.get("huge_bytes", 0)) else 0.0
    risk = max(0.0, min(1.0, risk))

    if risk >= DEFAULTS["deception_threshold"]:
        return {"ml_action": "honeypot", "ml_risk": risk, "model": _MODEL_KIND}
    if risk >= DEFAULTS["biometric_threshold"]:
        return {"ml_action": "reauth_biometric", "ml_risk": risk, "model": _MODEL_KIND}
    return {"ml_action": "allow", "ml_risk": risk, "model": _MODEL_KIND}

def infer(features: Dict[str, Any]) -> Dict[str, Any]:
    _load_joblib_if_present()

    if _MODEL is None:
        return _fallback_predict(features)

    # joblib model is a sklearn Pipeline([DictVectorizer, LogisticRegression])
    # It supports predict_proba + classes_
    try:
        proba = _MODEL.predict_proba([features])[0]
        classes = list(getattr(_MODEL, "classes_", []))
        best_i = int(max(range(len(proba)), key=lambda i: proba[i]))
        best_action = str(classes[best_i]) if best_i < len(classes) else "allow"
        best_p = float(proba[best_i])
        # interpret as “confidence of chosen action”; risk is 1 - allow_conf if allow exists
        allow_p = float(proba[classes.index("allow")]) if "allow" in classes else 0.0
        ml_risk = max(0.0, min(1.0, 1.0 - allow_p))
        return {
            "ml_action": best_action,
            "ml_risk": ml_risk,
            "ml_confidence": best_p,
            "model": _MODEL_KIND,
        }
    except Exception:
        # Never break runtime decisions because ML exploded
        return _fallback_predict(features)
