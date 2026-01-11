from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Optional, Literal

Action = Literal["allow", "reauth_biometric", "deception"]


@dataclass(frozen=True)
class PolicyThresholds:
    biometric_min: float = 50.0       # step-up auth threshold
    deception_min: float = 80.0       # deception/honeypot threshold
    unknown_identity_action: Action = "deception"


@dataclass
class AIDecision:
    action: Action
    confidence: float
    reason: str
    risk_score: float
    risk_level: str
    behavior_score: float
    behavior_level: str
    deception_reason: Optional[str] = None


class PolicyAgent:
    def __init__(self, thresholds: PolicyThresholds | None = None):
        self.t = thresholds or PolicyThresholds()

    def _recommend_impl(self, ctx: Dict[str, Any], feats: Dict[str, Any]) -> Dict[str, Any]:
        anchors_ok = bool(ctx.get("anchors_ok", False))

        risk_score = float(ctx.get("risk_score", 0.0) or 0.0)
        risk_level = (ctx.get("risk_level") or "low").lower()

        behavior_score = float(ctx.get("behavior_score", 0.0) or 0.0)
        behavior_level = (ctx.get("behavior_level") or "low").lower()

        combined = float(feats.get("combined", feats.get("combined_score", 0.0)) or 0.0)

        # run_ai passes behavior_action; proxy used "next_action" earlier
        behavior_action = (ctx.get("behavior_action") or feats.get("behavior_action") or "allow").lower()

        # anomaly is a probability-like number 0..1 (not a bool)
        anomaly = float(feats.get("anomaly", 0.0) or 0.0)

        # 1) Missing identity anchors => deception (enterprise posture)
        if not anchors_ok:
            return {"action": "deception", "confidence": 0.9, "reason": "missing_identity_anchors"}

        # 2) Anomaly override (acts like “ML” gate even before real ML)
        if anomaly >= 0.8:
            return {"action": "deception", "confidence": 0.85, "reason": "anomaly_detected"}
        if anomaly >= 0.6:
            return {"action": "reauth_biometric", "confidence": 0.8, "reason": "anomaly_suspected"}

        # 3) Respect behavior engine escalation if already demanded
        if behavior_action in ("deception", "honeypot"):
            return {"action": "deception", "confidence": 0.85, "reason": "behavior_engine_deception"}
        if behavior_action in ("reauth_biometric", "biometric"):
            return {"action": "reauth_biometric", "confidence": 0.8, "reason": "behavior_engine_biometric"}

        # 4) Combined thresholds
        if combined >= self.t.deception_min:
            return {"action": "deception", "confidence": 0.8, "reason": "combined_score_deception_threshold"}
        if combined >= self.t.biometric_min:
            return {"action": "reauth_biometric", "confidence": 0.75, "reason": "combined_score_biometric_threshold"}

        return {"action": "allow", "confidence": 0.7, "reason": "combined_score_low"}

    # Public API that run_ai can call
    def recommend(self, ctx: Dict[str, Any], feats: Dict[str, Any]) -> Dict[str, Any]:
        return self._recommend_impl(ctx, feats)

    def decide(self, ctx: Dict[str, Any], feats: Dict[str, Any]) -> Dict[str, Any]:
        return self._recommend_impl(ctx, feats)

    def __call__(self, ctx: Dict[str, Any], feats: Dict[str, Any]) -> Dict[str, Any]:
        return self._recommend_impl(ctx, feats)
