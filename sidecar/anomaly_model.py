from collections import defaultdict, deque
from typing import Any, Deque, Dict, Tuple

class AnomalyModel:
    """
    Lightweight anomaly detector:
      - tracks rolling average of combined_score per user_id
      - flags anomaly if current score is far above recent baseline
    """

    def __init__(self, window: int = 25, spike_delta: float = 25.0):
        self.window = window
        self.spike_delta = spike_delta
        self._hist: Dict[str, Deque[float]] = defaultdict(lambda: deque(maxlen=self.window))

    def update_and_score(self, ctx: Dict[str, Any], feats: Dict[str, Any]) -> Dict[str, Any]:
        user_id = str(ctx.get("user_id", "anonymous"))
        score = float(feats.get("combined_score", 0.0))

        hist = self._hist[user_id]
        baseline = sum(hist) / len(hist) if hist else score
        hist.append(score)

        delta = score - baseline
        is_anomaly = delta >= self.spike_delta

        # return a normalized anomaly score 0..100-ish
        anomaly_score = max(0.0, min(100.0, (delta / max(1.0, self.spike_delta)) * 100.0))

        return {
            "baseline": baseline,
            "delta": delta,
            "anomaly_score": anomaly_score,
            "is_anomaly": is_anomaly,
            "window_n": len(hist),
        }
