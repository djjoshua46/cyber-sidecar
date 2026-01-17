# sidecar/ml/anomaly_model.py

class AnomalyModel:
    def score(self, feats: dict) -> float:
        """
        Returns anomaly score 0..1
        """
        score = 0.0

        if feats.get("ports_open", 0) > 5:
            score += 0.3

        if feats.get("sql_ok") is False:
            score += 0.4

        if feats.get("combined", 0) > 70:
            score += 0.3

        return min(score, 1.0)
