import time
from typing import Callable, Dict, Any

from .features import compute_features
from .policy_agent import PolicyAgent
from .anomaly_model import AnomalyModel
from .responders import ResponderHub

def run_ai_loop(
    get_latest_context: Callable[[], Dict[str, Any]],
    on_output: Callable[[Dict[str, Any]], None] | None = None,
    interval_s: float = 5.0,
):
    """
    get_latest_context(): returns a ctx dict like build_context() output (or similar)
    on_output(output): optional hook to log to DB, print, send to UI, etc.
    """
    policy = PolicyAgent()
    anomaly_model = AnomalyModel()
    responders = ResponderHub(enable_port_checks=True)

    while True:
        bundle = get_latest_context()

        ctx = bundle["ctx"]
        feats = bundle["feats"]
        policy_rec = bundle["policy_rec"]

        anomaly = anomaly_model.update_and_score(ctx, feats)
        output = responders.build_actions(ctx, feats, policy_rec, anomaly)

        if on_output:
            on_output({"ctx": ctx, "feats": feats, "output": output})
        else:
            print(
                f"[AI] user={ctx.get('user_id')} session={ctx.get('session_id')} "
                f"combined={float(feats.get('combined', 0.0)):.1f} rec={output['recommended_action']} "
                f"anomaly={anomaly.get('is_anomaly')} ports_open={len((output.get('port_report') or {}).get('open_ports', []))}"
            )

        time.sleep(interval_s)
