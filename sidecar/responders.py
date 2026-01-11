from typing import Any, Dict, List
import socket

COMMON_PORTS = [22, 80, 443, 445, 1433, 3306, 3389, 5432, 6379, 8080, 9200]

def _tcp_check(host: str, port: int, timeout: float = 0.4) -> bool:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        return s.connect_ex((host, port)) == 0
    except Exception:
        return False
    finally:
        try:
            s.close()
        except Exception:
            pass

def quick_port_exposure(host: str = "127.0.0.1") -> Dict[str, Any]:
    results = {p: _tcp_check(host, p) for p in COMMON_PORTS}
    open_ports = [p for p, ok in results.items() if ok]
    return {"host": host, "open_ports": sorted(open_ports), "raw": results}


class ResponderHub:
    def __init__(self, enable_port_checks: bool = True):
        self.enable_port_checks = enable_port_checks

    def build_actions(
        self,
        ctx: Dict[str, Any],
        feats: Dict[str, Any],
        policy_rec: Dict[str, Any],
        anomaly: Dict[str, Any],
    ) -> Dict[str, Any]:
        actions: List[Dict[str, Any]] = []

        rec = policy_rec["recommended_action"]

        # If anomaly flagged, escalate one step (optional)
        if anomaly.get("is_anomaly") and rec == "allow":
            actions.append({"type": "escalate", "to": "biometric", "reason": "anomaly_spike"})
            rec = "biometric"

        # Respond based on recommended action
        if rec == "biometric":
            actions.append({"type": "require_stepup", "method": "webauthn", "reason": policy_rec["reason"]})
        elif rec == "honeypot":
            actions.append({"type": "serve_deception", "reason": policy_rec["reason"]})
        elif rec == "block":
            actions.append({"type": "block_request", "reason": policy_rec["reason"]})
        else:
            actions.append({"type": "allow", "reason": policy_rec["reason"]})

        # Defensive check: port exposure snapshot
        port_report = None
        if self.enable_port_checks:
            port_report = quick_port_exposure("127.0.0.1")
            # If DB port exposed unexpectedly, recommend escalation
            if 1433 in port_report["open_ports"]:
                actions.append({"type": "alert", "severity": "high", "reason": "mssql_port_1433_open"})

        return {
            "recommended_action": rec,
            "policy_reason": policy_rec["reason"],
            "anomaly": anomaly,
            "actions": actions,
            "port_report": port_report,
        }
