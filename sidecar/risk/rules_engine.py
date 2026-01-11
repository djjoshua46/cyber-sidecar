from .models import RiskInput, RiskDecision

def evaluate(input: RiskInput) -> RiskDecision:
    score = 0.0

    # Identity trust
    if input.identity and input.identity.is_verified:
        score += 0.3

    # Device trust
    score += 0.3 * input.device_trust

    # IP / Geo
    if input.ip_reputation == "bad":
        score += 0.5
    elif input.ip_reputation == "unknown":
        score += 0.2

    # Action sensitivity
    if input.action == "READ":
        score += 0.0
    elif input.action == "WRITE":
        score += 0.2
    elif input.action == "ADMIN":
        score += 0.5

    if score < 0.4:
        action = "ALLOW"
    elif score < 0.7:
        action = "STEP_UP"
    elif score < 0.9:
        action = "DECEIVE"
    else:
        action = "BLOCK"

    return RiskDecision(score=score, action=action)
