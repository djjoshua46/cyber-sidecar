from sqlalchemy.orm import Session
from .config import TENANT_ID
from .policy import get_policy_for_tenant
from .commander_runtime import compute_current_posture


def get_effective_policy(db: Session):
    """
    Returns a policy object, but with mode/thresholds adjusted
    based on current Commander posture.
    """
    base_policy = get_policy_for_tenant(db, TENANT_ID)
    posture = compute_current_posture(db, TENANT_ID)

    level = posture["overall"]["level"]

    # Copy so we don't mutate DB-backed object in weird ways
    policy = base_policy

    if level == "low":
        # normal mode
        policy.mode = "normal"
        policy.high_threshold = max(80, policy.high_threshold)
        policy.medium_threshold = max(40, policy.medium_threshold)
    elif level == "medium":
        # earlier medium/high kicks in
        policy.mode = "tightened"
        policy.high_threshold = min(70, policy.high_threshold)
        policy.medium_threshold = min(30, policy.medium_threshold)
    elif level == "high":
        # very paranoid
        policy.mode = "paranoid"
        policy.high_threshold = min(50, policy.high_threshold)
        policy.medium_threshold = min(20, policy.medium_threshold)

    return policy
