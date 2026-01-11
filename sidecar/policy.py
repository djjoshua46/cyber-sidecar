from __future__ import annotations

from typing import Optional

from sqlalchemy.orm import Session

from .models import PolicySettings


def get_policy_for_tenant(db: Session, tenant_id: str) -> PolicySettings:
    """
    Fetch the policy row for a tenant, or create a sane default.

    Modes we can support later:
      - "log_only"          -> never block, only log
      - "block_high_only"   -> block on high-risk exports (future)
      - "block_all_exports" -> block all exports (future)
    """
    # Your ORM model doesn't have a `name` attribute, so we just pick
    # the first policy row for this tenant (if any).
    policy = (
        db.query(PolicySettings)
        .filter(PolicySettings.tenant_id == tenant_id)
        .order_by(PolicySettings.id)  # oldest first
        .first()
    )

    if not policy:
        # Create a simple default policy row.
        policy = PolicySettings(
            tenant_id=tenant_id,
            mode="log_only",
            high_threshold=70,
            medium_threshold=40,
        )
        db.add(policy)
        db.commit()
        db.refresh(policy)

    return policy


def _looks_like_export_url(url: str) -> bool:
    """Cheap helper: does this URL *look* like an export endpoint?"""
    u = url.lower()
    if any(ext for ext in (".csv", ".xlsx", ".xls") if u.endswith(ext)):
        return True
    if "export" in u or "download" in u or "report" in u:
        return True
    return False


def should_block_preflight(
    policy: PolicySettings,
    target_url: str,
    method: Optional[str] = None,
) -> bool:
    """
    Decide if we should block *before* calling the upstream service.

    For now we keep this conservative:
      - log_only           -> never block
      - block_all_exports  -> block anything that looks like an export URL

    Later we can make this smarter and feed in:
      - user risk profile
      - time of day
      - device flags
      - rolling export volume, etc.
    """
    mode = (policy.mode or "").lower()

    if mode == "log_only":
        return False

    if mode == "block_all_exports" and _looks_like_export_url(target_url):
        return True

    # "block_high_only" and other modes can be implemented later,
    # once we have a pre-computed risk score on the session/user.
    return False
