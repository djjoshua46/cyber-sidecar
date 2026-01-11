from __future__ import annotations

from typing import NamedTuple, Optional


class DeceptionDecision(NamedTuple):
    used: bool
    body_bytes: bytes
    content_type: str
    reason: Optional[str]


def _make_honey_csv(original_body: bytes) -> bytes:
    """
    Very simple honey CSV: keep header if present, fill rows with decoy values.
    """
    try:
        text = original_body.decode("utf-8", errors="replace")
    except Exception:
        # Minimal fallback
        header = "id,name,email\n"
        rows = [
            "1,Decoy User,decoy@example.com",
            "2,Fake Person,fake@example.com",
            "3,Test Account,test@example.com",
        ]
        return (header + "\n".join(rows) + "\n").encode("utf-8")

    lines = text.splitlines()
    if not lines:
        header = "id,name,email\n"
        lines = [header.strip()]

    header = lines[0]
    fake_rows = [
        "1001,Decoy User A,decoy-a@example.com",
        "1002,Decoy User B,decoy-b@example.com",
        "1003,Decoy User C,decoy-c@example.com",
        "1004,Decoy User D,decoy-d@example.com",
    ]
    body = header + "\n" + "\n".join(fake_rows) + "\n"
    return body.encode("utf-8")


def maybe_apply_deception(
    *,
    risk_score: float,
    risk_level: str,
    policy_mode: str,
    original_body: bytes,
    content_type: str,
    resource: Optional[str],
    user_id: Optional[str],
) -> DeceptionDecision:
    """
    Decide whether to serve a decoy export instead of blocking.

    For now:
      - only for high risk
      - only when policy_mode == 'block_high'
      - only on CSV-like responses or 'export' resources
    """
    lowered_ct = (content_type or "").lower()
    lowered_res = (resource or "").lower()

    if risk_level != "high":
        return DeceptionDecision(False, original_body, content_type, None)

    if policy_mode != "block_high":
        return DeceptionDecision(False, original_body, content_type, None)

    # Only bother for 'export-ish' responses
    if not (
        "text/csv" in lowered_ct
        or "csv" in lowered_res
        or "export" in lowered_res
        or "download" in lowered_res
    ):
        return DeceptionDecision(False, original_body, content_type, None)

    honey = _make_honey_csv(original_body)
    return DeceptionDecision(
        True,
        honey,
        "text/csv",
        f"honey_export_high_risk_user={user_id or 'unknown'}",
    )
