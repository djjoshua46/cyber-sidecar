# sidecar/routes/tone.py
from fastapi import APIRouter, Depends, HTTPException, status

from ..deps import get_db, get_request_context, RequestContext
from ..tone_engine import issue_tone
from sqlalchemy.orm import Session

router = APIRouter(prefix="/admin/tone", tags=["tone"])

@router.post("/issue")
async def issue_tone_for_session(
    ctx: RequestContext = Depends(get_request_context),
    db: Session = Depends(get_db),
):
    """
    Issue a fresh tone for the current (user, session, device).
    This is what the client agent/mobile app will call.
    """
    if not ctx.user_id or not ctx.session_id or not ctx.device_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Missing x-user-id, x-session-id, or x-device-id headers",
        )

    tone = issue_tone(
        db,
        session_id=ctx.session_id,
        user_id=ctx.user_id,
        device_id=ctx.device_id,
    )
    return {
        "tone": tone,
        "session_id": ctx.session_id,
        "expires_in_seconds": 180,  # matches TONE_LIFETIME_SECONDS
    }
