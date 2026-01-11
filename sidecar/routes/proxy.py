from __future__ import annotations

import hashlib, asyncio, time, os, json, uuid, httpx, ipaddress, logging
from time import perf_counter
import redis.asyncio as redis
import json as _json

from datetime import datetime, timezone
from typing import Any, Dict, Optional
from uuid import uuid4
from fastapi import APIRouter, Depends, Header, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from starlette.responses import Response
from sqlalchemy.orm import Session
from sqlalchemy import desc, select
from pathlib import Path
from functools import lru_cache
from ..risk_engine import (
    create_risk_finding_for_export,
    evaluate_risk,
    decide_action,
)

from ..config import TENANT_ID
from ..deps import get_db
from ..models import Event, Export, RiskFinding, EphemeralSessionKey
from ..policy import get_policy_for_tenant
from ..tone_engine import issue_tone_redis, validate_tone_redis, log_tone_rotation_sql
from ..ml.features import build_policy_features
from ..ml.infer import infer as ml_infer
from ..ml.export_training import append_training_row
from ..ml.cloud_intent import classify_cloud_intent
from ..ml.cloud_baselines import update_cloud_baselines

from ..geoip import lookup_geo_label
from ..drift_engine import update_and_score_drift
from ..deception_engine import maybe_apply_deception
from ..replay_forensics import log_http_event
from ..policy_runtime import get_effective_policy
from ..services.watermark import apply_watermark_bytes, make_trace_sig, should_watermark
from ..identity.dpop import verify_dpop
from ..security.reauth_proof import verify_reauth_proof
from ..common.customer_profile import switch, reauth_proof_header_name, fail_mode

router = APIRouter(prefix="/proxy", tags=["proxy"])
HTTPX_CLIENT: httpx.AsyncClient | None = None
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
REDIS_TONE_PREFIX = "tone"
redis_client: redis.Redis | None = None
logger = logging.getLogger("sidecar.proxy")
DEBUG_PREFLIGHT = os.getenv("SIDECAR_DEBUG_PREFLIGHT", "0").lower() in ("1", "true", "yes")
SIDECAR_LOADTEST = os.getenv("SIDECAR_LOADTEST", "0").lower() in ("1", "true", "yes")

SIDECAR_BODY_MODE = os.getenv("SIDECAR_BODY_MODE", "preview").lower()  # full | preview | none
SIDECAR_BODY_PREVIEW_BYTES = int(os.getenv("SIDECAR_BODY_PREVIEW_BYTES", "2048"))
SIDECAR_COMMIT_MODE = os.getenv("SIDECAR_COMMIT_MODE", "immediate").lower()
SIDECAR_BEACON_AUTO_ARM = os.getenv("SIDECAR_BEACON_AUTO_ARM", "0").lower() in ("1","true","yes")
SIDECAR_BEACON_TTL_DAYS_DEFAULT = int(os.getenv("SIDECAR_BEACON_TTL_DAYS_DEFAULT", "365"))

# -------------------------
# Upstream request settings
# (module-level so app startup can import them)
# -------------------------
UPSTREAM_TIMEOUT_SECONDS = float(os.getenv("UPSTREAM_TIMEOUT_SECONDS", "3"))
UPSTREAM_RETRY_BUDGET_SECONDS = float(os.getenv("UPSTREAM_RETRY_BUDGET_SECONDS", "5"))
UPSTREAM_MAX_ATTEMPTS = int(os.getenv("UPSTREAM_MAX_ATTEMPTS", "4"))
UPSTREAM_RETRY_AFTER_SECONDS = int(os.getenv("UPSTREAM_RETRY_AFTER_SECONDS", "5"))
UPSTREAM_CLIENT_CERT = os.getenv("UPSTREAM_CLIENT_CERT")  # path to .pem
UPSTREAM_CLIENT_KEY  = os.getenv("UPSTREAM_CLIENT_KEY")   # path to .pem

cert = None
if UPSTREAM_CLIENT_CERT and UPSTREAM_CLIENT_KEY:
    cert = (UPSTREAM_CLIENT_CERT, UPSTREAM_CLIENT_KEY)

client = httpx.AsyncClient(
    verify=True,
    cert=cert,
    timeout=UPSTREAM_TIMEOUT_SECONDS,  # or httpx.Timeout(UPSTREAM_TIMEOUT_SECONDS)
)


def _policy_train_emit(
    *,
    effective_tenant_id: str,
    x_user_id: str,
    x_session_id: str,
    x_device_id: str,
    target_url: str,
    method: str,
    client_ip: str,
    user_agent: str,
    status_code_effective: int,
    status_code_outer: int | None = None,
    status_code_inner: int | None = None,
    action_raw: str | None = None,
    deception_used: bool = False,
    session_tainted: bool = False,
    behavior_score: float = 0.0,
    drift_score: float = 0.0,
    tone_risk: float = 0.0,
    byte_size: int = 0,
    row_count: int = 0,
    decision_action: str = "",
    reason_codes=None,
    reason_detail=None,
    tone_present: int = 0,
    tone_state: str = "ok",
    identity_level: int = 0,
    risk_score: float = 0.0,
    risk_level: str = "low",
    path_class: str = "other",

):
    try:
        import os, time
        if os.environ.get("SIDECAR_DEBUG_TRAINING", "0") == "1":
            print("[TRAINING] _policy_train_emit called", time.time(), "cwd=", os.getcwd())
            print("[TRAINING] args decision_action=", repr(decision_action), "type=", type(decision_action).__name__)
            print("[TRAINING] args reason_codes=", repr(reason_codes), "type=", type(reason_codes).__name__)
            print("[TRAINING] args reason_detail=", repr(reason_detail), "type=", type(reason_detail).__name__)

        feats = build_policy_features(
            tenant_id=str(effective_tenant_id or ""),
            user_id=str(x_user_id or ""),
            session_id=str(x_session_id or ""),
            device_id=str(x_device_id or ""),
            client_ip=str(client_ip or ""),
            user_agent=str(user_agent or ""),
            method=str(method or ""),
            target_url=str(target_url or ""),
            status_code=int(status_code_inner or 0),
            byte_size=int(byte_size or 0),
            row_count=int(row_count or 0),
            behavior_score=float(behavior_score or 0.0),
            drift_score=float(drift_score or 0.0),
            tone_risk=float(tone_risk or 0.0),
            deception_used=False,
            session_tainted=False,
        )

        row = dict(feats)

        cloud = classify_cloud_intent(target_url=str(target_url or ""), method=str(method or ""), user_agent=str(user_agent or ""))
        row.update(cloud)

        # Pre-decision-ish scalar signals (trainable)
        row["tone_present"] = int(tone_present or 0)
        row["tone_state"] = str(tone_state or "ok")
        row["identity_level"] = int(identity_level or 0)
        row["risk_score"] = float(risk_score or 0.0)
        row["risk_level"] = str(risk_level or "low")
        row["path_class"] = str(path_class or "other")

        # Debug fields
        row["debug_action_raw"] = (str(action_raw) if action_raw is not None else None)
        row["debug_deception_used"] = bool(deception_used)
        row["debug_status_code_outer"] = (int(status_code_outer) if status_code_outer is not None else None)
        row["debug_status_code_inner"] = (int(status_code_inner) if status_code_inner is not None else None)
        row["debug_status_code_effective"] = int(status_code_effective or 0)

        # Labels
        a = (str(action_raw or "")).strip().lower()
        sc = int(status_code_effective or 0)

        label_action = "allow"
        if a in ("block",):
            label_action = "block"
        elif a in ("honeypot", "deception"):
            label_action = "honeypot"
        elif a in ("biometric", "reauth_biometric"):
            label_action = "reauth_biometric"

        if bool(deception_used):
            label_action = "honeypot"

        if sc == 401:
            label_action = "reauth_biometric"
        elif sc in (403, 429):
            label_action = "block"
        elif sc == 409:
            label_action = "honeypot"

        row["label_action"] = label_action

        if label_action == "honeypot":
            row["label_outcome"] = "blocked"
        elif 200 <= sc < 300:
            row["label_outcome"] = "allowed"
        elif sc in (401, 403, 429):
            row["label_outcome"] = "blocked"
        elif 400 <= sc < 500:
            row["label_outcome"] = "denied"
        elif sc >= 500:
            row["label_outcome"] = "error"
        else:
            row["label_outcome"] = "other"

        # ✅ policy_v2 schema + supervised reasoning fields
        row["schema_version"] = "policy_v2"
        row["debug_emitter"] = "unified_v2"

        da = decision_action
        if da in (None, "", "None", "null", "NULL"):
            da = row.get("label_action") or ""
        row["decision_action"] = str(da)
        row["reason_codes"] = (reason_codes if isinstance(reason_codes, list) else [])
        row["reason_detail"] = (reason_detail if isinstance(reason_detail, dict) else {})
        row["label_source"] = row.get("label_source") or "policy"
        row["synthetic"] = os.getenv("SIDECAR_LOADTEST", "0").lower() in ("1", "true", "yes")

        _policy_train_emit_row(row)

    except Exception as e:
        import traceback, os
        if os.environ.get("SIDECAR_DEBUG_TRAINING", "0") == "1":
            print("TRAINING_EMIT_ERROR:", repr(e))
            traceback.print_exc()



async def _emit_and_return(
    *,
    status_code: int,
    content: dict,
    effective_tenant_id: str,
    x_user_id: str,
    x_session_id: str,
    x_device_id: str,
    target_url: str,
    method: str,
    client_ip: str,
    user_agent: str,
    action: str,
    behavior_risk: dict | None = None,
    drift_score: float = 0.0,
    tone_risk: float = 0.0,
    deception_used: bool = False,
    session_tainted: bool = False,
    risk_score: float = 0.0,
    risk_level: str = "low",
    row_count: int = 0,
    byte_size: int = 0,
):
    # --- unwrap inner status if present ---
    inner_sc = None
    next_action = None
    if isinstance(content, dict):
        inner_sc = content.get("status_code", None)
        next_action = content.get("next_action", None)

    # --- compute EFFECTIVE status for training ---
    # IMPORTANT: effective status is SIDE-CAR enforcement, not upstream 404s.
    # effective_sc = 200  # default "allowed by policy"
    # a = (str(action or "")).strip().lower()

    # # If the response is explicitly telling the client what happened, use that.
    # na = (str(next_action or "")).strip().lower()
    # # -------------------------
    # # DEBUG OVERRIDE (TEMP)
    # # -------------------------
    # force = os.getenv("SIDECAR_FORCE_ACTION")
    # if force:
    #     f = force.lower()
    #     if f == "honeypot":
    #         effective_sc = 409
    #         deception_used = True
    #     elif f == "block":
    #         effective_sc = 403
    #     elif f == "reauth":
    #         effective_sc = 401

    # if na in ("deception", "honeypot"):
    #     effective_sc = 409
    #     deception_used = True
    # elif na in ("block", "deny"):
    #     # choose one of these depending on how you represent block
    #     effective_sc = 403
    # elif na in ("reauth_biometric", "reauth", "biometric"):
    #     effective_sc = 401
    # else:
    #     # if action says enforcement, respect it
    #     if a in ("honeypot", "deception"):
    #         effective_sc = 409
    #         deception_used = True
    #     elif a in ("block",):
    #         effective_sc = 403
    #     elif a in ("reauth_biometric", "biometric"):
    #         effective_sc = 401
    #     else:
    #         # otherwise: treat as allowed-by-policy even if upstream is 404
    #         effective_sc = 200

    # --- compute EFFECTIVE status for training ---
    # effective status is SIDE-CAR enforcement, not upstream 404s.
    effective_sc = 200  # default "allowed by policy"
    a = (str(action or "")).strip().lower()
    na = (str(next_action or "")).strip().lower()

    # --- FORCE ACTION (debug/testing) ---
    # This must be evaluated at request time (not import time),
    # so changing the env var immediately affects behavior.
    force = os.getenv("SIDECAR_FORCE_ACTION", "").strip().lower()

    if force in ("honeypot", "deception"):
        na = "deception"
        a = "honeypot"
        deception_used = True
        # Make the inner response reflect the enforcement too
        if isinstance(content, dict):
            content["next_action"] = "deception"
            content["status_code"] = 409

    elif force in ("block",):
        na = "block"
        a = "block"
        deception_used = False
        if isinstance(content, dict):
            content["next_action"] = "block"
            content["status_code"] = 403

    elif force in ("reauth", "biometric", "reauth_biometric"):
        na = "reauth_biometric"
        a = "reauth_biometric"
        deception_used = False
        if isinstance(content, dict):
            content["next_action"] = "reauth_biometric"
            content["status_code"] = 401

    # If the response explicitly tells the client what happened, trust that first.
    if na in ("deception", "honeypot"):
        effective_sc = 409
        deception_used = True
    elif na in ("block", "deny"):
        effective_sc = 403
    elif na in ("reauth_biometric", "reauth", "biometric", "retry_with_tone", "tone_required", "tone_invalid"):
        effective_sc = 401
    else:
        # Otherwise fall back to the chosen action (sidecar decision)
        if a in ("honeypot", "deception"):
            effective_sc = 409
            deception_used = True
        elif a in ("block",):
            effective_sc = 403
        elif a in ("reauth_biometric", "biometric"):
            effective_sc = 401
        else:
            effective_sc = 200

    # --- FORCE OVERRIDE (debug/testing) ---
    # Allows k6 / local tests to force a label regardless of upstream response.
    forced = (os.getenv("SIDECAR_FORCE_ACTION") or "").strip().lower()
    if forced:
        if forced in ("honeypot", "deception"):
            action = "honeypot"
            deception_used = True
            effective_sc = 409
            if isinstance(content, dict):
                # Make inner semantics consistent for training/debug
                content.setdefault("status_code", 409)
                content["next_action"] = "deception"
        elif forced in ("block",):
            action = "block"
            deception_used = False
            effective_sc = 403
            if isinstance(content, dict):
                content.setdefault("status_code", 403)
                content["next_action"] = "block"
        elif forced in ("reauth", "reauth_biometric", "biometric"):
            action = "reauth_biometric"
            deception_used = False
            effective_sc = 401
            if isinstance(content, dict):
                content.setdefault("status_code", 401)
                content["next_action"] = "reauth_biometric"

    # -----------------------------
    # decision + reasons (ALWAYS)
    # -----------------------------
    def _derive_decision_and_reasons(
        *,
        effective_sc: int,
        action: str,
        deception_used: bool,
        content: object,
        risk_level: str,
        risk_score: float,
        behavior_risk: object,
    ):
        action_l = (action or "").strip().lower()

        err_l = ""
        na_l = ""
        tone_reason = None

        if isinstance(content, dict):
            err_l = str(content.get("error") or "").strip().lower()
            na_l = str(content.get("next_action") or "").strip().lower()
            tone_reason = content.get("tone_reason")

        # Stable “decision_action” classes for ML
        decision_action = "allow"
        if deception_used or effective_sc == 409 or action_l in ("honeypot", "deception"):
            decision_action = "honeypot"
        elif effective_sc in (401,):
            decision_action = "reauth"
        elif effective_sc >= 400:
            decision_action = "block"

        # Reason codes (multi-label)
        reason_codes = []

        # Identity / tone gates
        if err_l == "identity_required":
            reason_codes.append("identity_required")
        if err_l in ("tone_required", "tone_invalid"):
            reason_codes.append(err_l)

        # Policy action signals
        if na_l in ("block", "deny"):
            reason_codes.append("policy_block")
        if na_l in ("deception", "honeypot"):
            reason_codes.append("policy_honeypot")
        if na_l in ("retry_with_tone", "reauth", "reauth_biometric", "biometric"):
            reason_codes.append("policy_reauth")

        # Fall back to the coarse decision if nothing else triggered
        if not reason_codes:
            reason_codes.append(f"decision_{decision_action}")

        behavior_score = 0.0
        behavior_level = None
        if isinstance(behavior_risk, dict):
            behavior_score = float(behavior_risk.get("score") or 0.0)
            behavior_level = behavior_risk.get("level")

        reason_detail = {
            "error": err_l or None,
            "next_action": na_l or None,
            "decision_action": decision_action,
            "effective_status": int(effective_sc),
            "risk_level": str(risk_level or "low"),
            "risk_score": float(risk_score or 0.0),
            "behavior_level": behavior_level,
            "behavior_score": float(behavior_score),
            "tone_reason": tone_reason,
            "action_raw": action_l or None,
        }

        return decision_action, reason_codes, reason_detail


    decision_action, reason_codes, reason_detail = _derive_decision_and_reasons(
        effective_sc=int(effective_sc or 0),
        action=str(action or ""),
        deception_used=bool(deception_used),
        content=content,
        risk_level=str(risk_level or "low"),
        risk_score=float(risk_score or 0.0),
        behavior_risk=behavior_risk,
    )

    # -----------------------------
    # pre-decision-ish feature signals (top-level scalars)
    # -----------------------------
    err_l = ""
    na_l = ""
    if isinstance(content, dict):
        err_l = str(content.get("error") or "").strip().lower()
        na_l = str(content.get("next_action") or "").strip().lower()

    # Tone signals (derived from gate outcome; still useful + not label leakage fields)
    tone_present = 1
    tone_state = "ok"
    if err_l == "tone_required":
        tone_present = 0
        tone_state = "missing"
    elif err_l == "tone_invalid":
        tone_present = 1
        tone_state = "invalid"

    # Identity level (based on which ids are present)
    identity_level = 0
    if x_user_id: identity_level = max(identity_level, 1)
    if x_session_id: identity_level = max(identity_level, 2)
    if x_device_id: identity_level = max(identity_level, 3)

    # Path class (small stable taxonomy)
    lowered = (target_url or "").lower()
    if "/export/small" in lowered:
        path_class = "export_small"
    elif "/export/medium" in lowered:
        path_class = "export_medium"
    elif "/auth/tone/refresh" in lowered:
        path_class = "auth_refresh"
    elif "/proxy/" in lowered:
        path_class = "proxy_http"
    else:
        path_class = "other"

    # -----------------------------
    # emit training row (never break request)
    # -----------------------------
    try:
        _policy_train_emit(
            effective_tenant_id=str(effective_tenant_id or ""),
            x_user_id=str(x_user_id or ""),
            x_session_id=str(x_session_id or ""),
            x_device_id=str(x_device_id or ""),
            target_url=str(target_url or ""),
            method=str(method or ""),
            client_ip=str(client_ip or ""),
            user_agent=str(user_agent or ""),
            status_code_effective=int(effective_sc or 0),
            status_code_outer=int(status_code or 0),
            status_code_inner=(int(inner_sc) if inner_sc is not None else None),
            action_raw=str(action or ""),
            deception_used=bool(deception_used),
            session_tainted=bool(session_tainted),
            behavior_score=float(behavior_risk.get("score", 0.0) if isinstance(behavior_risk, dict) else 0.0),
            drift_score=float(drift_score or 0.0),
            tone_risk=float(tone_risk or 0.0),
            byte_size=int(byte_size or 0),
            row_count=int(row_count or 0),
            tone_present=int(tone_present),
            tone_state=str(tone_state),
            identity_level=int(identity_level),
            risk_score=float(risk_score or 0.0),
            risk_level=str(risk_level or "low"),
            path_class=str(path_class),

            # NEW: supervised reasoning fields
            decision_action=decision_action,
            reason_codes=reason_codes,
            reason_detail=reason_detail,
        )
    except Exception:
        pass

    # -----------------------------
    # always include decision + reasons in LIVE response
    # -----------------------------
    if isinstance(content, dict):
        content["decision_action"] = decision_action
        content["reason_codes"] = reason_codes
        content["reason_detail"] = reason_detail
    else:
        # if your response body isn't a dict, still return something stable
        content = {
            "decision_action": decision_action,
            "reason_codes": reason_codes,
            "reason_detail": reason_detail,
        }

    try:
        # stamp effective status in the live response too (helps k6/debug)
        if isinstance(content, dict):
            content.setdefault("status_code_effective", int(effective_sc or 0))
            content.setdefault("status_code_outer", int(status_code or 0))
            if inner_sc is not None:
                content.setdefault("status_code_inner", int(inner_sc))

        return JSONResponse(status_code=int(status_code or 200), content=content)

    except Exception as e:
        logger.exception("_emit_and_return: failed to build response")
        return JSONResponse(
            status_code=500,
            content={
                "error": "emit_and_return_failed",
                "detail": str(e),
            },
        )

class ProxyRequest(BaseModel):
    # Matches your PowerShell body:
    # {
    #   "target_url": "http://127.0.0.1:8090/customers/export",
    #   "method": "GET",
    #   "headers": {}
    # }
    target_url: str
    method: str = "GET"
    headers: Dict[str, str] = {}
    body: Optional[str] = None  # optional raw body for POST/PUT etc.

_ACTION_RANK = {
    "allow": 0,
    "biometric": 1,
    "reauth_biometric": 1,
    "honeypot": 2,
    "deception": 2,
    "block": 3,
}

TENANT_CONFIG_DIR = os.getenv("SIDECAR_TENANT_CONFIG_DIR", "/app/tenants")

def _header_get_any(headers, names):
    """Return the first non-empty header value for any name in `names`."""
    for n in names or []:
        v = headers.get(n)
        if v is not None and str(v).strip() != "":
            return v
    return None

@lru_cache(maxsize=256)
def load_tenant_config(tenant_id: str) -> dict:
    p = Path(TENANT_CONFIG_DIR) / f"{tenant_id}.json"
    if not p.exists():
        return {}
    return _json.loads(p.read_text(encoding="utf-8"))

def resolve_canonical_identity(request: Request, x_org_id, x_user_id, x_session_id, x_device_id, x_client_ip, user_agent):
    """
    Canonicalize identity fields using:
      1) Our X-* headers (if present)
      2) Tenant header_map fallbacks
    """

    # -------------------------
    # Tenant id first (because it selects the mapping)
    # -------------------------
    tenant_id = (
        x_org_id
        or _header_get_any(
            request.headers,
            ["X-Org-Id", "Org-Id", "OrgId", "Tenant-Id", "TenantId"]
        )
        or ""
    )

    # 🔑 DEV / TEST FALLBACK ONLY (never overwrite a real tenant)
    if not tenant_id:
        if os.getenv("SIDECAR_TEST_MODE", "0").lower() in ("1", "true", "yes") or \
           os.getenv("SIDECAR_LOADTEST", "0").lower() in ("1", "true", "yes"):
            tenant_id = os.getenv("SIDECAR_DEFAULT_TENANT", "default")
        else:
            tenant_id = ""   # production: remain empty (or fail later if you want)

    # -------------------------
    # Load tenant config (AFTER tenant is finalized)
    # -------------------------
    cfg = load_tenant_config(str(tenant_id)) if tenant_id else {}
    hm = (cfg.get("header_map") or {})

    canonical = {
        "tenant_id": tenant_id,
        "user_id": x_user_id or _header_get_any(request.headers, hm.get("user_id")),
        "session_id": x_session_id or _header_get_any(request.headers, hm.get("session_id")),
        "device_id": x_device_id or _header_get_any(request.headers, hm.get("device_id")),
        "user_agent": user_agent or request.headers.get("User-Agent"),
    }

    # -------------------------
    # Client IP handling
    # -------------------------
    effective_ip = get_effective_client_ip(request)

    if effective_ip:
        canonical["client_ip"] = effective_ip
    elif SIDECAR_TEST_MODE:
        canonical["client_ip"] = x_client_ip or _header_get_any(request.headers, hm.get("client_ip"))
    else:
        canonical["client_ip"] = (request.client.host if request.client else "") or ""

    return canonical, cfg


def _more_severe(a: str, b: str) -> str:
    return a if _ACTION_RANK.get(a, 0) >= _ACTION_RANK.get(b, 0) else b

def _lt_enabled() -> bool:
    return os.getenv("SIDECAR_LOADTEST", "0") in ("1", "true", "yes")

def _lt_trace_enabled() -> bool:
    return os.getenv("SIDECAR_TRACE_TIMING", "0") in ("1", "true", "yes")

class _Timer:
    def __init__(self):
        self.marks = {}
        self.t0 = time.perf_counter()

    def mark(self, name: str):
        self.marks[name] = time.perf_counter()

    def ms_since(self, a: str, b: str) -> float:
        return (self.marks[b] - self.marks[a]) * 1000.0

    def ms_total(self) -> float:
        return (time.perf_counter() - self.t0) * 1000.0
    
def _env_true(name: str) -> bool:
    return os.getenv(name, "0").strip().lower() in ("1", "true", "yes", "y", "on")

SIDECAR_TEST_MODE = _env_true("SIDECAR_TEST_MODE")

def maybe_commit(db):
    if SIDECAR_COMMIT_MODE == "immediate":
        db.commit()
    else:
        db.flush()

def _safe_json(value: Any) -> str:
    """Convert arbitrary details into a JSON string, falling back to str()."""
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    try:
        return json.dumps(value, default=str)
    except Exception:
        return str(value)

def require_dpop_for_request(target_url: str) -> bool:
    # MVP: global switch
    if os.getenv("SIDECAR_REQUIRE_DPOP", "0").lower() in ("1", "true", "yes"):
        return True

    # Optional: simple path rule list (comma-separated)
    prefixes = [p.strip() for p in (os.getenv("SIDECAR_DPOP_PATH_PREFIXES", "")).split(",") if p.strip()]
    lowered = (target_url or "").lower()
    return any(lowered.startswith(p.lower()) for p in prefixes)

def _tone_cache_key(tenant_id: str, user_id: str, device_id: str, session_id: str) -> str:
    return f"tone:{tenant_id}:{user_id}:{device_id}:{session_id}"

def _tone_hash(t: str) -> str:
    return hashlib.sha256(t.encode("utf-8")).hexdigest()

def _now_ts() -> int:
    return int(time.time())

def _trusted_proxy_source(remote_ip: str) -> bool:
    # DEV SAFE: only trust XFF when request is coming from local machine
    return remote_ip in ("127.0.0.1", "::1")

def _client_ip_from_request(request) -> str:
    remote_ip = (request.client.host if request.client else "") or ""
    xff = (request.headers.get("x-forwarded-for") or "").strip()

    if xff and _trusted_proxy_source(remote_ip):
        # XFF can be a list: "client, proxy1, proxy2"
        return xff.split(",")[0].strip()

    return remote_ip

def _policy_train_emit_row(row: dict) -> None:
    try:
        from sidecar.ml.export_training import append_training_row
        append_training_row(row)
    except Exception:
        pass


def _parse_first_ip(xff: str | None) -> str | None:
    if not xff:
        return None
    # Take first hop
    first = xff.split(",")[0].strip()
    try:
        ipaddress.ip_address(first)
        return first
    except Exception:
        return None

def get_peer_ip(request) -> str | None:
    return request.client.host if request.client else None

def get_client_ip_trusted(request) -> tuple[str | None, dict]:
    """
    Returns (client_ip, meta).
    - client_ip is the best-effort 'real client' if behind trusted proxies,
      else the peer IP.
    - meta includes what we saw, for forensics.
    """
    peer_ip = get_peer_ip(request)
    xff = request.headers.get("x-forwarded-for") or request.headers.get("X-Forwarded-For")

    trusted = False
    trusted_list = [ip.strip() for ip in os.getenv("SIDECAR_TRUSTED_PROXIES", "127.0.0.1").split(",") if ip.strip()]
    if peer_ip and peer_ip in trusted_list:
        trusted = True

    xff_first = _parse_first_ip(xff) if trusted else None
    client_ip = xff_first or peer_ip

    meta = {
        "peer_ip": peer_ip,
        "xff": xff,
        "xff_used": bool(xff_first),
        "xff_trusted": trusted,
        "trusted_proxies": trusted_list,
    }
    return client_ip, meta

def _ip_prefix(ip: str) -> str:
    """
    Coarse IP grouping to avoid punishing normal DHCP changes.
    IPv4 -> /24, IPv6 -> /56.
    """
    try:
        addr = ipaddress.ip_address(ip)
        if addr.version == 4:
            net = ipaddress.ip_network(f"{ip}/24", strict=False)
        else:
            net = ipaddress.ip_network(f"{ip}/56", strict=False)
        return str(net)
    except Exception:
        return ip or ""
    
TRUST_XFF = os.getenv("SIDECAR_TRUST_XFF", "1") == "1"
TRUSTED_PROXY_CIDRS = [
    c.strip() for c in os.getenv("SIDECAR_TRUSTED_PROXY_CIDRS", "127.0.0.1/32").split(",") if c.strip()
]

def _ip_in_cidrs(ip: str, cidrs: list[str]) -> bool:
    try:
        ip_obj = ipaddress.ip_address(ip)
        for c in cidrs:
            if ip_obj in ipaddress.ip_network(c, strict=False):
                return True
    except Exception:
        return False
    return False

def get_effective_client_ip(request) -> str | None:
    """
    Safe-ish client IP extraction:
    - If TRUST_XFF=1 and the direct peer is trusted, use XFF (leftmost)
    - Else use request.client.host
    """
    peer = request.client.host if request.client else None

    xff = request.headers.get("x-forwarded-for") or request.headers.get("X-Forwarded-For")
    if TRUST_XFF and xff and peer and _ip_in_cidrs(peer, TRUSTED_PROXY_CIDRS):
        return xff.split(",")[0].strip()

    return peer

async def apply_session_and_rate_gates(
    redis_client,
    *,
    tenant_id: str,
    user_id: str,
    session_id: str,
    device_id: str,
    client_ip: str,
    user_agent: str,
    target_url: str,
    behavior_risk: dict,
    behavior_action: str,
    reauth_ok: bool,
) -> tuple[dict, str, bool, dict]:
    """
    Returns: (behavior_risk, behavior_action, session_tainted, debug)

    Gates:
      D1 Session age/idle
      D2 Session binding (device/ip/ua)
      D3 Rate/burst
      D4 Sensitive exports (huge)
      D5 Replay/mutation tainting
      D6 Escalation policy (biometric/honeypot)
    """
    debug: dict = {}
    if not redis_client:
        return behavior_risk, behavior_action, False, {"note": "no_redis"}

    def _rstr(v) -> str:
        if v is None:
            return ""
        if isinstance(v, (bytes, bytearray)):
            return v.decode("utf-8", errors="ignore")
        return str(v)

    lowered = (target_url or "").lower()
    is_huge_export = ("/export/huge" in lowered) or ("/export/large" in lowered)

    # ----- helpers -----
    LEVEL_RANK = {"low": 0, "medium": 1, "high": 2}
    def bump_level(cur: str, desired: str) -> str:
        cur_r = LEVEL_RANK.get((cur or "low"), 0)
        des_r = LEVEL_RANK.get(desired, 0)
        return desired if des_r > cur_r else (cur or "low")

    def bump_score(min_score: float) -> None:
        behavior_risk["score"] = max(float(behavior_risk.get("score", 0.0)), float(min_score))

    def require_biometric(min_level: str = "medium", min_score: float = 60.0) -> None:
        nonlocal behavior_action
        # don't downgrade honeypot
        if behavior_action != "honeypot":
            behavior_action = "biometric"
        behavior_risk["level"] = bump_level(behavior_risk.get("level", "low"), min_level)
        bump_score(min_score)

    def force_honeypot(min_score: float = 85.0) -> None:
        nonlocal behavior_action
        behavior_action = "honeypot"
        behavior_risk["level"] = bump_level(behavior_risk.get("level", "low"), "high")
        bump_score(min_score)

    # ---- Session meta key ----
    sid_key = f"sidmeta:{tenant_id}:{user_id}:{session_id}"
    now = _now_ts()

    created_at = _rstr(await redis_client.hget(sid_key, "created_at"))
    last_seen  = _rstr(await redis_client.hget(sid_key, "last_seen"))
    first_ip   = _rstr(await redis_client.hget(sid_key, "ip"))
    first_ua   = _rstr(await redis_client.hget(sid_key, "ua"))
    first_dev  = _rstr(await redis_client.hget(sid_key, "device"))

    if not created_at:
        await redis_client.hset(
            sid_key,
            mapping={
                "created_at": str(now),
                "last_seen": str(now),
                "ip": client_ip or "",
                "ua": user_agent or "",
                "device": device_id or "",
                "mutations": "0",
                "last_ip_pref": _ip_prefix(client_ip or ""),
                "last_ua": user_agent or "",
                "last_device": device_id or "",
            },
        )
        await redis_client.expire(sid_key, int(os.getenv("SIDMETA_TTL_S", "4800")))  # 80m
        created_at = str(now)
        last_seen = str(now)
        first_ip = client_ip or ""
        first_ua = user_agent or ""
        first_dev = device_id or ""

    # Read rolling "last seen" identity
    last_ip_pref = _rstr(await redis_client.hget(sid_key, "last_ip_pref")) or _ip_prefix(first_ip or "")
    last_ua_seen = _rstr(await redis_client.hget(sid_key, "last_ua")) or (first_ua or "")
    last_dev_seen = _rstr(await redis_client.hget(sid_key, "last_device")) or (first_dev or "")

    # Compute changes
    cur_ip_pref = _ip_prefix(client_ip or "")
    ip_pref_changed = bool(last_ip_pref and cur_ip_pref and last_ip_pref != cur_ip_pref)
    ua_changed = bool(last_ua_seen and user_agent and last_ua_seen != user_agent)
    dev_changed = bool(last_dev_seen and device_id and last_dev_seen != device_id)

    # Mutations counter (single source of truth)
    mut_raw = _rstr(await redis_client.hget(sid_key, "mutations")) or "0"
    try:
        mutations = int(mut_raw)
    except Exception:
        mutations = 0

    # Churn counters per 10-minute bucket (rotating behavior)
    bucket_10m = now // 600
    ip_churn_key = f"ipchurn:{tenant_id}:{user_id}:{session_id}:{bucket_10m}"
    ua_churn_key = f"uachurn:{tenant_id}:{user_id}:{session_id}:{bucket_10m}"

    ip_churn = 0
    ua_churn = 0

    if ip_pref_changed:
        ip_churn = int(await redis_client.incr(ip_churn_key))
        await redis_client.expire(ip_churn_key, 60 * 20)  # ~20 minutes
        mutations += 1

    if ua_changed:
        ua_churn = int(await redis_client.incr(ua_churn_key))
        await redis_client.expire(ua_churn_key, 60 * 20)
        mutations += 1

    if dev_changed:
        mutations += 1

    if (ip_pref_changed or ua_changed or dev_changed):
        await redis_client.hset(sid_key, "mutations", str(mutations))

    # Update rolling identity + last_seen (do this once)
    await redis_client.hset(
        sid_key,
        mapping={
            "last_seen": str(now),
            "last_ip_pref": cur_ip_pref,
            "last_ua": user_agent or "",
            "last_device": device_id or "",
        },
    )

    # ----- classify attacker patterns -----
    max_ip_changes_10m = int(os.getenv("MAX_IP_CHANGES_10M", "2"))   # 2+ per 10m = rotating
    max_ua_changes_10m = int(os.getenv("MAX_UA_CHANGES_10M", "2"))   # 2+ per 10m = rotating

    ip_rotating = ip_churn >= max_ip_changes_10m
    ua_rotating = ua_churn >= max_ua_changes_10m

    # “stolen stable IP”: IP looks stable but UA/device suddenly changes
    stolen_stable_ip = (not ip_pref_changed) and (ua_changed or dev_changed)

    # ---- D5/D6: taint + escalation policy ----
    session_tainted = False

    # Device change mid-session is the strongest signal in your current model
    if dev_changed:
        session_tainted = True

    # Hard upgrade for stolen stable IP (your request)
    if stolen_stable_ip and not reauth_ok:
        if is_huge_export:
            force_honeypot(90.0)
        else:
            require_biometric("high", 85.0)

    # Rotating behavior: allow a little grace, but escalate quickly
    if (ip_rotating or ua_rotating) and not reauth_ok:
        if is_huge_export:
            force_honeypot(85.0)
        else:
            require_biometric("medium", 70.0)

    debug["mutation"] = {
        "ip_pref_changed": ip_pref_changed,
        "ua_changed": ua_changed,
        "dev_changed": dev_changed,
        "mutations": mutations,
        "ip_churn_10m": int(ip_churn),
        "ua_churn_10m": int(ua_churn),
        "ip_rotating": bool(ip_rotating),
        "ua_rotating": bool(ua_rotating),
        "stolen_stable_ip": bool(stolen_stable_ip),
    }

    # ---- D1: session age + idle gates ----
    created_at_i = int(created_at or now)
    last_seen_i = int(last_seen or now)

    session_age_s = now - created_at_i
    idle_s = now - last_seen_i

    max_session_age_s = int(os.getenv("MAX_SESSION_AGE_S", "3600"))
    max_idle_s = int(os.getenv("MAX_SESSION_IDLE_S", "600"))
    debug["session"] = {"age_s": session_age_s, "idle_s": idle_s, "max_age_s": max_session_age_s, "max_idle_s": max_idle_s}

    if (session_age_s > max_session_age_s) or (idle_s > max_idle_s):
        if not reauth_ok:
            require_biometric("medium", 60.0)

    # ---- D3: rate/burst gate (per session) ----
    bucket_10s = now // 10
    rate_key = f"sidrate:{tenant_id}:{user_id}:{session_id}:{bucket_10s}"
    n = int(await redis_client.incr(rate_key))
    await redis_client.expire(rate_key, 30)

    burst_limit = int(os.getenv("SESSION_BURST_10S", "40"))
    debug["rate"] = {"bucket": bucket_10s, "count": n, "limit": burst_limit}

    if n > burst_limit:
        if is_huge_export:
            force_honeypot(85.0)
        else:
            require_biometric("medium", 60.0)

    # ---- D4: sensitive export gates ----
    if is_huge_export:
        if session_tainted:
            force_honeypot(90.0)
        else:
            if not reauth_ok and behavior_action != "honeypot":
                require_biometric("medium", 60.0)

    # ---- Final taint policy ----
    if session_tainted:
        force_honeypot(90.0)

    return behavior_risk, behavior_action, session_tainted, debug


# --- AI Enforcement helpers ---

_ACTION_RANK = {
    "allow": 0,
    "reauth_biometric": 1,
    "deception": 2,
    "honeypot": 2,   # treat honeypot as deception
}

def _normalize_action(a: str | None) -> str:
    a = (a or "allow").lower().strip()
    if a == "honeypot":
        return "deception"
    if a not in _ACTION_RANK:
        return "allow"
    return a

def _is_more_severe(a: str, b: str) -> bool:
    """Return True if a is more severe than b."""
    return _ACTION_RANK[_normalize_action(a)] > _ACTION_RANK[_normalize_action(b)]

def _fetch_latest_ai_action(db, tenant_id: str | None, user_id: str | None, session_id: str | None) -> dict | None:
    """
    Returns latest ai_decision Event details dict or None.
    We key primarily on SessionId; fall back to UserId if needed.
    """
    from ..models import Event
    from sqlalchemy import desc
    import json

    q = db.query(Event).filter(Event.event_type == "ai_decision")

    # TenantId is required in your schema; only filter if we have it
    if tenant_id:
        q = q.filter(Event.tenant_id == tenant_id)

    if session_id:
        q = q.filter(Event.session_id == session_id)
    elif user_id:
        q = q.filter(Event.user_id == user_id)
    else:
        return None

    row = q.order_by(desc(Event.id)).first()
    if not row or not row.details:
        return None
    try:
        return json.loads(row.details)
    except Exception:
        return None

def build_ml_features(
    *,
    tenant_id: str,
    user_id: str,
    device_id: str,
    session_id: str,
    client_ip: str,
    user_agent: str,
    target_url: str,
    method: str,
    gate_debug: dict | None,
    timings: dict | None,
) -> dict:
    est_bytes, est_rows = estimate_export_intent(target_url)

    mutation = (gate_debug or {}).get("mutation", {}) if isinstance(gate_debug, dict) else {}
    session = (gate_debug or {}).get("session", {}) if isinstance(gate_debug, dict) else {}
    rate    = (gate_debug or {}).get("rate", {}) if isinstance(gate_debug, dict) else {}

    t = timings or {}

    return {
        "schema_version": 2,
        "tenant_id": tenant_id,
        "user_id": user_id,
        "device_id": device_id,
        "session_id": session_id,

        "ip_prefix": _ip_prefix(client_ip or ""),
        "ua": (user_agent or "")[:180],

        "method": (method or "GET").upper(),
        "target_url": (target_url or "")[:500],
        "is_export_huge": int("/export/huge" in (target_url or "").lower() or "/export/large" in (target_url or "").lower()),
        "est_bytes": int(est_bytes or 0),
        "est_rows": int(est_rows or 0),

        "ip_pref_changed": int(bool(mutation.get("ip_pref_changed"))),
        "ua_changed": int(bool(mutation.get("ua_changed"))),
        "dev_changed": int(bool(mutation.get("dev_changed"))),
        "mutations": int(mutation.get("mutations") or 0),
        "ip_churn_10m": int(mutation.get("ip_churn_10m") or 0),
        "ua_churn_10m": int(mutation.get("ua_churn_10m") or 0),
        "stolen_stable_ip": int(bool(mutation.get("stolen_stable_ip"))),

        "session_age_s": float(session.get("age_s") or 0),
        "idle_s": float(session.get("idle_s") or 0),

        "burst_10s_count": int(rate.get("count") or 0),
        "burst_10s_limit": int(rate.get("limit") or 0),

        "upstream_ms": float(t.get("upstream_ms") or 0),
        "total_ms": float(t.get("total_ms") or 0),
    }

def estimate_export_intent(target_url: str) -> tuple[int, int]:
    """
    Preflight-only rough estimate. Keep this conservative.
    The real row_count/byte_size is measured AFTER upstream returns.
    """
    u = (target_url or "").lower()

    # These should roughly match adversary_harness upstream generators:
    # small: 5 rows
    # medium: ~800 rows
    # huge: ~5000 rows
    if "huge" in u:
        return (5_000_000, 5_000)     # ~few MB, 5k rows
    if "medium" in u:
        return (500_000, 800)         # ~hundreds KB, 800 rows
    if "small" in u:
        return (10_000, 5)            # tiny, 5 rows

    return (0, 0)

def _get_latest_ai_decision(db, session_id: str) -> dict | None:
    if not session_id:
        return None
    row = (
        db.query(Event)
          .filter(Event.event_type == "ai_decision", Event.session_id == session_id)
          .order_by(desc(Event.id))
          .first()
    )
    if not row or not row.details:
        return None
    try:
        return json.loads(row.details)
    except Exception:
        return None
    
def _log_event(
    db: Session,
    *,
    tenant_id: str,
    user_id: Optional[str],
    device_id: Optional[str],
    session_id: Optional[str],
    source: str,
    event_type: str,
    resource: Optional[str],
    ip: Optional[str],
    geo: Optional[str],
    client_ip: Optional[str] = None,
    user_agent: Optional[str],
    details: Optional[dict] = None,
) -> Event:
    """
    Create an Event row using the SAME attribute names as sidecar.models.Event.
    We know from the /events route that Event expects snake_case attributes:
      tenant_id, user_id, device_id, session_id, source, event_type,
      resource, ip, geo, details.
    We'll put client_ip and user_agent into the details JSON so we don't
    rely on their exact column/attribute names.
    """

    # Merge any extra details + client_ip / user_agent into a single JSON blob
    details_payload: dict = {}
    if isinstance(details, dict):
        details_payload.update(details)

    if client_ip is not None:
        details_payload.setdefault("client_ip", client_ip)
    if user_agent is not None:
        details_payload.setdefault("user_agent", user_agent)
    if client_ip is None and ip is not None:
        client_ip = ip

    details_str = _safe_json(details_payload or None)
    # Build the ORM object with snake_case field names
    evt = Event(
        tenant_id=tenant_id,
        user_id=user_id,
        device_id=device_id,
        session_id=session_id,
        source=source,
        event_type=event_type,
        resource=resource,
        ip=ip,
        geo=geo,
        details=details_str or None,
    )

    # If the ORM model has explicit columns for these, populate them.
    # Your SQL table DOES (ClientIp, UserAgent), so this will stop them being NULL.
    try:
        if hasattr(evt, "client_ip"):
            setattr(evt, "client_ip", client_ip)
        if hasattr(evt, "user_agent"):
            setattr(evt, "user_agent", user_agent)
    except Exception:
        pass

    db.add(evt)

    return evt


def _compute_basic_risk_score(
    *,
    row_count: int,
    byte_size: int,
    status_code: int,
    resource: str,
    user_id: Optional[str],
    session_id: Optional[str],
) -> float:
    """
    VERY SIMPLE placeholder risk scoring.

    This is where the 'fluid monster' gets smarter over time.
    Right now it's:

      - more rows = more risk
      - more bytes = more risk
      - successful export (200) gets a little bump
      - 'export' in path gets a little bump

    We’ll later add:
      - geo / ip distance
      - unusual device for this user
      - unusual time-of-day
      - export frequency baseline, etc.
    """
    score = 0.0

    # Rows: scaled gently
    if row_count > 0:
        score += min(60.0, row_count / 10.0)

    # Bytes: scaled per MB
    if byte_size > 0:
        score += min(30.0, byte_size / (1024 * 1024))

    # HTTP success
    if status_code == 200:
        score += 5.0

    # Export-ish resource name
    lowered = (resource or "").lower()
    if "export" in lowered or "download" in lowered or "csv" in lowered:
        score += 5.0

    return max(0.0, min(score, 100.0))


def _risk_level_from_policy(
    *, score: float, mode: str, high_threshold: int, medium_threshold: int
) -> tuple[str, bool]:
    """
    Map a risk score into (risk_level, should_block).

    mode: e.g. 'block_high' or 'monitor'
    """
    if score >= high_threshold:
        level = "high"
        block = mode == "block_high"
    elif score >= medium_threshold:
        level = "medium"
        # You *could* choose to block medium in some modes later.
        block = False
    else:
        level = "low"
        block = False

    return level, block


@router.post("/http")
async def proxy_http(
    request: Request,
    payload: ProxyRequest,
    db: Session = Depends(get_db),
    x_user_id: Optional[str] = Header(None, alias="X-User-Id"),
    x_session_id: Optional[str] = Header(None, alias="X-Session-Id"),
    x_device_id: Optional[str] = Header(None, alias="X-Device-Id"),
    x_tone: Optional[str] = Header(None, alias="X-Tone"),
    x_reauth_result: Optional[str] = Header(None, alias="X-Reauth-Result"),
    x_org_id: Optional[str] = Header(None, alias="X-Org-Id"),
    x_client_ip: Optional[str] = Header(None, alias="X-Client-Ip"),
) -> JSONResponse:
    """
    Single-path proxy with strict preflight (NO upstream yet):

    Preflight gates:
      A) Trusted upstream gate (optional)
      B) Redis availability gate (optional)
      1) Identity anchors required -> 401 reauth_biometric
      2) Tone required/valid -> 409 reauth_tone (issue/refresh tone)
      3) Optional DPoP -> 401 reauth_dpop
      4) Risk preflight -> allow / reauth_biometric / honeypot / block (NO upstream)
      5) Optional session/rate gates (Redis) -> can escalate
      6) Optional ML escalation -> can only escalate severity

    If preflight satisfied:
      -> call upstream
      -> optional watermark/trace
      -> post-upstream risk score (bytes/rows/status + drift)
      -> optional deception (post-upstream) depending on policy
      -> log export_completed + auto-arm beacon if hostile
    """

    # -------------------------
    # Timing + safe defaults
    # -------------------------
    t_total0 = perf_counter()
    t_preflight0 = t_total0
    timings: Dict[str, float] = {}

    def _final(content: Dict[str, Any]) -> Dict[str, Any]:
        timings["total_ms"] = round((perf_counter() - t_total0) * 1000, 2)
        if "preflight_ms" not in timings:
            timings["preflight_ms"] = round((perf_counter() - t_preflight0) * 1000, 2)
        if os.getenv("SIDECAR_TIMINGS", "0") == "1":
            content["timings"] = timings
        return content

    # SAFE DEFAULTS (never crash on early returns)
    intent_bytes: int = 0
    intent_rows: int = 0
    byte_size: int = 0
    row_count: int = 0
    content_type: str = ""
    deception_used: bool = False
    deception_reason = None
    risk_score: float = 0.0
    risk_level: str = "low"
    drift_score: float = 0.0
    tone_risk: float = 0.0
    export_id: str = ""
    trace_id: str = ""
    trace_sig: str = ""
    beacon_url: str = ""
    behavior_risk: dict = {"score": 0.0, "level": "low", "reasons": []}
    session_tainted: bool = False
    reauth_ok: bool = False

    # Your existing timer utility (optional)
    tm = _Timer()
    tm.mark("start")
    t_preflight0 = perf_counter()

    # -------------------------
    # Basic canonical context
    # -------------------------
    redis_client = getattr(request.app.state, "redis", None)

    target_url = str(payload.target_url)
    method = str((payload.method or "GET")).upper()
    upstream_headers = payload.headers or {}
    body_bytes: Optional[bytes] = payload.body.encode("utf-8") if payload.body is not None else None

    # Mint IDs early so ALL outcomes (including honeypot) can carry trace correlation.
    export_id = str(uuid4())
    trace_id = str(uuid4())

    # Beacon URL can be minted early too.
    base = os.getenv("SIDECAR_PUBLIC_BASE", "http://127.0.0.1:8000").rstrip("/")
    beacon_url = f"{base}/proxy/beacon/t/{trace_id}"

    # -------------------------
    # Trusted upstream gate (enterprise realism)
    # -------------------------
    def _parse_cidrs(raw: str) -> list[ipaddress._BaseNetwork]:
        out = []
        for part in (raw or "").split(","):
            part = part.strip()
            if not part:
                continue
            out.append(ipaddress.ip_network(part, strict=False))
        return out

    def _ip_in_cidrs(ip: str, cidrs: list[ipaddress._BaseNetwork]) -> bool:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return any(addr in net for net in cidrs)

    def _get_peer_ip(req: Request) -> str:
        return (req.client.host if req.client else "") or ""

    enforce_trusted = os.getenv("SIDECAR_ENFORCE_TRUSTED_UPSTREAM", "").strip().lower() in {"1", "true", "yes"}
    trusted_upstream = True
    if enforce_trusted:
        cidrs = _parse_cidrs(os.getenv("SIDECAR_TRUSTED_PROXY_CIDRS", ""))
        peer_ip = _get_peer_ip(request)
        trusted_upstream = bool(cidrs) and _ip_in_cidrs(peer_ip, cidrs)
        if not trusted_upstream:
            raise HTTPException(
                status_code=403,
                detail={
                    "error": "untrusted_upstream",
                    "peer_ip": peer_ip,
                    "next_action": "route_through_customer_proxy",
                },
            )

    # -------------------------
    # Canonical identity (single source of truth)
    # -------------------------
    canonical, tenant_cfg = resolve_canonical_identity(
        request=request,
        x_org_id=x_org_id,
        x_user_id=x_user_id,
        x_session_id=x_session_id,
        x_device_id=x_device_id,
        x_client_ip=x_client_ip,
        user_agent=request.headers.get("User-Agent"),
    )

    effective_tenant_id = canonical["tenant_id"]
    tenant_id = effective_tenant_id
    user_id = canonical["user_id"]
    session_id = canonical["session_id"]
    device_id = canonical["device_id"]
    client_ip = canonical["client_ip"]
    user_agent = canonical["user_agent"]

    geo_label = lookup_geo_label(client_ip)

    # Canonical tone (never re-read later)
    incoming_tone = (x_tone or "").strip()

    # -------------------------
    # Environment flags
    # -------------------------
    SIDECAR_LOADTEST = os.getenv("SIDECAR_LOADTEST", "0").lower() in ("1", "true", "yes")
    SIDECAR_BODY_MODE = os.getenv("SIDECAR_BODY_MODE", "preview").lower()
    SIDECAR_BODY_PREVIEW_BYTES = int(os.getenv("SIDECAR_BODY_PREVIEW_BYTES", "2048"))
    SIDECAR_COMMIT_MODE = os.getenv("SIDECAR_COMMIT_MODE", "end")
    SIDECAR_BEACON_AUTO_ARM = os.getenv("SIDECAR_BEACON_AUTO_ARM", "0").lower() in ("1", "true", "yes")

    redis_required = os.getenv("SIDECAR_REQUIRE_REDIS", "1").lower() in ("1", "true", "yes")
    test_mode = os.getenv("SIDECAR_TEST_MODE", "0").lower() in ("1", "true", "yes")
    bypass_strict_gates = bool(test_mode)

    # Always take redis from the FastAPI app state (set in app.py lifespan)
    redis_client = getattr(request.app.state, "redis", None)

    # -------------------------
    # Redis availability gate (predictable)
    # -------------------------
    if redis_required and (not test_mode) and (redis_client is None):
        return await _emit_and_return(
            status_code=503,
            content=_final({"error": "redis_unavailable", "next_action": "retry"}),
            effective_tenant_id=effective_tenant_id,
            x_user_id=str(user_id or ""),
            x_session_id=str(session_id or ""),
            x_device_id=str(device_id or ""),
            target_url=target_url,
            method=method,
            client_ip=str(client_ip),
            user_agent=str(user_agent),
            action="block",
            behavior_risk={"score": 0.0, "level": "low", "reasons": ["redis_unavailable"]},
            drift_score=0.0,
            tone_risk=0.0,
            # deception_used=False,  Used for Debug
            # session_tainted=False, Used for Debug
            risk_score=0.0,
            risk_level="low",
            row_count=0,
            byte_size=0,
        )

    # -------------------------
    # Export intent (preflight metric)
    # -------------------------
    intent_bytes, intent_rows = estimate_export_intent(target_url)

    # -------------------------
    # Log export_started (non-loadtest only)
    # -------------------------
    if not SIDECAR_LOADTEST and not _lt_enabled():
        _log_event(
            db,
            tenant_id=effective_tenant_id,
            user_id=user_id,
            device_id=device_id,
            session_id=session_id,
            source="proxy",
            event_type="export_started",
            resource=target_url,
            ip=client_ip,
            geo=geo_label,
            details={
                "method": method,
                "intent_bytes": int(intent_bytes or 0),
                "intent_rows": int(intent_rows or 0),
                "export_id": export_id,
                "trace_id": trace_id,
                "user_agent": user_agent,
            },
            user_agent=user_agent,
        )
        maybe_commit(db)

    # -------------------------
    # PRE-FLIGHT (NO UPSTREAM)
    # -------------------------
    anchors_ok = bool(user_id and session_id and device_id)

    # Session taint check (non-loadtest, non-test)
    if (not bypass_strict_gates) and (not SIDECAR_LOADTEST) and session_id:
        try:
            session_tainted = (
                db.query(Event)
                .filter(
                    Event.tenant_id == effective_tenant_id,
                    Event.session_id == session_id,
                    Event.event_type == "identity_incomplete",
                )
                .count()
                > 0
            )
        except Exception:
            session_tainted = False

    # Reauth success signal
    proof_header = reauth_proof_header_name()
    reauth_proof = request.headers.get(proof_header)

    if reauth_proof:
        try:
            await verify_reauth_proof(
                jwt_proof=reauth_proof,
                tenant_id=str(effective_tenant_id),
                user_id=str(user_id or ""),
                session_id=str(session_id or ""),
                device_id=str(device_id or ""),
                tone=incoming_tone,
                method=method,
                target_url=target_url,
                redis_client=redis_client,
                max_age_sec=180,
                fail_mode=fail_mode("reauth_replay_cache", default="closed"),
            )
            reauth_ok = True
        except ValueError:
            reauth_ok = False
    else:
        if trusted_upstream and switch("dev_allow_reauth_header", default=False):
            reauth_ok = (x_reauth_result or "").strip().lower() in {"ok", "pass", "true", "1"}
        else:
            reauth_ok = False

    # TEST MODE OVERRIDES (must be LAST so nothing overwrites)
    if bypass_strict_gates:
        anchors_ok = True
        incoming_tone = incoming_tone or "test-tone"
        reauth_ok = True
        session_tainted = False

    # 0) Anchors missing -> force biometric reauth (no tone dance)
    if not anchors_ok:
        if not SIDECAR_LOADTEST:
            _log_event(
                db,
                tenant_id=effective_tenant_id,
                user_id=user_id,
                device_id=device_id,
                session_id=session_id,
                source="proxy",
                event_type="identity_incomplete",
                resource=target_url,
                ip=client_ip,
                geo=geo_label,
                details={"reason": "missing_identity_anchors"},
                client_ip=client_ip,
                user_agent=user_agent,
            )
            maybe_commit(db)

        return await _emit_and_return(
            status_code=401,
            content=_final({
                "error": "identity_required",
                "next_action": "reauth_biometric",
                "tone": None,
                "tone_reason": "identity_incomplete",
                "behavior_score": 0.0,
                "behavior_level": "low",
                "reauth": {
                    "type": "webauthn",
                    "challenge_url": "/auth/webauthn/challenge",
                    "verify_url": "/auth/webauthn/verify",
                },
            }),
            effective_tenant_id=effective_tenant_id,
            x_user_id=str(user_id or ""),
            x_session_id=str(session_id or ""),
            x_device_id=str(device_id or ""),
            target_url=target_url,
            method=method,
            client_ip=str(client_ip),
            user_agent=str(user_agent),
            action="reauth_biometric",
            behavior_risk={"score": 0.0, "level": "low", "reasons": ["identity_incomplete"]},
            drift_score=0.0,
            tone_risk=0.0,
            deception_used=False,
            session_tainted=bool(session_tainted),
            risk_score=0.0,
            risk_level="low",
        )

    # 1) Tone handshake (missing -> issue -> 409)
    if not incoming_tone:
        try:
            issued = await issue_tone_redis(
                redis_client,
                db,
                tenant_id=effective_tenant_id,
                session_id=session_id,
                user_id=user_id,
                device_id=device_id,
            )
            maybe_commit(db)

        except Exception as e:
            # Enterprise behavior: Redis/tone infra failing is NOT a 500.
            # If we require Redis (normal mode), fail predictably with 503.
            if redis_required and (not test_mode):
                return await _emit_and_return(
                    status_code=503,
                    content=_final({"error": "redis_unavailable", "next_action": "retry"}),
                    effective_tenant_id=effective_tenant_id,
                    x_user_id=str(user_id or ""),
                    x_session_id=str(session_id or ""),
                    x_device_id=str(device_id or ""),
                    target_url=target_url,
                    method=method,
                    client_ip=str(client_ip),
                    user_agent=str(user_agent),
                    action="block",
                    behavior_risk={"score": 0.0, "level": "low", "reasons": ["redis_unavailable"]},
                    drift_score=0.0,
                    tone_risk=0.0,
                    risk_score=0.0,
                    risk_level="low",
                    row_count=0,
                    byte_size=0,
                )

            # If Redis isn't required (or in test/dev), degrade gracefully:
            issued = {"tone": "test-tone"} if test_mode else {"tone": None}

        # Normal “tone_required” response (409) when we successfully issued a tone
        return await _emit_and_return(
            status_code=409,
            content=_final({
                "message": "tone_required",
                "next_action": "retry_with_tone",
                "tone": issued.get("tone"),
                "tone_reason": "tone_issued",
                "behavior_score": 0.0,
                "behavior_level": "low",
                "reauth": None,
            }),
            effective_tenant_id=effective_tenant_id,
            x_user_id=str(user_id or ""),
            x_session_id=str(session_id or ""),
            x_device_id=str(device_id or ""),
            target_url=target_url,
            method=method,
            client_ip=str(client_ip),
            user_agent=str(user_agent),
            action="reauth_tone",
            behavior_risk={"score": 0.0, "level": "low", "reasons": ["tone_required"]},
            drift_score=0.0,
            tone_risk=0.0,
            deception_used=False,
            session_tainted=bool(session_tainted),
            risk_score=0.0,
            risk_level="low",
        )

    # 1b) Tone validate (invalid/expired/mismatch/unknown -> refresh -> 409)
    incoming_tone = (incoming_tone or "").strip()

    if bypass_strict_gates:
        is_valid, tone_reason = True, "test_mode"
    else:
        is_valid, tone_reason = await validate_tone_redis(
            redis_client,
            db,
            tenant_id=effective_tenant_id,
            session_id=session_id,
            user_id=user_id,
            device_id=device_id,
            provided_tone=incoming_tone,
        )

    tone_state = (tone_reason or "ok")

    if (not is_valid) or tone_state in ("tone_expired", "tone_mismatch", "tone_unknown_session"):
        issued = await issue_tone_redis(
            redis_client,
            db,
            tenant_id=effective_tenant_id,
            session_id=session_id,
            user_id=user_id,
            device_id=device_id,
        )
        maybe_commit(db)

        return await _emit_and_return(
            status_code=409,
            content=_final({
                "message": "tone_invalid",
                "tone_state": tone_state,
                "next_action": "retry_with_tone",
                "tone": issued.get("tone"),
                "tone_reason": "tone_refreshed",
                "behavior_score": 0.0,
                "behavior_level": "low",
                "reauth": None,
            }),
            effective_tenant_id=effective_tenant_id,
            x_user_id=str(user_id or ""),
            x_session_id=str(session_id or ""),
            x_device_id=str(device_id or ""),
            target_url=target_url,
            method=method,
            client_ip=str(client_ip),
            user_agent=str(user_agent),
            action="reauth_tone",  # ✅ correct action
            behavior_risk={"score": 0.0, "level": "low", "reasons": ["tone_invalid", tone_state]},
            drift_score=0.0,
            tone_risk=0.0,
            deception_used=False,
            session_tainted=bool(session_tainted),
            risk_score=0.0,
            risk_level="low",
        )

    # 2) DPoP gate (optional, after tone is valid)
    if require_dpop_for_request(target_url):
        dpop_jwt = request.headers.get("DPoP")
        if not dpop_jwt:
            return await _emit_and_return(
                status_code=401,
                content=_final({
                    "error": "dpop_required",
                    "next_action": "reauth",
                    "reason_codes": ["missing_dpop_header"],
                }),
                effective_tenant_id=effective_tenant_id,
                x_user_id=str(user_id or ""),
                x_session_id=str(session_id or ""),
                x_device_id=str(device_id or ""),
                target_url=target_url,
                method=method,
                client_ip=str(client_ip),
                user_agent=str(user_agent),
                action="reauth_dpop",
                behavior_risk=behavior_risk,
                drift_score=0.0,
                tone_risk=0.0,
                deception_used=False,
                session_tainted=bool(session_tainted),
                risk_score=0.0,
                risk_level="low",
            )

        try:
            await verify_dpop(
                dpop_jwt=dpop_jwt,
                http_method=method,
                http_url=target_url,
                tone=incoming_tone,
                redis_client=redis_client,
                iat_skew_sec=120,
                require_tone_binding=True,
            )
        except ValueError as e:
            return await _emit_and_return(
                status_code=401,
                content=_final({
                    "error": "dpop_invalid",
                    "next_action": "reauth",
                    "reason_codes": [str(e)],
                }),
                effective_tenant_id=effective_tenant_id,
                x_user_id=str(user_id or ""),
                x_session_id=str(session_id or ""),
                x_device_id=str(device_id or ""),
                target_url=target_url,
                method=method,
                client_ip=str(client_ip),
                user_agent=str(user_agent),
                action="reauth_dpop",
                behavior_risk=behavior_risk,
                drift_score=0.0,
                tone_risk=0.0,
                deception_used=False,
                session_tainted=bool(session_tainted),
                risk_score=0.0,
                risk_level="low",
            )

    # 3) Behavior preflight (no bytes read yet)
    tm.mark("before_risk")
    behavior_risk = evaluate_risk(
        user_id=user_id or "anonymous",
        session_id=session_id or "anon-session",
        device_id=device_id or "anon-device",
        user_agent=user_agent,
        ip=client_ip or "0.0.0.0",
        byte_size=intent_bytes,
        row_count=intent_rows,
    )
    action = decide_action(behavior_risk)  # allow/biometric/honeypot/block
    tm.mark("after_risk")

    # 4) Session taint handling (enterprise default: step-up, not permanent honeypot)
    if session_tainted and not reauth_ok:
        action = _more_severe(action, "biometric")
    # if tainted + reauth_ok, we *do not* force honeypot; we keep monitoring via gates.

    # 5) Redis gates (safe: never crash if redis missing)
    need_gates = (
        session_tainted
        or (behavior_risk.get("level") in ("medium", "high"))
        or (action != "allow")
        or (intent_rows and intent_rows > 5000)
        or (intent_bytes and intent_bytes > 5_000_000)
    )

    if need_gates and redis_client:
        behavior_risk, action, session_tainted2, gate_dbg = await apply_session_and_rate_gates(
            redis_client,
            tenant_id=effective_tenant_id,
            user_id=user_id or "anonymous",
            session_id=session_id or "anon-session",
            device_id=device_id or "anon-device",
            client_ip=client_ip or "0.0.0.0",
            user_agent=user_agent or "",
            target_url=target_url or "",
            behavior_risk=behavior_risk,
            behavior_action=action,
            reauth_ok=reauth_ok,
        )
        session_tainted = bool(session_tainted) or bool(session_tainted2)
    elif need_gates and not redis_client:
        # degrade safely (enterprise stance: step-up rather than 500)
        action = _more_severe(action, "biometric")

    # 6) ML escalation (can only escalate)
    ml = None
    try:
        feats = build_policy_features(
            tenant_id=effective_tenant_id,
            user_id=user_id,
            session_id=session_id,
            device_id=device_id,
            client_ip=client_ip,
            user_agent=user_agent,
            method=method,
            target_url=target_url,
            status_code=0,
            byte_size=0,
            row_count=0,
            behavior_score=float(behavior_risk.get("score", 0.0)),
            drift_score=0.0,
            tone_risk=float(tone_risk),
            deception_used=False,
            session_tainted=bool(session_tainted),
        )

        cloud = classify_cloud_intent(
            target_url=str(target_url or ""),
            method=str(method or ""),
            user_agent=str(user_agent or ""),
        )
        feats.update(cloud)

        baseline_feats = await update_cloud_baselines(
            redis_client=redis_client,
            tenant_id=str(effective_tenant_id or ""),
            user_id=str(user_id or ""),
            device_id=str(device_id or ""),
            session_id=str(session_id or ""),
            cloud=cloud,
        )
        feats.update(baseline_feats)

        # Use baselines to escalate safely
        if baseline_feats.get("cloud_first_seen_service") == 1 and cloud.get("cloud_sensitivity") in ("high", "critical"):
            action = _more_severe(action, "biometric")

        if baseline_feats.get("cloud_enum_burst_score", 0.0) >= 0.6 and cloud.get("cloud_plane") in ("control", "identity"):
            action = _more_severe(action, "biometric")

        # ---- Cloud ATO deterministic guardrails (pre-ML) ----
        # These rules are SAFE: they only escalate actions, never downgrade.
        try:
            if cloud.get("cloud_is_cloud") == 1:
                fam = cloud.get("cloud_action_family", "unknown")
                sens = cloud.get("cloud_sensitivity", "low")

                # Critical control-plane/persistence actions should ALWAYS step-up or block
                if fam in ("privilege_escalation", "persistence", "logging_change", "key_mgmt"):
                    # Prefer step-up first (enterprise-friendly), ML can still escalate further
                    action = _more_severe(action, "biometric")

                # Exfil hint: step-up + later throttling (we add throttling in Step 2)
                if cloud.get("ato_exfil_hint") == 1 and sens in ("high", "critical"):
                    action = _more_severe(action, "biometric")
        except Exception:
            pass

        ml = ml_infer(feats)
        action = _more_severe(action, str(ml.get("ml_action", "allow")))
    except Exception:
        ml = None

    # Debug force override (optional)
    forced = (os.getenv("SIDECAR_FORCE_ACTION") or "").strip().lower()
    if forced:
        if forced in ("honeypot", "deception"):
            action = "honeypot"
        elif forced in ("block",):
            action = "block"
        elif forced in ("reauth", "reauth_biometric", "biometric"):
            action = "biometric"
        elif forced in ("allow",):
            action = "allow"

    # PRE-FLIGHT boundary: set preflight_ms EXACTLY here
    timings["preflight_ms"] = round((perf_counter() - t_preflight0) * 1000, 2)

    # ---- Common envelope headers (for ALL outcomes) ----
    trace_sig = make_trace_sig(
        trace_id=trace_id,
        export_id=export_id,
        tenant_id=effective_tenant_id,
    )
    common_headers = {
        "X-Export-Id": export_id or "",
        "X-Trace-Id": trace_id or "",
        "X-Trace-Sig": trace_sig or "",
        "X-Beacon-Url": beacon_url or "",
    }

    # ---- Paid capability gate (enforcement only) ----
    # Everyone still gets: detection + ML + logging
    # Only paid gets: enforcement (block/biometric/honeypot)
    cloud_ato_paid = os.getenv("SIDECAR_CAP_CLOUD_ATO", "0").lower() in ("1", "true", "yes")
    active_containment_paid = os.getenv("SIDECAR_CAP_ACTIVE_CONTAINMENT", "0").lower() in ("1", "true", "yes")

    # If not paid, force observe-only for “containment” actions
    if not active_containment_paid:
        if action in ("block", "biometric", "honeypot"):
            # keep what we WOULD have done for upsell/telemetry
            would_have = action
            action = "allow"
            # optional: attach this to response body or headers later
            common_headers["X-Would-Have-Action"] = would_have

    # ---- Upsell counters: log "would-have-enforced" ----
    try:
        if redis_client:
            # counts per tenant per day
            day = datetime.utcnow().strftime("%Y%m%d")
            key = f"sc:upsell:{effective_tenant_id}:{day}:{would_have}"
            await redis_client.incr(key)
            await redis_client.expire(key, 8 * 24 * 3600)  # keep 8 days
    except Exception:
        pass

    # 7) Hard block (NO upstream)
    if action == "block":
        return await _emit_and_return(
            status_code=403,
            content=_final({
                "error": "blocked_by_preflight_policy",
                "next_action": "block",
                "tone": incoming_tone,
                "tone_reason": tone_state,
                "behavior_score": float(behavior_risk.get("score", 0.0)),
                "behavior_level": behavior_risk.get("level", "low"),
                "reauth": None,
                "headers": common_headers,
            }),
            effective_tenant_id=effective_tenant_id,
            x_user_id=str(user_id or ""),
            x_session_id=str(session_id or ""),
            x_device_id=str(device_id or ""),
            target_url=target_url,
            method=method,
            client_ip=str(client_ip),
            user_agent=str(user_agent),
            action="block",
            behavior_risk=behavior_risk,
            drift_score=0.0,
            tone_risk=0.0,
            deception_used=False,
            session_tainted=bool(session_tainted),
            risk_score=0.0,
            risk_level="high",
        )

    # 8) Honeypot (NO upstream)
    if action == "honeypot":
        decision = maybe_apply_deception(
            risk_score=100.0,
            risk_level="high",
            policy_mode="monitor",
            original_body=b"",
            content_type="text/csv",
            resource=target_url,
            user_id=user_id,
        )

        honey_body = ""
        honey_ct = "text/csv"
        if decision and getattr(decision, "used", False):
            honey_body = (decision.body_bytes or b"").decode("utf-8", errors="replace")
            honey_ct = getattr(decision, "content_type", honey_ct)

        honey_headers = dict(common_headers)
        honey_headers.update({
            "content-type": honey_ct,
            "X-Risk-Level": "high",
        })

        return await _emit_and_return(
            status_code=200,  # wrapper 200
            content=_final({
                "status_code": 409,  # inner indicates deception handoff
                "headers": honey_headers,
                "body": honey_body,
                "next_action": "deception",
                "tone": incoming_tone,
                "tone_reason": tone_state,
                "behavior_score": float(behavior_risk.get("score", 0.0)),
                "behavior_level": behavior_risk.get("level", "low"),
                "reauth": None,
                "risk_score": 100.0,
                "risk_level": "high",
            }),
            effective_tenant_id=effective_tenant_id,
            x_user_id=str(user_id or ""),
            x_session_id=str(session_id or ""),
            x_device_id=str(device_id or ""),
            target_url=target_url,
            method=method,
            client_ip=str(client_ip),
            user_agent=str(user_agent),
            action="honeypot",
            behavior_risk=behavior_risk,
            drift_score=0.0,
            tone_risk=0.0,
            deception_used=True,
            session_tainted=bool(session_tainted),
            risk_score=100.0,
            risk_level="high",
        )

    # 9) Step-up biometric if required (NO upstream)
    if action == "biometric" and behavior_risk.get("level") in ("medium", "high"):
        if not reauth_ok:
            return await _emit_and_return(
                status_code=401,
                content=_final({
                    "error": "step_up_required",
                    "next_action": "reauth_biometric",
                    "tone": incoming_tone,
                    "tone_reason": tone_state,
                    "behavior_score": float(behavior_risk.get("score", 0.0)),
                    "behavior_level": behavior_risk.get("level", "low"),
                    "reauth": {
                        "type": "webauthn",
                        "challenge_url": "/auth/webauthn/challenge",
                        "verify_url": "/auth/webauthn/verify",
                    },
                    "headers": common_headers,
                }),
                effective_tenant_id=effective_tenant_id,
                x_user_id=str(user_id or ""),
                x_session_id=str(session_id or ""),
                x_device_id=str(device_id or ""),
                target_url=target_url,
                method=method,
                client_ip=str(client_ip),
                user_agent=str(user_agent),
                action="reauth_biometric",
                behavior_risk=behavior_risk,
                drift_score=0.0,
                tone_risk=0.0,
                deception_used=False,
                session_tainted=bool(session_tainted),
                risk_score=0.0,
                risk_level="low",
            )

    # Optional: log reauth succeeded
    if reauth_ok and not SIDECAR_LOADTEST:
        _log_event(
            db,
            tenant_id=effective_tenant_id,
            user_id=user_id,
            device_id=device_id,
            session_id=session_id,
            source="proxy",
            event_type="reauth_succeeded",
            resource=target_url,
            ip=client_ip,
            geo=geo_label,
            details={"method": "proof_or_dev_header"},
            client_ip=client_ip,
            user_agent=user_agent,
        )
        maybe_commit(db)

    # -------------------------
    # UPSTREAM PROXY (allowed)
    # -------------------------
    t_upstream0 = perf_counter()

    UPSTREAM_TIMEOUT = float(os.getenv("UPSTREAM_TIMEOUT_SECONDS", "3"))
    UPSTREAM_RETRY_BUDGET_SECONDS = float(os.getenv("UPSTREAM_RETRY_BUDGET_SECONDS", "5"))
    UPSTREAM_MAX_ATTEMPTS = int(os.getenv("UPSTREAM_MAX_ATTEMPTS", "4"))
    use_stream = bool(SIDECAR_LOADTEST and SIDECAR_BODY_MODE == "none")

    client = getattr(request.app.state, "upstream_client", None) or HTTPX_CLIENT
    if client is None:
        raise RuntimeError("Upstream HTTP client not initialized (lifespan did not run?)")

    attempt = 0
    start_ts = time.time()
    status_code = None
    resp_headers: Dict[str, str] = {}
    resp = None
    last_err = None

    tm.mark("before_upstream")

    while attempt < UPSTREAM_MAX_ATTEMPTS and (time.time() - start_ts) < UPSTREAM_RETRY_BUDGET_SECONDS:
        attempt += 1
        try:
            if use_stream:
                async with client.stream(
                    method=method,
                    url=target_url,
                    headers=upstream_headers,
                    content=body_bytes if body_bytes else None,
                    timeout=UPSTREAM_TIMEOUT,
                ) as sresp:
                    status_code = sresp.status_code
                    resp_headers = dict(sresp.headers)
                    if status_code in (502, 503, 504):
                        last_err = f"upstream_status_{status_code}"
                        await asyncio.sleep(min(2 * attempt, 2))
                        continue
                    break
            else:
                resp = await client.request(
                    method=method,
                    url=target_url,
                    headers=upstream_headers,
                    content=body_bytes if body_bytes else None,
                    timeout=UPSTREAM_TIMEOUT,
                )
                status_code = resp.status_code
                resp_headers = dict(resp.headers)
                if status_code in (502, 503, 504):
                    last_err = f"upstream_status_{status_code}"
                    await asyncio.sleep(min(2 * attempt, 2))
                    continue
                break
        except httpx.RequestError as exc:
            last_err = str(exc)
            await asyncio.sleep(min(2 * attempt, 2))
            continue

    tm.mark("after_upstream")
    timings["upstream_ms"] = round((perf_counter() - t_upstream0) * 1000, 2)

    if status_code is None or status_code in (502, 503, 504):
        if not SIDECAR_LOADTEST:
            _log_event(
                db,
                tenant_id=effective_tenant_id,
                user_id=user_id,
                device_id=device_id,
                session_id=session_id,
                source="proxy",
                event_type="upstream_unavailable",
                resource=target_url,
                ip=client_ip,
                geo=geo_label,
                details={
                    "phase": "failed",
                    "error": last_err,
                    "target_url": target_url,
                    "attempts": attempt,
                    "retry_window_sec": UPSTREAM_RETRY_BUDGET_SECONDS,
                    "export_id": export_id,
                    "trace_id": trace_id,
                },
                client_ip=client_ip,
                user_agent=user_agent,
            )
            if SIDECAR_COMMIT_MODE == "end":
                db.commit()

        down_headers = dict(common_headers)
        down_headers["content-type"] = "application/json"

        return await _emit_and_return(
            status_code=503,
            content=_final({
                "status_code": 503,
                "headers": down_headers,
                "body": "",
                "risk_score": 0.0,
                "risk_level": "low",
                "deception_used": False,
                "deception_reason": None,
            }),
            effective_tenant_id=effective_tenant_id,
            x_user_id=str(user_id or ""),
            x_session_id=str(session_id or ""),
            x_device_id=str(device_id or ""),
            target_url=target_url,
            method=method,
            client_ip=client_ip,
            user_agent=user_agent,
            action="block",
            behavior_risk=behavior_risk,
            drift_score=0.0,
            tone_risk=0.0,
            deception_used=False,
            session_tainted=bool(session_tainted),
            risk_score=0.0,
            risk_level="low",
            row_count=0,
            byte_size=0,
        )

    # -------------------------
    # Response body handling
    # -------------------------
    content_type = (resp_headers.get("content-type", "") or "").lower()

    lt_enabled = SIDECAR_LOADTEST
    if lt_enabled and SIDECAR_BODY_MODE == "none":
        resp_body_bytes = b""
        byte_size = int(intent_bytes or 0)
        row_count = int(intent_rows or 0)

    elif use_stream:
        resp_body_bytes = b""
        byte_size = int(intent_bytes or 0)
        row_count = int(intent_rows or 0)

    else:
        resp_body_bytes = resp.content or b""
        byte_size = len(resp_body_bytes)
        row_count = 0
        if "text/csv" in content_type and resp_body_bytes:
            row_count = max(0, resp_body_bytes.count(b"\n") - 1)

    # -------------------------
    # Watermark + trace sig
    # -------------------------
    try:
        if should_watermark(content_type, target_url):
            resp_body_bytes = apply_watermark_bytes(
                resp_body_bytes,
                content_type=content_type,
                target_url=target_url,
                tenant_id=effective_tenant_id,
                export_id=export_id,
                trace_id=trace_id,
                trace_sig=trace_sig,
                beacon_url=beacon_url,
            )
            byte_size = len(resp_body_bytes)
            if "text/csv" in content_type and resp_body_bytes:
                row_count = max(0, resp_body_bytes.count(b"\n") - 1)
    except Exception:
        pass

    # client body output shaping
    if SIDECAR_BODY_MODE == "full":
        body_out = resp_body_bytes.decode("utf-8", errors="replace")
    elif SIDECAR_BODY_MODE == "preview":
        body_out = resp_body_bytes[:SIDECAR_BODY_PREVIEW_BYTES].decode("utf-8", errors="replace")
    else:
        body_out = ""

    # -------------------------
    # Post-upstream risk score
    # -------------------------
    policy = get_effective_policy(db)

    base_risk = _compute_basic_risk_score(
        row_count=row_count,
        byte_size=byte_size,
        status_code=status_code,
        resource=target_url,
        user_id=user_id,
        session_id=session_id,
    )

    drift_score = 0.0
    if not SIDECAR_LOADTEST:
        drift_score = update_and_score_drift(
            db,
            tenant_id=effective_tenant_id,
            user_id=user_id,
            ip=client_ip,
            byte_size=byte_size,
            row_count=row_count,
        )

    tone_risk = 0.0
    risk_score = min(100.0, max(0.0, base_risk + tone_risk + drift_score))

    risk_level, should_block = _risk_level_from_policy(
        score=risk_score,
        mode=policy.mode,
        high_threshold=policy.high_threshold,
        medium_threshold=policy.medium_threshold,
    )

    # Optional: deception POST-upstream
    deception_used = False
    deception_reason = None
    if should_block:
        decision = maybe_apply_deception(
            risk_score=risk_score,
            risk_level=risk_level,
            policy_mode=policy.mode,
            original_body=resp_body_bytes,
            content_type=content_type or "application/octet-stream",
            resource=target_url,
            user_id=user_id,
        )
        if decision and getattr(decision, "used", False):
            deception_used = True
            deception_reason = getattr(decision, "reason", None)
            resp_body_bytes = getattr(decision, "body_bytes", resp_body_bytes)
            body_out = resp_body_bytes.decode("utf-8", errors="replace")
            resp_headers["content-type"] = getattr(decision, "content_type", resp_headers.get("content-type"))
            should_block = False  # serve honey instead of hard block

    # -------------------------
    # DB export + event logs (non-loadtest)
    # -------------------------
    export_obj = None
    if not SIDECAR_LOADTEST:
        SKIP_FILE_HASH = os.getenv("SIDECAR_SKIP_FILE_HASH", "0") == "1"
        file_hash = None
        if resp_body_bytes and not SKIP_FILE_HASH:
            file_hash = hashlib.sha256(resp_body_bytes).hexdigest()

        export_obj = Export(
            export_id=export_id,
            tenant_id=effective_tenant_id,
            user_id=user_id,
            session_id=session_id,
            resource=target_url,
            row_count=row_count if row_count > 0 else None,
            byte_size=byte_size if byte_size > 0 else None,
            file_hash=file_hash,
            created_at_utc=datetime.utcnow(),
            ip=client_ip,
            user_agent=user_agent,
            is_deception=deception_used,
            deception_reason=deception_reason,
        )
        db.add(export_obj)

        # -------------------------
        # RiskFinding: session escalation (Option 2)
        # -------------------------
        try:
            SESSION_FLOOR = int(os.getenv("SIDECAR_SESSION_FINDING_FLOOR", "60"))
            corr_id = session_id  # correlation_id tracks the "same identity" over time

            if (not SIDECAR_LOADTEST) and corr_id and int(risk_score) >= SESSION_FLOOR:
                # latest session-finding for this correlation id
                existing_session = db.execute(
                    select(RiskFinding)
                    .where(RiskFinding.tenant_id == effective_tenant_id)
                    .where(RiskFinding.finding_type == "session")
                    .where(RiskFinding.correlation_id == str(corr_id))
                    .order_by(RiskFinding.created_at_utc.desc())
                    .limit(1)
                ).scalars().first()

                # Only write on level change (low -> medium -> high)
                if (existing_session is None) or (
                    str(existing_session.risk_level).lower() != str(risk_level).lower()
                ):
                    rf_session = RiskFinding(
                        tenant_id=effective_tenant_id,
                        user_id=user_id,
                        session_id=session_id,
                        export_id=export_id,  # keep export_id as the trigger event
                        resource=target_url,
                        risk_score=int(risk_score),
                        risk_level=str(risk_level),
                        reason=json.dumps([
                            "session_escalation",
                            f"risk_score={int(risk_score)}",
                            f"risk_level={str(risk_level)}",
                        ]),
                        finding_type="session",
                        correlation_id=str(corr_id),
                        created_at_utc=datetime.utcnow(),
                        is_acknowledged=False,
                    )
                    db.add(rf_session)
        except Exception:
            pass


        # -------------------------
        # INLINE risk finding (authoritative)
        # -------------------------
        try:
            # Config: create findings at/above this score even if "low"
            FINDING_FLOOR = float(os.getenv("SIDECAR_FINDING_FLOOR", "50"))

            # Build reasons (machine + human readable)
            reasons = []

            # Decompose the score we already computed
            if base_risk > 0:
                reasons.append(f"base_risk={base_risk:.1f}")
            if drift_score > 0:
                reasons.append(f"drift_score={drift_score:.1f}")
            if tone_risk > 0:
                reasons.append(f"tone_risk={tone_risk:.1f}")

            # Preflight / behavior signals (if you have them in scope)
            try:
                bscore = float(behavior_risk.get("score", 0.0))
                if bscore > 0:
                    reasons.append(f"behavior_score={bscore:.1f}")
            except Exception:
                pass

            # Action decisions
            reasons.append(f"preflight_action={str(action)}")
            if should_block:
                reasons.append("policy_should_block=true")
            if deception_used:
                reasons.append("deception_used=true")

            # Only create a RiskFinding when it’s meaningfully actionable
            # - anything not "allow" is actionable
            # - OR score >= floor
            actionable = (str(action).lower() != "allow") or (float(risk_score) >= FINDING_FLOOR)

            if actionable:
                rf = RiskFinding(
                    tenant_id=effective_tenant_id,
                    user_id=user_id,
                    session_id=session_id,
                    export_id=export_id,            # IMPORTANT: UUID string (Export.export_id)
                    resource=target_url,
                    risk_score=int(risk_score),
                    risk_level=str(risk_level),
                    reason=json.dumps(reasons),
                    created_at_utc=datetime.utcnow(),
                    is_acknowledged=False,
                )
                db.add(rf)

        except Exception:
            # Must never break request flow
            pass

        # ✅ Correct logging: behavior_* vs risk_*
        _log_event(
            db,
            tenant_id=effective_tenant_id,
            user_id=user_id,
            device_id=device_id,
            session_id=session_id,
            source="proxy",
            event_type="export_completed",
            resource=target_url,
            ip=client_ip,
            geo=geo_label,
            details={
                "phase": "completed",
                "status_code": int(status_code),
                "row_count": int(row_count),
                "byte_size": int(byte_size),
                "behavior_score": float(behavior_risk.get("score", 0.0)),
                "behavior_level": str(behavior_risk.get("level", "low")),
                "preflight_action": str(action),
                "risk_score": float(risk_score),
                "risk_level": str(risk_level),
                "deception_used": bool(deception_used),
                "deception_reason": deception_reason,
                "export_id": export_id,
                "trace_id": trace_id,
                "trace_sig": trace_sig,
                "beacon_url": beacon_url,
                "should_block_initial": bool(should_block),
            },
            client_ip=client_ip,
            user_agent=user_agent,
        )

        try:
            if redis_client:
                msg = json.dumps({
                    "tenant_id": effective_tenant_id,
                    "export_id": export_id,
                    "session_id": session_id,
                    "user_id": user_id,
                    "device_id": device_id,
                    "risk_score": float(risk_score),
                    "risk_level": str(risk_level),
                    "event_type": "export_completed",
                    "ts": datetime.utcnow().isoformat(),
                })
                await redis_client.publish(f"events:{effective_tenant_id}", msg)
        except Exception:
            pass

        if SIDECAR_COMMIT_MODE == "end":
            db.commit()
        else:
            db.flush()

    # -------------------------
    # Beacon auto-arm (hostile)
    # -------------------------
    if SIDECAR_BEACON_AUTO_ARM:
        try:
            if redis_client and trace_id:
                tid = str(effective_tenant_id or "")
                hostile = (
                    bool(deception_used)
                    or str(action).lower() in ("honeypot", "block")
                    or str(risk_level).lower() in ("high", "critical")
                )
                if hostile and tid:
                    ttl_days = int(os.getenv("SIDECAR_BEACON_TTL_DAYS_DEFAULT", "365"))
                    ttl_s = max(60, ttl_days * 86400)

                    await redis_client.setex(f"beacon:armed:{tid}:{trace_id}", ttl_s, "1")
                    await redis_client.setex(f"sess:revoked:{tid}:{session_id}", ttl_s, "1")

                    if not SIDECAR_LOADTEST:
                        _log_event(
                            db,
                            tenant_id=tid,
                            user_id=user_id,
                            device_id=device_id,
                            session_id=session_id,
                            source="beacon",
                            event_type="beacon_armed_auto",
                            resource=trace_id,
                            ip=client_ip,
                            geo=geo_label,
                            client_ip=client_ip,
                            user_agent=user_agent,
                            details={
                                "trace_id": trace_id,
                                "ttl_days": ttl_days,
                                "reason": "auto_arm_hostile",
                                "risk_level": risk_level,
                                "risk_score": float(risk_score),
                                "behavior_action": str(action),
                                "deception_used": bool(deception_used),
                                "deception_reason": deception_reason,
                            },
                        )
                        maybe_commit(db)
        except Exception:
            pass

    # -------------------------
    # Final response envelope
    # -------------------------
    envelope_headers = dict(resp_headers or {})
    envelope_headers.update(common_headers)
    envelope_headers.update({"X-Risk-Level": risk_level or "low"})

    return await _emit_and_return(
        status_code=200,
        content=_final({
            "status_code": int(status_code),
            "headers": envelope_headers,
            "body": body_out,
            "risk_score": float(risk_score),
            "risk_level": str(risk_level),
            "deception_used": bool(deception_used),
            "deception_reason": deception_reason,
        }),
        effective_tenant_id=effective_tenant_id,
        x_user_id=user_id,
        x_session_id=session_id,
        x_device_id=device_id,
        target_url=target_url,
        method=method,
        client_ip=client_ip,
        user_agent=user_agent,
        action=("allow" if action == "allow" else action),
        behavior_risk=behavior_risk,
        drift_score=float(drift_score or 0.0),
        tone_risk=float(tone_risk or 0.0),
        deception_used=bool(deception_used),
        session_tainted=bool(session_tainted),
        risk_score=float(risk_score or 0.0),
        risk_level=str(risk_level or "low"),
        row_count=int(row_count or 0),
        byte_size=int(byte_size or 0),
    )

# @router.post("/http")
# async def proxy_http(
#     request: Request,
#     payload: ProxyRequest,
#     db: Session = Depends(get_db),
#     x_user_id: Optional[str] = Header(None, alias="X-User-Id"),
#     x_session_id: Optional[str] = Header(None, alias="X-Session-Id"),
#     x_device_id: Optional[str] = Header(None, alias="X-Device-Id"),
#     x_tone: Optional[str] = Header(None, alias="X-Tone"),
#     x_reauth_result: Optional[str] = Header(None, alias="X-Reauth-Result"),
#     x_org_id: Optional[str] = Header(None, alias="X-Org-Id"),
#     x_client_ip: Optional[str] = Header(None, alias="X-Client-Ip"),
# ) -> JSONResponse:
#     """
#     Single-path proxy with strict preflight:

#     Preflight gates (NO upstream yet):
#       1) Anchors required (user/session/device) -> otherwise reauth
#       2) Tone handshake required -> issue tone and require retry
#       3) Behavior preflight -> allow / biometric / honeypot / block
#          - biometric satisfied by X-Reauth-Result: ok
#          - honeypot returns deception payload WITHOUT upstream

#     If preflight satisfied:
#       -> call upstream, measure basics, return envelope
#     """

#     t_total0 = perf_counter()
#     timings: Dict[str, float] = {}
#     t_preflight0 = t_total0 

#     def _final(content: Dict[str, Any]) -> Dict[str, Any]:
#         timings["total_ms"] = round((perf_counter() - t_total0) * 1000, 2)

#         # Only set preflight_ms if caller didn't set it explicitly
#         if "preflight_ms" not in timings:
#             timings["preflight_ms"] = round((perf_counter() - t_preflight0) * 1000, 2)

#         if os.getenv("SIDECAR_TIMINGS", "0") == "1":
#             content["timings"] = timings
#         return content

#     def _parse_cidrs(raw: str) -> list[ipaddress._BaseNetwork]:
#         out = []
#         for part in (raw or "").split(","):
#             part = part.strip()
#             if not part:
#                 continue
#             out.append(ipaddress.ip_network(part, strict=False))
#         return out

#     def _ip_in_cidrs(ip: str, cidrs: list[ipaddress._BaseNetwork]) -> bool:
#         try:
#             addr = ipaddress.ip_address(ip)
#         except ValueError:
#             return False
#         return any(addr in net for net in cidrs)

#     def _get_peer_ip(request: Request) -> str:
#         # peer IP = the socket peer (the thing actually talking to Sidecar)
#         return (request.client.host if request.client else "") or ""
    
#     # ---- TRUSTED UPSTREAM GATE (enterprise realism) ----
#     enforce_trusted = os.getenv("SIDECAR_ENFORCE_TRUSTED_UPSTREAM", "").strip().lower() in {"1", "true", "yes"}

#     trusted_upstream = True  # default unless enforcement is enabled
#     if enforce_trusted:
#         cidrs = _parse_cidrs(os.getenv("SIDECAR_TRUSTED_PROXY_CIDRS", ""))
#         peer_ip = _get_peer_ip(request)

#         trusted_upstream = bool(cidrs) and _ip_in_cidrs(peer_ip, cidrs)

#         if not trusted_upstream:
#             # When enforcement is ON, Sidecar must only be reachable behind the customer's gateway/proxy.
#             raise HTTPException(
#                 status_code=403,
#                 detail={
#                     "error": "untrusted_upstream",
#                     "peer_ip": peer_ip,
#                     "next_action": "route_through_customer_proxy",
#                 },
#             )
#     # -----------------------------------------------

#     tm = _Timer()
#     tm.mark("start")

#     redis_client = getattr(request.app.state, "redis", None)

#     canonical, tenant_cfg = resolve_canonical_identity(
#         request=request,
#         x_org_id=x_org_id,
#         x_user_id=x_user_id,
#         x_session_id=x_session_id,
#         x_device_id=x_device_id,
#         x_client_ip=x_client_ip,
#         user_agent=request.headers.get("User-Agent"),
#     )

#     effective_tenant_id = canonical["tenant_id"]
#     tenant_id = effective_tenant_id  # compatibility alias
#     user_id = canonical["user_id"]
#     session_id = canonical["session_id"]
#     device_id = canonical["device_id"]
#     client_ip = canonical["client_ip"]
#     user_agent = canonical["user_agent"]

#     # incoming_tone = (x_tone or "").strip()

#     # ---------------------------
#     # Canonical request context (single source of truth)
#     # ---------------------------
#     target_url = str(payload.target_url)
#     method = str((payload.method or "GET")).upper()

#     # Canonical identity already computed above:
#     # effective_tenant_id, user_id, session_id, device_id, client_ip, user_agent

#     geo_label = lookup_geo_label(client_ip)

#     # Canonical tone value (DO NOT re-read headers later and overwrite it)
#     incoming_tone = (x_tone or "").strip()

#     # ---- SAFE DEFAULTS so LOADTEST paths never crash ----
#     intent_bytes: int = 0
#     intent_rows: int = 0
#     export_obj = None
#     byte_size: int = 0
#     row_count: int = 0
#     content_type: str = ""
#     deception_used: bool = False
#     deception_reason = None
#     risk_score: float = 0.0
#     risk_level: str = "low"
#     drift_score: float = 0.0
#     tone_risk: float = 0.0
#     export_id: str = ""
#     trace_id: str = ""
#     trace_sig: str = ""
#     beacon_url: str = ""

#     # ---- SAFE DEFAULTS so early-return paths never crash ----
#     behavior_score: float = 0.0
#     behavior_level: str = "low"
#     tone_reason: str = "ok"
#     behavior_risk: dict = {"score": 0.0, "level": "low", "reasons": []}
#     behavior_action: str = "allow"
#     session_tainted: bool = False
#     anchors_ok: bool = bool(user_id and session_id and device_id)
#     # -----------------------------------------------------

#     # ---------------------------
#     # Redis availability gate (production behavior)
#     # ---------------------------
#     redis_required = os.getenv("SIDECAR_REQUIRE_REDIS", "1").lower() in ("1", "true", "yes")
#     test_mode = os.getenv("SIDECAR_TEST_MODE", "0").lower() in ("1", "true", "yes")
#     bypass_strict_gates = test_mode  # test harness bypass (k6/locust/dev)

#     if redis_required and (not test_mode) and (redis_client is None):
#         return await _emit_and_return(
#             status_code=503,
#             content=_final({
#                 "error": "redis_unavailable",
#                 "next_action": "retry",
#             }),
#             effective_tenant_id=effective_tenant_id,
#             x_user_id=str(user_id or ""),
#             x_session_id=str(session_id or ""),
#             x_device_id=str(device_id or ""),
#             target_url=target_url,
#             method=method,
#             client_ip=str(client_ip),
#             user_agent=str(user_agent),
#             action="block",
#             behavior_risk={"score": 0.0, "level": "low", "reasons": ["redis_unavailable"]},
#             drift_score=0.0,
#             tone_risk=0.0,
#             deception_used=False,
#             session_tainted=bool(session_tainted),
#             risk_score=0.0,
#             risk_level="low",
#             row_count=int(row_count or 0),
#             byte_size=int(byte_size or 0),
#         )
    
#     # # ---------- TRUSTED UPSTREAM (enterprise realism) ----------
#     # # If enabled, Sidecar will NOT accept identity/reauth headers from the public internet.
#     # # Customer will place Sidecar behind their gateway/proxy and ONLY the gateway IPs are trusted.

#     # def _is_trusted_upstream(req: Request) -> bool:
#     #     import os, ipaddress
#     #     cidrs = [c.strip() for c in os.getenv("SIDECAR_TRUSTED_PROXY_CIDRS", "").split(",") if c.strip()]
#     #     if not cidrs:
#     #         return False
#     #     peer = req.client.host if req.client else ""
#     #     try:
#     #         ip = ipaddress.ip_address(peer)
#     #         return any(ip in ipaddress.ip_network(c) for c in cidrs)
#     #     except Exception:
#     #         return False

#     # enforce_trusted = switch("enforce_trusted_upstream", default=False)
#     # trusted_upstream = _is_trusted_upstream(request) if enforce_trusted else True

#     # # Optional: treat any identity headers from untrusted sources as tampering
#     # if enforce_trusted and not trusted_upstream:
#     #     # If attacker tries to supply identity-ish headers directly, block hard.
#     #     if any([x_org_id, x_user_id, x_session_id, x_device_id, x_reauth_result]) or request.headers.get(reauth_proof_header_name()):
#     #         return await _emit_and_return(
#     #             status_code=403,
#     #             content=_final({
#     #                 "error": "untrusted_upstream",
#     #                 "next_action": "use_customer_gateway",
#     #                 "decision_action": "block",
#     #                 "reason_codes": ["untrusted_upstream"],
#     #             }),
#     #             effective_tenant_id=effective_tenant_id,
#     #             x_user_id=str(x_user_id or ""),
#     #             x_session_id=str(x_session_id or ""),
#     #             x_device_id=str(x_device_id or ""),
#     #             target_url=str(payload.target_url),
#     #             method=str((payload.method or "GET")).upper(),
#     #             client_ip=str(_client_ip_from_request(request)),
#     #             user_agent=str(request.headers.get("User-Agent") or ""),
#     #             action="block",
#     #             behavior_risk={"score": 0.0, "level": "low", "reasons": ["untrusted_upstream"]},
#     #             drift_score=float(drift_score or 0.0),
#     #             tone_risk=float(tone_risk or 0.0),
#     #             deception_used=False,
#     #             session_tainted=bool(session_tainted),
#     #             risk_score=float(risk_score or 0.0),
#     #             risk_level=str(risk_level or "low"),
#     #         )
#     # # -----------------------------------------------------------

#     # if SIDECAR_TEST_MODE:
#     #     incoming_tone = (tone or "test-tone").strip()
#     # else:
        
#     #     # --- Rolling Tone Gate (Redis source of truth) ---
#     #     if not (user_id and session_id and device_id):
#     #         return await _emit_and_return(
#     #             status_code=401,
#     #             content={"error": "identity_required", "next_action": "reauth"},
#     #             effective_tenant_id=effective_tenant_id,
#     #             x_user_id=str(x_user_id or ""),
#     #             x_session_id=str(x_session_id or ""),
#     #             x_device_id=str(x_device_id or ""),
#     #             target_url=str(payload.target_url),
#     #             method=str(payload.method),
#     #             client_ip=str(client_ip),
#     #             user_agent=str(user_agent),
#     #             action="reauth_biometric",
#     #             behavior_risk={},
#     #             drift_score=float(drift_score or 0.0),
#     #             tone_risk=float(tone_risk or 0.0),
#     #             deception_used=False,
#     #             session_tainted=bool(session_tainted),
#     #             risk_score=float(risk_score or 0.0),
#     #             risk_level=str(risk_level or "low"),
#     #         )

#     #     if not redis_client and os.getenv("SIDECAR_TEST_MODE", "0") != "1":
#     #         return await _emit_and_return(
#     #             status_code=503,
#     #             content={"error": "redis_unavailable", "next_action": "retry"},
#     #             effective_tenant_id=effective_tenant_id,
#     #             x_user_id=x_user_id,
#     #             x_session_id=x_session_id,
#     #             x_device_id=x_device_id,
#     #             target_url=target_url,
#     #             method=method,
#     #             client_ip=client_ip,
#     #             user_agent=user_agent,
#     #             action="block",                 # treat as denied (service unavailable)
#     #             behavior_risk=behavior_risk or {},
#     #             drift_score=float(drift_score or 0.0),
#     #             tone_risk=float(tone_risk or 0.0),
#     #             deception_used=False,
#     #             session_tainted=bool(session_tainted),
#     #             risk_score=float(risk_score or 0.0),
#     #             risk_level=str(risk_level or "low"),
#     #             row_count=int(row_count or 0),
#     #             byte_size=int(byte_size or 0),
#     #         )

#     #     incoming_tone = (tone or "").strip()

#     #     if not incoming_tone:
#     #         issued = await issue_tone_redis(
#     #             redis_client,
#     #             tenant_id=effective_tenant_id,
#     #             user_id=user_id,
#     #             device_id=device_id,
#     #             session_id=x_session_id or "anon-session", 
#     #             min_sec=10,
#     #             max_sec=30,
#     #         )

#     #         # SQL log that matches Redis EXACTLY (same tone + same expiry)
#     #         try:
#     #             log_tone_rotation_sql(
#     #                 db,
#     #                 tenant_id=tenant_id,
#     #                 session_id=session_id,
#     #                 user_id=user_id,
#     #                 device_id=device_id,
#     #                 raw_tone=str(issued["tone"]),
#     #                 expires_at=issued["expires_at"],
#     #             )
#     #         except Exception:
#     #             pass

#     #         return await _emit_and_return(
#     #             status_code=401,
#     #             content={
#     #                 "error": "tone_required",
#     #                 "next_action": "retry_with_tone",
#     #                 "tone": str(issued["tone"]),
#     #             },
#     #             effective_tenant_id=effective_tenant_id,
#     #             x_user_id=str(x_user_id or ""),
#     #             x_session_id=str(x_session_id or ""),
#     #             x_device_id=str(x_device_id or ""),
#     #             target_url=str(payload.target_url),
#     #             method=str(payload.method),
#     #             client_ip=str(client_ip),
#     #             user_agent=str(user_agent),
#     #             action="reauth_biometric",
#     #             behavior_risk=behavior_risk if isinstance(behavior_risk, dict) else {},
#     #             drift_score=float(drift_score or 0.0),
#     #             tone_risk=float(tone_risk or 0.0),
#     #             deception_used=False,
#     #             session_tainted=bool(session_tainted),
#     #             risk_score=float(risk_score or 0.0),
#     #             risk_level=str(risk_level or "low"),
#     #         )

#     #     ok = await validate_tone_redis(
#     #         redis_client=redis_client,
#     #         tenant_id=effective_tenant_id,
#     #         user_id=x_user_id or "anonymous",
#     #         device_id=x_device_id or "anon-device",
#     #         session_id=x_session_id or "anon-session",   # ✅ REQUIRED
#     #         presented_tone=incoming_tone,
#     #     )

#     #     if not ok:
#     #         issued = await issue_tone_redis(
#     #             redis_client,
#     #             tenant_id=effective_tenant_id,
#     #             user_id=user_id,
#     #             device_id=device_id,
#     #             session_id=x_session_id,
#     #             min_sec=10,
#     #             max_sec=30,
#     #         )

#     #         try:
#     #             log_tone_rotation_sql(
#     #                 db,
#     #                 tenant_id=tenant_id,
#     #                 session_id=session_id,
#     #                 user_id=user_id,
#     #                 device_id=device_id,
#     #                 raw_tone=str(issued["tone"]),
#     #                 expires_at=issued["expires_at"],
#     #             )
#     #         except Exception:
#     #             pass

#     #         return await _emit_and_return(
#     #             status_code=401,
#     #             content={
#     #                 "error": "tone_invalid",
#     #                 "next_action": "retry_with_tone",
#     #                 "tone": str(issued["tone"]),
#     #             },
#     #             effective_tenant_id=effective_tenant_id,
#     #             x_user_id=str(x_user_id or ""),
#     #             x_session_id=str(x_session_id or ""),
#     #             x_device_id=str(x_device_id or ""),
#     #             target_url=str(payload.target_url),
#     #             method=str(payload.method),
#     #             client_ip=str(client_ip),
#     #             user_agent=str(user_agent),
#     #             action="reauth_biometric",
#     #             behavior_risk=behavior_risk if isinstance(behavior_risk, dict) else {},
#     #             drift_score=float(drift_score or 0.0),
#     #             tone_risk=float(tone_risk or 0.0),
#     #             deception_used=False,
#     #             session_tainted=bool(session_tainted),
#     #             risk_score=float(risk_score or 0.0),
#     #             risk_level=str(risk_level or "low"),
#     #         )
#     #     # --- end Rolling Tone Gate ---

#     # redis_client = getattr(request.app.state, "redis", None)
#     if redis_client and session_id:
#         revoked_key = f"sess:revoked:{effective_tenant_id}:{session_id}"
#         if await redis_client.get(revoked_key):
#             # log + hard deny
#             _log_event(
#                 db,
#                 tenant_id=effective_tenant_id,
#                 user_id=user_id,
#                 device_id=device_id,
#                 session_id=session_id,
#                 source="proxy",
#                 event_type="session_revoked_block",
#                 resource=payload.target_url,
#                 ip=client_ip,
#                 geo=geo_label,
#                 client_ip=client_ip,
#                 user_agent=user_agent,
#                 details={"reason": "revoked_key_present"},
#             )
#             maybe_commit(db)
#             raise HTTPException(status_code=401, detail="session_revoked")

#     # require_dpop = os.getenv("SIDECAR_REQUIRE_DPOP", "0") == "1"
#     # if require_dpop:
#     #     dpop_jwt = request.headers.get("DPoP")  # keep name configurable later
#     #     presented_tone = incoming_tone # you already validated it above in the Rolling Tone Gate

#     #     try:
#     #         await verify_dpop(
#     #             dpop_jwt=dpop_jwt,
#     #             http_method=str(payload.method or "GET"),
#     #             http_url=str(payload.target_url),
#     #             tone=presented_tone,
#     #             redis_client=redis_client,
#     #             iat_skew_sec=int(os.getenv("SIDECAR_DPOP_SKEW_SEC", "120")),
#     #             require_tone_binding=True,
#     #         )
#     #     except ValueError as e:
#     #         # IMPORTANT: log + return a normal-looking denial (don’t leak details in prod)
#     #         return await _emit_and_return(
#     #             status_code=401,
#     #             content={"error": "reauth_required", "next_action": "reauth"},
#     #             effective_tenant_id=effective_tenant_id,
#     #             x_user_id=str(x_user_id or ""),
#     #             x_session_id=str(x_session_id or ""),
#     #             x_device_id=str(x_device_id or ""),
#     #             target_url=str(payload.target_url),
#     #             method=str(payload.method),
#     #             client_ip=str(client_ip),
#     #             user_agent=str(user_agent),
#     #             action="reauth_dpop",
#     #             behavior_risk=behavior_risk if isinstance(behavior_risk, dict) else {},
#     #             drift_score=float(drift_score or 0.0),
#     #             tone_risk=float(tone_risk or 0.0),
#     #             deception_used=False,
#     #             session_tainted=bool(session_tainted),
#     #             risk_score=float(risk_score or 0.0),
#     #             risk_level=str(risk_level or "low"),
#     #         )
    
#     # --- 0) If no tone -> issue one and require retry ---
#     # if not tone:
#     #     issued = issue_tone(
#     #         db,
#     #         tenant_id=effective_tenant_id,
#     #         session_id=session_id,
#     #         user_id=user_id,
#     #         device_id=device_id,
#     #     )

#     #     expires_at = issued["expires_at"]
#     #     tone_value = issued["tone"]

#     #     # Cache hashed tone in Redis with TTL
#     #     if redis_client and expires_at:
#     #         ttl = int((expires_at - datetime.utcnow()).total_seconds())
#     #         ttl = max(1, ttl)
#     #         await redis_client.setex(
#     #             _tone_cache_key(effective_tenant_id, user_id, device_id),
#     #             ttl,
#     #             _tone_hash(tone_value),
#     #         )

#     #     return JSONResponse(
#     #         status_code=401,
#     #         content={
#     #             "error": "tone_required",
#     #             "next_action": "reauth",
#     #             "tone": tone_value,
#     #             "expires_at": expires_at.isoformat() if expires_at else None,
#     #         },
#     #     )

#     # # --- 1) Tone exists -> validate (Redis fast-path, DB fallback) ---
#     # incoming_tone = (tone or "").strip()  # 'tone' is x_tone above
#     # ok = False
#     # tone_reason = "ok"

#     # # Redis fast-path
#     # if redis_client and incoming_tone:
#     #     cached = await redis_client.get(
#     #         _tone_cache_key(effective_tenant_id, user_id, device_id)
#     #     )
#     #     if cached and cached.decode("utf-8") == _tone_hash(incoming_tone):
#     #         ok = True

#     # # DB fallback
#     # if not ok:
#     #     ok, tone_reason = validate_tone_db(
#     #         db,
#     #         tenant_id=effective_tenant_id,
#     #         session_id=session_id,
#     #         user_id=user_id,
#     #         device_id=device_id,
#     #         provided_tone=incoming_tone,
#     #     )

#     # if not ok:
#     #     return JSONResponse(
#     #         status_code=401,
#     #         content={
#     #             "error": "invalid_tone",
#     #             "next_action": "reauth",
#     #             "tone_reason": tone_reason,  # optional (remove later for stealth)
#     #         },
#     #     )


#     # # Validate tone: Redis fast-path first, DB fallback second
#     # ok = False

#     # if redis_client:
#     #     cached = await redis_client.get(_tone_cache_key(tenant_id, user_id, device_id))
#     #     if cached and cached.decode("utf-8") == _tone_hash(tone):
#     #         ok = True

#     # if not ok:
#     #     # fallback to DB source of truth
#     #     ok, _reason = validate_tone(db, session_id=session_id, user_id=user_id, device_id=device_id, provided_tone=tone)

#     #     # refresh Redis cache on success
#     #     if ok and redis_client:
#     #         # pull latest record to get its expires_at + combined tone
#     #         # simplest: re-issue a fresh tone window here (keeps TTL correct)
#     #         issued = issue_tone(db, tenant_id=effective_tenant_id, session_id=session_id, user_id=user_id, device_id=device_id)
#     #         ttl = int((issued["expires_at"] - datetime.utcnow()).total_seconds())
#     #         ttl = max(1, ttl)
#     #         await redis_client.setex(
#     #             _tone_cache_key(tenant_id, user_id, device_id),
#     #             ttl,
#     #             _tone_hash(issued["tone"]),
#     #         )

#     # if not ok:
#     #     return JSONResponse(
#     #         status_code=401,
#     #         content={"error": "invalid_tone", "next_action": "reauth"},
#     #     )


#     # Normalize incoming tone (FastAPI Header + raw header)
#     # incoming_tone = (x_tone or request.headers.get("X-Tone") or "").strip()

#     # TEST MODE: allow k6/dev harness to proceed without doing the full tone dance
#     # if os.getenv("SIDECAR_TEST_MODE", "0") == "1" and not incoming_tone:
#     #     incoming_tone = "test-tone"

#     # target_url = payload.target_url
#     logger.info(f"[proxy] HTTPX_CLIENT is None? {HTTPX_CLIENT is None}")
#     # method = (payload.method or "GET").upper()
#     intent_bytes, intent_rows = estimate_export_intent(target_url)
#     upstream_headers = payload.headers or {}
#     body_bytes: Optional[bytes] = payload.body.encode("utf-8") if payload.body is not None else None

#     # user_agent = request.headers.get("user-agent")
#     export_id = str(uuid4())
#     trace_id = trace_id or str(uuid4())   # or however you do it
#     trace_sig = trace_sig or ""           # or compute it here

#     tm.mark("after_parse")

#     # Only do DB logging when NOT loadtesting (DB commits destroy latency during perf tests)
#     if not SIDECAR_LOADTEST:
#         tm.mark("before_db")

#         # Log export_started always (even if preflight blocks)
#         if not _lt_enabled():
#             _log_event(
#                 db,
#                 tenant_id=effective_tenant_id,
#                 user_id=user_id,
#                 device_id=device_id,
#                 session_id=session_id,
#                 source="proxy",
#                 event_type="export_started",
#                 resource=target_url,
#                 ip=client_ip,
#                 geo=geo_label,
#                 details={
#                     "method": method,
#                     "intent_bytes": int(intent_bytes or 0),
#                     "intent_rows": int(intent_rows or 0),
#                     "export_id": export_id,
#                     "trace_id": trace_id,
#                     "trace_sig": trace_sig,
#                     "user_agent": user_agent,
#                 },
#                 user_agent=user_agent,
#             )
#             maybe_commit(db)

#     # -------------------------
#     # PRE-FLIGHT (NO UPSTREAM)
#     # -------------------------
#     anchors_ok = bool(user_id and session_id and device_id)

#     # If this session ever arrived without full identity anchors, treat it as tainted.
#     session_tainted = False
#     if (not bypass_strict_gates) and (not SIDECAR_LOADTEST) and session_id:
#         session_tainted = (
#             db.query(Event)
#             .filter(
#                 Event.tenant_id == effective_tenant_id,
#                 Event.session_id == session_id,   # <-- FIXED (see #3 below)
#                 Event.event_type == "identity_incomplete",
#             )
#             .count()
#             > 0
#         )

#     # Reauth success signal from harness/client
#     reauth_ok = False

#     proof_header = reauth_proof_header_name()
#     reauth_proof = request.headers.get(proof_header)

#     if reauth_proof:
#         try:
#             await verify_reauth_proof(
#                 jwt_proof=reauth_proof,
#                 tenant_id=str(effective_tenant_id),
#                 user_id=str(user_id or ""),
#                 session_id=str(session_id or ""),
#                 device_id=str(device_id or ""),
#                 tone=incoming_tone,
#                 method=method,
#                 target_url=target_url,
#                 redis_client=redis_client,
#                 max_age_sec=180,
#                 fail_mode=fail_mode("reauth_replay_cache", default="closed"),
#             )
#             reauth_ok = True
#         except ValueError:
#             reauth_ok = False
#     else:
#         # DEV/Test-only fallback:
#         if trusted_upstream and switch("dev_allow_reauth_header", default=False):
#             reauth_ok = (x_reauth_result or "").strip().lower() in {"ok", "pass", "true", "1"}
#         else:
#             reauth_ok = False

#     # ✅ TEST MODE (LOCAL LOAD TESTING ONLY) — apply overrides LAST so nothing overwrites them
#     if bypass_strict_gates:
#         anchors_ok = True
#         incoming_tone = incoming_tone or "test-tone"
#         reauth_ok = True
#         session_tainted = False


#     # 0) Anchors missing -> cannot do tone safely -> force reauth
#     if not anchors_ok:
#         _log_event(
#             db,
#             tenant_id=effective_tenant_id,
#             user_id=user_id,
#             device_id=device_id,
#             session_id=session_id,
#             source="proxy",
#             event_type="identity_incomplete",
#             resource=target_url,
#             ip=client_ip,
#             geo=geo_label,
#             details={"reason": "missing_identity_anchors"},
#             client_ip=client_ip,
#             user_agent=user_agent,
#         )
#         # db.commit()
#         maybe_commit(db)

#         tm.mark("end")

#         return await _emit_and_return(
#             status_code=401,
#             content=_final({
#                 "error": "Identity anchors missing. Reauth required.",
#                 "next_action": "reauth_biometric",
#                 "tone": None,
#                 "tone_reason": "identity_incomplete",
#                 "behavior_score": 0.0,
#                 "behavior_level": "low",
#                 "reauth": {
#                     "type": "webauthn",
#                     "challenge_url": "/auth/webauthn/challenge",
#                     "verify_url": "/auth/webauthn/verify",
#                 },
#             }),
#             effective_tenant_id=effective_tenant_id,
#             x_user_id=str(user_id or ""),
#             x_session_id=str(session_id or ""),
#             x_device_id=str(device_id or ""),
#             target_url=str(payload.target_url),
#             method=method,
#             client_ip=str(client_ip),
#             user_agent=str(user_agent),
#             action="reauth_biometric",
#             behavior_risk={},
#             drift_score=float(drift_score or 0.0),
#             tone_risk=float(tone_risk or 0.0),
#             deception_used=False,
#             session_tainted=bool(session_tainted),
#             risk_score=float(risk_score or 0.0),
#             risk_level=str(risk_level or "low"),
#         )

#     # 1) Tone handshake: must have a valid tone before upstream
#     # tone_reason: str = "ok"
#     # issued_tone: Optional[str] = None

#     if not incoming_tone:
#         issued = await issue_tone_redis(
#             redis_client,
#             db,
#             tenant_id=effective_tenant_id,
#             session_id=session_id,
#             user_id=user_id,
#             device_id=device_id,
#         )
#         maybe_commit(db)

#         return await _emit_and_return(
#             status_code=409,
#             content=_final({
#                 "message": "Tone required. Retry the same request with X-Tone.",
#                 "next_action": "retry_with_tone",
#                 "tone": issued.get("tone"),
#                 "tone_reason": "tone_issued",
#                 "behavior_score": 0.0,
#                 "behavior_level": "low",
#                 "reauth": None,
#             }),
#             effective_tenant_id=effective_tenant_id,
#             x_user_id=str(user_id or ""),
#             x_session_id=str(session_id or ""),
#             x_device_id=str(device_id or ""),
#             target_url=str(payload.target_url),
#             method=method,
#             client_ip=str(client_ip),
#             user_agent=str(user_agent),
#             action="reauth_tone",
#             behavior_risk={"score": 0.0, "level": "low", "reasons": ["tone_required"]},
#             drift_score=0.0,
#             tone_risk=0.0,
#             deception_used=False,
#             session_tainted=bool(session_tainted),
#             risk_score=0.0,
#             risk_level="low",
#         )

#     # --- Tone (ephemeral proof) gate ---
#     incoming_tone = (incoming_tone or "").strip()

#     if bypass_strict_gates:
#         is_valid, tone_reason = True, "test_mode"
#     else:
#         is_valid, tone_reason = await validate_tone_redis(
#             redis_client,
#             db,
#             tenant_id=effective_tenant_id,
#             session_id=session_id,
#             user_id=user_id,
#             device_id=device_id,
#             provided_tone=incoming_tone,
#         )

#     tone_state = (tone_reason or "ok")
#     tone_present = 1 if incoming_tone else 0

#     if (not is_valid) or tone_state in ("tone_expired", "tone_mismatch", "tone_unknown_session"):
#         issued = await issue_tone_redis(
#             redis_client,
#             db,
#             tenant_id=effective_tenant_id,
#             session_id=session_id,
#             user_id=user_id,
#             device_id=device_id,
#         )

#         maybe_commit(db)

#         return await _emit_and_return(
#             status_code=409,
#             content=_final({
#                 "message": f"Tone invalid ({tone_state}). Retry with fresh tone.",
#                 "next_action": "retry_with_tone",
#                 "tone": issued.get("tone"),
#                 "tone_reason": "tone_refreshed",
#                 "behavior_score": 0.0,
#                 "behavior_level": "low",
#                 "reauth": None,
#             }),
#             effective_tenant_id=effective_tenant_id,
#             x_user_id=str(user_id or ""),
#             x_session_id=str(session_id or ""),
#             x_device_id=str(device_id or ""),
#             target_url=str(payload.target_url),
#             method=method,
#             client_ip=str(client_ip),
#             user_agent=str(user_agent),
#             action="reauth_tone",
#             behavior_risk={"score": 0.0, "level": "low", "reasons": ["tone_invalid"]},
#             drift_score=0.0,
#             tone_risk=0.0,
#             deception_used=False,
#             session_tainted=bool(session_tainted),
#             risk_score=0.0,
#             risk_level="low",
#         )

#     # --- end tone gate ---

#     # -------------------------
#     # DPoP (device proof-of-possession) gate
#     # -------------------------
#     if require_dpop_for_request(target_url):
#         dpop_jwt = request.headers.get("DPoP")
#         try:
#             await verify_dpop(
#                 dpop_jwt=dpop_jwt,
#                 http_method=method,
#                 http_url=target_url,
#                 tone=incoming_tone,
#                 redis_client=redis_client,
#                 iat_skew_sec=120,
#                 require_tone_binding=True,
#             )
#         except ValueError as e:
#             return await _emit_and_return(
#                 status_code=401,
#                 content=_final({
#                     "error": "DPoP required.",
#                     "next_action": "reauth",
#                     "status_code": 401,
#                     "reason_codes": [str(e)],
#                 }),
#                 effective_tenant_id=effective_tenant_id,
#                 x_user_id=str(user_id or ""),
#                 x_session_id=str(session_id or ""),
#                 x_device_id=str(device_id or ""),
#                 target_url=str(payload.target_url),
#                 method=method,
#                 client_ip=str(client_ip),
#                 user_agent=str(user_agent),
#                 action="reauth",
#                 behavior_risk=behavior_risk if isinstance(behavior_risk, dict) else {},
#                 drift_score=float(drift_score or 0.0),
#                 tone_risk=float(tone_risk or 0.0),
#                 deception_used=bool(deception_used),
#                 session_tainted=bool(session_tainted),
#                 risk_score=float(risk_score or 0.0),
#                 risk_level=str(risk_level or "low"),
#             )

#     # 2) Behavior preflight (identity-only; no bytes yet)
#     preflight_note = "risk_eval_started"

#     tm.mark("before_risk")
#     # intent_bytes, intent_rows = estimate_export_intent(target_url)
#     tm.mark("after_intent")

#     behavior_risk = evaluate_risk(
#         user_id=user_id or "anonymous",
#         session_id=session_id or "anon-session",
#         device_id=device_id or "anon-device",
#         user_agent=user_agent,
#         ip=client_ip or "0.0.0.0",
#         byte_size=intent_bytes,
#         row_count=intent_rows,
#     )

#     behavior_action = decide_action(behavior_risk)  # allow/biometric/honeypot/block
#     tm.mark("after_risk")
#     # print("=== PRE-FLIGHT RISK ===")
#     # print("user_id:", x_user_id)
#     # print("session_id:", x_session_id)
#     # print("device_id:", x_device_id)
#     # print("anchors_ok:", anchors_ok)
#     # print("behavior_risk:", behavior_risk)
#     # print("behavior_action:", behavior_action)
#     # print("=======================")

#     if DEBUG_PREFLIGHT:
#         logger.info(
#             "PREFLIGHT_RISK user=%s session=%s device=%s anchors_ok=%s risk=%s action=%s",
#             x_user_id, x_session_id, x_device_id, anchors_ok, behavior_risk, behavior_action
#         )

#     # ---- D1–D6 gates: session binding, age/idle, burst limits, sensitive export rules ----
#     effective_user = user_id or "anonymous"
#     effective_sess = session_id or "anon-session"
#     effective_dev  = device_id or "anon-device"

#     # Run heavier Redis gates only when needed
#     need_gates = (
#         session_tainted
#         or (behavior_risk.get("level") in ("medium", "high"))
#         or (behavior_action != "allow")
#         or (intent_rows and intent_rows > 5000)
#         or (intent_bytes and intent_bytes > 5_000_000)
#     )

#     if need_gates:
#         behavior_risk, behavior_action, session_tainted2, gate_dbg = await apply_session_and_rate_gates(
#             redis_client,
#             tenant_id=effective_tenant_id,
#             user_id=effective_user,
#             session_id=effective_sess,
#             device_id=effective_dev,
#             client_ip=client_ip or "0.0.0.0",
#             user_agent=user_agent or "",
#             target_url=target_url or "",
#             behavior_risk=behavior_risk,
#             behavior_action=behavior_action,
#             reauth_ok=reauth_ok,
#         )
#     else:
#         session_tainted2, gate_dbg = False, {"skipped": True, "reason": "low_risk"}

#     # If earlier code already set session_tainted, keep it.
#     session_tainted = bool(session_tainted) or bool(session_tainted2)

#     # print("=== GATES ===")
#     # print(gate_dbg)
#     # print("=============")

#     if DEBUG_PREFLIGHT:
#         logger.info("GATES %s", gate_dbg)

#     # If session started suspicious (missing anchors), never "auto-allow" it later.
#     if session_tainted and not reauth_ok:
#         behavior_action = "biometric"
#     elif session_tainted and reauth_ok:
#         # keep watch, but don't force honeypot
#         behavior_action = _more_severe(behavior_action, "allow")

#     # Final decision variable used everywhere below
#     action = behavior_action

#     # -------------------------
#     # ML policy recommendation (SAFE: can only escalate)
#     # -------------------------
#     ml = None
#     try:
#         # At preflight time we don't have status/bytes/rows yet, so we pass safe placeholders.
#         # This still works because behavior/tone/taint carry most signal for preflight decisions.
#         feats = build_policy_features(
#             tenant_id=effective_tenant_id,
#             user_id=user_id,
#             session_id=session_id,
#             device_id=device_id,
#             client_ip=client_ip,
#             user_agent=user_agent,
#             method=method,
#             target_url=target_url,
#             status_code=0,
#             byte_size=0,
#             row_count=0,
#             behavior_score=float(behavior_risk.get("score", 0.0) if isinstance(behavior_risk, dict) else 0.0),
#             drift_score=0.0,
#             tone_risk=float(tone_risk),
#             deception_used=False,
#             session_tainted=bool(session_tainted),
#         )
#         ml = ml_infer(feats)
#         action = _more_severe(action, str(ml.get("ml_action", "allow")))
#         if DEBUG_PREFLIGHT:
#             logger.info("ML policy=%s => action=%s (risk=%s model=%s)", ml, action, ml.get("ml_risk"), ml.get("model"))
#     except Exception:
#         ml = None

#     if action != "allow":
#         logger.warning(
#             "[DECISION] action=%s level=%s score=%s user=%s session=%s device=%s url=%s",
#             action,
#             behavior_risk.get("level"),
#             behavior_risk.get("score"),
#             x_user_id, x_session_id, x_device_id, target_url,
#         )

#     # Optional: force honeypot for huge exports ONLY when explicitly enabled
#     force_hp = os.getenv("FORCE_HONEYPOT_EXPORTS", "0") == "1"
#     lowered = (target_url or "").lower()
#     if force_hp and ("/export/huge" in lowered or "/export/large" in lowered):
#         action = "honeypot"

#     # --- FORCE OVERRIDE (debug/testing) ---
#     forced = (os.getenv("SIDECAR_FORCE_ACTION") or "").strip().lower()
#     if forced:
#         if forced in ("honeypot", "deception"):
#             action = "honeypot"
#             deception_used = True
#         elif forced in ("block",):
#             action = "block"
#             deception_used = False
#         elif forced in ("reauth", "reauth_biometric", "biometric"):
#             action = "biometric"
#             deception_used = False

#     # print(
#     #     "[PRE] user=%s session=%s device=%s url=%s intent_bytes=%s intent_rows=%s behavior_score=%s behavior_level=%s action=%s tainted=%s reauth_ok=%s tone_reason=%s"
#     #     % (
#     #         x_user_id, x_session_id, x_device_id, target_url,
#     #         intent_bytes, intent_rows,
#     #         behavior_risk.get("score"), behavior_risk.get("level"),
#     #         action,
#     #         session_tainted,
#     #         reauth_ok,
#     #         tone_reason,
#     #     )
#     # )

#     if DEBUG_PREFLIGHT:
#         logger.info(
#             "PRE user=%s session=%s device=%s url=%s intent_bytes=%s intent_rows=%s score=%s level=%s action=%s tainted=%s reauth_ok=%s tone_reason=%s",
#             x_user_id, x_session_id, x_device_id, target_url,
#             intent_bytes, intent_rows,
#             behavior_risk.get("score"), behavior_risk.get("level"),
#             action,
#             session_tainted,
#             reauth_ok,
#             tone_reason,
#         )

#     # Hard block
#     if action == "block":
#         return await _emit_and_return(
#             status_code=403,
#             content=_final({
#                 "error": "Blocked by preflight policy",
#                 "next_action": "block",
#                 "tone": incoming_tone,
#                 "tone_reason": tone_reason,
#                 "behavior_score": float(behavior_risk.get("score", 0.0)),
#                 "behavior_level": behavior_risk.get("level", "low"),
#                 "reauth": None,
#             }),
#             effective_tenant_id=effective_tenant_id,
#             x_user_id=str(user_id or ""),
#             x_session_id=str(session_id or ""),
#             x_device_id=str(device_id or ""),
#             target_url=str(payload.target_url),
#             method=method,
#             client_ip=str(client_ip),
#             user_agent=str(user_agent),
#             action="block",
#             behavior_risk=behavior_risk if isinstance(behavior_risk, dict) else {},
#             drift_score=float(drift_score or 0.0),
#             tone_risk=float(tone_risk or 0.0),
#             deception_used=bool(deception_used),
#             session_tainted=bool(session_tainted),
#             risk_score=float(risk_score or 0.0),
#             risk_level=str(risk_level or "high"),
#         )

#     # Honeypot: return deception WITHOUT upstream
#     if action == "honeypot":
#         decision = maybe_apply_deception(
#             risk_score=100.0,
#             risk_level="high",
#             policy_mode="monitor",
#             original_body=b"",
#             content_type="text/csv",
#             resource=target_url,
#             user_id=user_id,
#         )

#         honey_body = ""
#         honey_ct = "text/csv"
#         if decision and getattr(decision, "used", False):
#             honey_body = (decision.body_bytes or b"").decode("utf-8", errors="replace")
#             honey_ct = getattr(decision, "content_type", honey_ct)

#         return await _emit_and_return(
#             status_code=200,  # keep wrapper HTTP 200
#             content=_final({
#                 "status_code": 409,  # <-- IMPORTANT: treat deception as 409 handoff
#                 "headers": {"content-type": honey_ct},
#                 "body": honey_body,
#                 "next_action": "deception",
#                 "tone": incoming_tone,
#                 "tone_reason": tone_reason,
#                 "behavior_score": float(behavior_risk.get("score", 0.0)),
#                 "behavior_level": behavior_risk.get("level", "low"),
#                 "reauth": None,
#                 "risk_score": 100.0,
#                 "risk_level": "high",
#             }),
#             effective_tenant_id=effective_tenant_id,
#             x_user_id=str(user_id or ""),
#             x_session_id=str(session_id or ""),
#             x_device_id=str(device_id or ""),
#             target_url=str(payload.target_url),
#             method=method,
#             client_ip=str(client_ip),
#             user_agent=str(user_agent),
#             action="honeypot",
#             behavior_risk=behavior_risk if isinstance(behavior_risk, dict) else {},
#             drift_score=float(drift_score or 0.0),
#             tone_risk=float(tone_risk or 0.0),
#             deception_used=True,
#             session_tainted=bool(session_tainted),
#             risk_score=100.0,
#             risk_level="high",
#         )


#     # Step-up only if asked AND not yet satisfied
#     if action == "biometric" and behavior_risk.get("level") in ("medium", "high"):
#         if not reauth_ok:
#             return await _emit_and_return(
#                 status_code=401,
#                 content=_final({
#                     "error": "Step-up authentication required.",
#                     "next_action": "reauth_biometric",
#                     "tone": incoming_tone,
#                     "tone_reason": tone_reason,
#                     "behavior_score": behavior_risk.get("score", 0.0),
#                     "behavior_level": behavior_risk.get("level", "low"),
#                     "reauth": {
#                         "type": "webauthn",
#                         "challenge_url": "/auth/webauthn/challenge",
#                         "verify_url": "/auth/webauthn/verify",
#                     },
#                 }),
#                 effective_tenant_id=effective_tenant_id,
#                 x_user_id=str(user_id or ""),
#                 x_session_id=str(session_id or ""),
#                 x_device_id=str(device_id or ""),
#                 target_url=str(payload.target_url),
#                 method=method,
#                 client_ip=str(client_ip),
#                 user_agent=str(user_agent),
#                 action="reauth_biometric",
#                 behavior_risk=behavior_risk if isinstance(behavior_risk, dict) else {},
#                 drift_score=float(drift_score or 0.0),
#                 tone_risk=float(tone_risk or 0.0),
#                 deception_used=bool(deception_used),
#                 session_tainted=bool(session_tainted),
#                 risk_score=float(risk_score or 0.0),
#                 risk_level=str(risk_level or "low"),
#             )

#     # Optional: log reauth succeeded (only when header says ok)
#     if reauth_ok:
#         _log_event(
#             db,
#             tenant_id=effective_tenant_id,
#             user_id=user_id,
#             device_id=device_id,
#             session_id=session_id,
#             source="proxy",
#             event_type="reauth_succeeded",
#             resource=target_url,
#             ip=client_ip,
#             geo=geo_label,
#             details={"method": "X-Reauth-Result header"},
#             client_ip=client_ip,
#             user_agent=user_agent,
#         )
#         # db.commit()
#         maybe_commit(db)

#     # -------------------------
#     # UPSTREAM PROXY (OK TO CALL)
#     # -------------------------
#     t_upstream0 = perf_counter()

#     UPSTREAM_TIMEOUT = float(os.getenv("UPSTREAM_TIMEOUT_SECONDS", "3"))
#     UPSTREAM_RETRY_BUDGET_SECONDS = float(os.getenv("UPSTREAM_RETRY_BUDGET_SECONDS", "5"))
#     UPSTREAM_MAX_ATTEMPTS = int(os.getenv("UPSTREAM_MAX_ATTEMPTS", "4"))
#     RETRY_AFTER_SECONDS = int(os.getenv("UPSTREAM_RETRY_AFTER_SECONDS", "5"))
#     use_stream = bool(SIDECAR_LOADTEST and SIDECAR_BODY_MODE == "none")

#     attempt = 0
#     start_ts = time.time()
#     resp = None
#     last_err = None

#     logger.info(f"[proxy] HTTPX_CLIENT is None? {HTTPX_CLIENT is None}")

#     client = getattr(request.app.state, "upstream_client", None) or HTTPX_CLIENT
#     if client is None:
#         raise RuntimeError("Upstream HTTP client not initialized (lifespan did not run?)")

#     tm.mark("before_upstream")

#     status_code = None
#     resp_headers = {}
#     resp = None

#     while attempt < UPSTREAM_MAX_ATTEMPTS and (time.time() - start_ts) < UPSTREAM_RETRY_BUDGET_SECONDS:
#         attempt += 1
#         try:
#             if use_stream:
#                 async with client.stream(
#                     method=method,
#                     url=target_url,
#                     headers=upstream_headers,
#                     content=body_bytes if body_bytes else None,
#                 ) as sresp:
#                     status_code = sresp.status_code
#                     resp_headers = dict(sresp.headers)

#                     if status_code in (502, 503, 504):
#                         last_err = f"upstream_status_{status_code}"
#                         await asyncio.sleep(min(2 * attempt, 2))
#                         continue

#                     # success (or non-retriable)
#                     break
#             else:
#                 resp = await client.request(
#                     method=method,
#                     url=target_url,
#                     headers=upstream_headers,
#                     content=body_bytes if body_bytes else None,
#                 )

#                 status_code = resp.status_code
#                 resp_headers = dict(resp.headers)

#                 if status_code in (502, 503, 504):
#                     last_err = f"upstream_status_{status_code}"
#                     await asyncio.sleep(min(2 * attempt, 2))
#                     continue

#                 break

#         except httpx.RequestError as exc:
#             last_err = str(exc)
#             await asyncio.sleep(min(2 * attempt, 2))
#             continue

#     tm.mark("after_upstream")

#     # If we never got a usable response, emit “degraded” and tell client to retry later
#     if status_code is None or status_code in (502, 503, 504):
#         _log_event(
#             db,
#             tenant_id=effective_tenant_id,
#             user_id=user_id,
#             device_id=device_id,
#             session_id=session_id,
#             source="proxy",
#             event_type="upstream_unavailable",
#             resource=target_url,
#             ip=client_ip,
#             geo=geo_label,
#             details={
#                 "phase": "failed",
#                 "error": last_err,
#                 "target_url": target_url,
#                 "attempts": attempt,
#                 "retry_window_sec": UPSTREAM_RETRY_BUDGET_SECONDS,
#             },
#             client_ip=client_ip,
#             user_agent=user_agent,
#         )
#         if SIDECAR_COMMIT_MODE == "end":
#             db.commit()

#         return await _emit_and_return(
#             status_code=503,
#             content=_final({
#                 "status_code": 503,
#                 "headers": {"content-type": "application/json"},
#                 "body": "",
#                 "risk_score": 0.0,
#                 "risk_level": "low",
#                 "deception_used": False,
#                 "deception_reason": None,
#             }),
#             effective_tenant_id=effective_tenant_id,
#             x_user_id=str(user_id or ""),
#             x_session_id=str(session_id or ""),
#             x_device_id=str(device_id or ""),
#             target_url=target_url,
#             method=method,
#             client_ip=client_ip,
#             user_agent=user_agent,
#             action="block",
#             behavior_risk=behavior_risk or {},
#             drift_score=float(drift_score or 0.0),
#             tone_risk=float(tone_risk or 0.0),
#             deception_used=False,
#             session_tainted=bool(session_tainted),
#             risk_score=0.0,
#             risk_level="low",
#             row_count=int(row_count or 0),
#             byte_size=int(byte_size or 0),
#         )

#     # status_code and resp_headers are already set above (stream or normal)
#     # status_code = resp.status_code
#     # resp_headers: dict[str, str] = dict(resp.headers)

#     # ---------------------------------------------
#     # Response body handling
#     # ---------------------------------------------
#     # IMPORTANT: "none" must *not* read resp.content.
#     body_mode = os.getenv("SIDECAR_BODY_MODE", "preview").lower()
#     lt_enabled = os.getenv("SIDECAR_LOADTEST", "0").lower() in ("1", "true", "yes")

#     if lt_enabled and body_mode == "none":
#         resp_body_bytes = b""
#         byte_size = int(intent_bytes or 0)
#         row_count = int(intent_rows or 0)
#         content_type = resp_headers.get("content-type", "").lower()

#     elif use_stream:
#         resp_body_bytes = b""
#         byte_size = int(intent_bytes or 0)
#         row_count = int(intent_rows or 0)
#         content_type = resp_headers.get("content-type", "").lower()

#     else:
#         resp_body_bytes = resp.content or b""

#         # Basic metrics
#         byte_size = len(resp_body_bytes)
#         content_type = resp_headers.get("content-type", "").lower()
#         row_count = 0
#         if "text/csv" in content_type and resp_body_bytes:
#             row_count = max(0, resp_body_bytes.count(b"\n") - 1)


#     # -------------------------
#     # TRACE + WATERMARK (always mint, only embed for export-like content)
#     # -------------------------
#     # export_id and trace_id were minted earlier (before export_started) so
#     # export_started/export_completed/headers correlate 1:1.

#     # Public beacon endpoint (dormant by default, logs only if armed)
#     base = os.getenv("SIDECAR_PUBLIC_BASE", "http://127.0.0.1:8000").rstrip("/")
#     beacon_url = f"{base}/proxy/beacon/t/{trace_id}"

#     trace_sig = make_trace_sig(
#         trace_id=trace_id,
#         export_id=export_id,
#         tenant_id=effective_tenant_id,
#     )

#     # Watermark export-like payloads (CSV first)
#     try:
#         if should_watermark(content_type, target_url):
#             resp_body_bytes = apply_watermark_bytes(
#                 resp_body_bytes,
#                 content_type=content_type,
#                 target_url=target_url,
#                 tenant_id=effective_tenant_id,
#                 export_id=export_id,
#                 trace_id=trace_id,
#                 trace_sig=trace_sig,
#                 beacon_url=beacon_url,
#             )

#             # Update metrics after watermarking
#             byte_size = len(resp_body_bytes)
#             if "text/csv" in (content_type or "").lower() and resp_body_bytes:
#                 row_count = max(0, resp_body_bytes.count(b"\n") - 1)
#     except Exception:
#         pass

#     # Decide how much body to return to client (load tests should NOT return full CSV)
#     body_out = ""
#     if SIDECAR_BODY_MODE == "full":
#         # current behavior (slow)
#         try:
#             body_out = resp_body_bytes.decode("utf-8")
#         except UnicodeDecodeError:
#             body_out = resp_body_bytes.decode("latin-1", errors="replace")
#     elif SIDECAR_BODY_MODE == "preview":
#         # first N bytes only (fast)
#         preview = resp_body_bytes[:SIDECAR_BODY_PREVIEW_BYTES]
#         body_out = preview.decode("utf-8", errors="replace")
#     else:
#         # none: return empty body (fastest)
#         body_out = ""


#     # -------------------------
#     # RISK SCORE (AFTER UPSTREAM)
#     # -------------------------
#     policy = get_effective_policy(db)

#     # Basic export risk (rows/bytes/status/resource)
#     base_risk = _compute_basic_risk_score(
#         row_count=row_count,
#         byte_size=byte_size,
#         status_code=status_code,
#         resource=target_url,
#         user_id=user_id,
#         session_id=session_id,
#     )

#     # Tone risk (now that tone is validated, this should usually be small)
#     # If you want "perfectly valid tone => 0", you can set this to 0.0 instead.
#     tone_risk = 0.0

#     # Drift score (baseline/trend engine)
#     drift_score = 0.0
#     if not SIDECAR_LOADTEST:
#         drift_score = update_and_score_drift(
#             db,
#             tenant_id=effective_tenant_id,
#             user_id=user_id,
#             ip=client_ip,
#             byte_size=byte_size,
#             row_count=row_count,
#         )

#     # Combine
#     risk_score = min(100.0, max(0.0, base_risk + tone_risk + drift_score))

#     # Map to level + optional block decision
#     risk_level, should_block = _risk_level_from_policy(
#         score=risk_score,
#         mode=policy.mode,
#         high_threshold=policy.high_threshold,
#         medium_threshold=policy.medium_threshold,
#     )

#     # -------------------------
#     # OPTIONAL: deception on high risk (POST-upstream)
#     # -------------------------
#     deception_used = False
#     deception_reason = None

#     if should_block:
#         decision = maybe_apply_deception(
#             risk_score=risk_score,
#             risk_level=risk_level,
#             policy_mode=policy.mode,
#             original_body=resp_body_bytes,
#             content_type=content_type or "application/octet-stream",
#             resource=target_url,
#             user_id=user_id,
#         )
#         if decision and getattr(decision, "used", False):
#             deception_used = True
#             deception_reason = getattr(decision, "reason", None)
#             resp_body_bytes = getattr(decision, "body_bytes", resp_body_bytes)
#             body_text = resp_body_bytes.decode("utf-8", errors="replace")
#             resp_headers["content-type"] = getattr(decision, "content_type", resp_headers.get("content-type"))

#             # If we served honey, we usually do NOT hard-block the response.
#             # (If you want "block+deceive", remove this line.)
#             should_block = False

#     # # -------------------------
#     # # TRAINING LOG (jsonl)
#     # # -------------------------
#     # try:
#     #     # -------------------------
#     #     # FORCE ACTION (for training / k6 scenarios)
#     #     # -------------------------
#     #     forced = (os.getenv("SIDECAR_FORCE_ACTION") or "").strip().lower()
#     #     if forced:
#     #         if forced in ("honeypot", "deception"):
#     #             action = "honeypot"
#     #             deception_used = True
#     #             status_code = 409  # effective-ish for training label
#     #         elif forced in ("block",):
#     #             action = "block"
#     #             deception_used = False
#     #             status_code = 403
#     #         elif forced in ("reauth", "reauth_biometric", "biometric"):
#     #             action = "reauth_biometric"
#     #             deception_used = False
#     #             status_code = 401

#     #     feats2 = build_policy_features(
#     #         tenant_id=effective_tenant_id,
#     #         user_id=x_user_id,
#     #         session_id=x_session_id,
#     #         device_id=x_device_id,
#     #         client_ip=client_ip,
#     #         user_agent=user_agent,
#     #         method=method,
#     #         target_url=target_url,
#     #         status_code=int(status_code or 0),
#     #         byte_size=int(byte_size or 0),
#     #         row_count=int(row_count or 0),
#     #         behavior_score=float(behavior_risk.get("score", 0.0) if isinstance(behavior_risk, dict) else 0.0),
#     #         drift_score=float(drift_score or 0.0),
#     #         tone_risk=float(tone_risk),
#     #         deception_used=bool(deception_used),
#     #         session_tainted=bool(session_tainted),
#     #     )

#     #     row = dict(feats2)

#     #     # Normalize enforced action into training label space
#     #     # -------------------------
#     #     # LABELS (multi-class)
#     #     # -------------------------

#     #     # Start from the actual enforced policy decision
#     #     label_action_final = "allow"

#     #     a = str(action or "").lower()

#     #     if a in ("block",):
#     #         label_action_final = "block"
#     #     elif a in ("honeypot", "deception"):
#     #         label_action_final = "honeypot"
#     #     elif a in ("biometric", "reauth_biometric"):
#     #         label_action_final = "reauth_biometric"

#     #     # Now override based on response status if needed
#     #     sc = int(status_code or 0)

#     #     if sc == 401:
#     #         label_action_final = "reauth_biometric"
#     #     elif sc in (403, 429):
#     #         label_action_final = "block"
#     #     elif sc == 409:
#     #         # treat 409 as deception redirect/hand-off
#     #         label_action_final = "honeypot"

#     #     row["label_action"] = label_action_final

#     #     # --- k6 ground truth label override (for supervised training) ---
#     #     k6_expected = (request.headers.get("x-k6-expected-action") or "").strip().lower()
#     #     k6_scenario = (request.headers.get("x-k6-scenario") or "").strip()

#     #     if k6_scenario:
#     #         row["k6_scenario"] = k6_scenario

#     #     # If k6 supplies expected action, use it as the label
#     #     if k6_expected:
#     #         row["label_action"] = k6_expected
#     #         row["label_source"] = "k6"
#     #     else:
#     #         row["label_source"] = "policy"

#     #     # Ensure deception_used is consistent with honeypot label
#     #     row["deception_used"] = bool(deception_used) or (label_action_final == "honeypot")

#     #     if 200 <= sc < 300:
#     #         row["label_outcome"] = "allowed"
#     #     elif sc in (401, 403, 429):
#     #         row["label_outcome"] = "blocked"
#     #     elif 400 <= sc < 500:
#     #         row["label_outcome"] = "denied"
#     #     elif sc >= 500:
#     #         row["label_outcome"] = "error"
#     #     else:
#     #         row["label_outcome"] = "other"

#     #     row["synthetic"] = bool(SIDECAR_LOADTEST)
        
#     #     row["schema_version"] = "policy_v2"

#     #     # required fields for training/validation
#     #     row["risk_score"] = float(risk_score or 0.0)
#     #     row["risk_level"] = str(risk_level or "low")
#     #     if isinstance(behavior_risk, dict):
#     #         row["behavior_level"] = str(behavior_risk.get("level") or behavior_risk.get("behavior_level") or "unknown")
#     #     else:
#     #         row["behavior_level"] = "unknown"

#     #     # raw/request fields required by validator
#     #     row.update({
#     #         "ts_utc": datetime.utcnow().isoformat() + "Z",
#     #         "target_url": str(target_url),
#     #         "method": str(method),
#     #         "status_code": int(status_code or 0),
#     #         "client_ip": str(client_ip),
#     #         "user_agent": str(user_agent),

#     #         # identity/join keys (string-safe)
#     #         "tenant_id": str(effective_tenant_id or ""),
#     #         "user_id": str(x_user_id or ""),
#     #         "device_id": str(x_device_id or ""),
#     #         "session_id": str(x_session_id or ""),
#     #     })

#     #     row["debug_action"] = str(action or "")

#     #     _policy_train_emit_row(row)
#     # except Exception:
#     #     pass


#     # -------------------------
#     # EXPORT ROW + RISK FINDING
#     # -------------------------
#     # export_id = str(uuid.uuid4())

#     # Always safe defaults so later code never crashes (even in loadtest)
#     export_obj = None

#     SKIP_FILE_HASH = os.getenv("SIDECAR_SKIP_FILE_HASH", "0") == "1"
#     file_hash = None
#     if resp_body_bytes and not SKIP_FILE_HASH:
#         file_hash = hashlib.sha256(resp_body_bytes).hexdigest()

#     # ✅ Loadtest: NO SQL writes, NO event logging, NO commits
#     if not SIDECAR_LOADTEST:
#         tm.mark("before_db")

#         export_obj = Export(
#             export_id=export_id,
#             tenant_id=effective_tenant_id,
#             user_id=user_id,
#             session_id=session_id,
#             resource=target_url,
#             row_count=row_count if row_count > 0 else None,
#             byte_size=byte_size if byte_size > 0 else None,
#             file_hash=file_hash,
#             created_at_utc=datetime.utcnow(),
#             ip=client_ip,
#             user_agent=user_agent,
#             is_deception=deception_used,
#             deception_reason=deception_reason,
#         )
#         db.add(export_obj)

#         # best-effort: never break request because risk engine exploded
#         try:
#             create_risk_finding_for_export(export_obj)
#         except Exception:
#             pass

#         _log_event(
#             db,
#             tenant_id=effective_tenant_id,
#             user_id=user_id,
#             device_id=device_id,
#             session_id=session_id,
#             source="proxy",
#             event_type="export_completed",
#             resource=target_url,
#             ip=client_ip,
#             geo=geo_label,
#             details={
#                 "phase": "completed",
#                 "status_code": int(status_code),
#                 "row_count": int(row_count),
#                 "byte_size": int(byte_size),
#                 "behavior_score": float(behavior_risk.get("score", 0.0)),
#                 "behavior_level": str(behavior_risk.get("level", "low")),
#                 "next_action": str(behavior_action),
#                 "risk_score": float(risk_score),
#                 "risk_level": str(risk_level),
#                 "deception_used": bool(deception_used),
#                 "deception_reason": deception_reason,
#                 "export_id": export_id,
#                 "trace_id": trace_id,
#                 "trace_sig": trace_sig,
#                 "beacon_url": beacon_url,
#                 "risk_level": risk_level,
#                 "should_block_initial": bool(should_block),
#             },
#             client_ip=client_ip,
#             user_agent=user_agent,
#         )

#         # commit behavior
#         if SIDECAR_COMMIT_MODE == "end":
#             db.commit()
#         else:
#             db.flush()

#         tm.mark("after_db")

#     # ------------------------------
#     # BEACON AUTO-ARM (V2 behavior)
#     # ------------------------------
#     if SIDECAR_BEACON_AUTO_ARM:
#         try:
#             # redis_client = getattr(request.app.state, "redis", None)
#             if redis_client and trace_id:
#                 # IMPORTANT: use the SAME tenant derivation as arm+hit endpoints
#                 tenant_id = str(effective_tenant_id or "")
#                 if not tenant_id:
#                     if test_mode:
#                         tenant_id = "demo-tenant"
#                     else:
#                         # no tenant => no arming
#                         tenant_id = ""


#                 hostile = (
#                     bool(deception_used)
#                     or (str(behavior_action).lower() in ("honeypot", "deception", "block"))
#                     or (str(risk_level).lower() in ("high", "critical"))
#                 )

#                 if hostile:
#                     ttl_days = int(os.getenv("SIDECAR_BEACON_TTL_DAYS_DEFAULT", "365"))
#                     ttl_s = max(60, ttl_days * 86400)

#                     armed_key = f"beacon:armed:{tenant_id}:{trace_id}"
#                     await redis_client.setex(armed_key, ttl_s, "1")
#                     await redis_client.setex(
#                         f"sess:revoked:{tenant_id}:{session_id}",
#                         ttl_s,
#                         "1"
#                     )

#                     if not SIDECAR_LOADTEST:
#                         _log_event(
#                             db,
#                             tenant_id=tenant_id,
#                             user_id=user_id,
#                             device_id=device_id,
#                             session_id=session_id,
#                             source="beacon",
#                             event_type="beacon_armed_auto",
#                             resource=trace_id,
#                             ip=client_ip,
#                             geo=geo_label,
#                             client_ip=client_ip,
#                             user_agent=user_agent,
#                             details={
#                                 "trace_id": trace_id,
#                                 "ttl_days": ttl_days,
#                                 "reason": "auto_arm_hostile",
#                                 "risk_level": risk_level,
#                                 "risk_score": float(behavior_risk.get("score", 0.0) if isinstance(behavior_risk, dict) else 0.0),
#                                 "behavior_action": behavior_action,
#                                 "deception_used": bool(deception_used),
#                                 "deception_reason": deception_reason,
#                             },
#                         )
#                         maybe_commit(db)
#         except Exception:
#             pass

#     # keep timings outside so it runs in BOTH modes
#     timings["upstream_ms"] = round((perf_counter() - t_upstream0) * 1000, 2)

#     # ---- LOADTEST timing line (prints for BOTH 200 and non-200 success paths) ----
#     if _lt_enabled() and _lt_trace_enabled():
#         try:
#             payload_t = {
#                 "t_total_ms": round(tm.ms_total(), 2),
#                 "t_parse_ms": round(tm.ms_since("start", "after_parse"), 2) if "after_parse" in tm.marks else None,
#                 "t_intent_ms": round(tm.ms_since("after_parse", "after_intent"), 2) if "after_intent" in tm.marks else None,
#                 "t_upstream_ms": round(tm.ms_since("before_upstream", "after_upstream"), 2) if ("before_upstream" in tm.marks and "after_upstream" in tm.marks) else None,
#                 "t_risk_ms": round(tm.ms_since("before_risk", "after_risk"), 2) if ("before_risk" in tm.marks and "after_risk" in tm.marks) else None,
#                 "t_db_ms": round(tm.ms_since("before_db", "after_db"), 2) if ("before_db" in tm.marks and "after_db" in tm.marks) else None,
#                 "status": int(status_code) if "status_code" in locals() else None,
#                 "target": (target_url or "")[:120],
#             }
#             logger.warning("SIDECAR_TIMING %s", json.dumps(payload_t))
#             print("SIDECAR_TIMING " + json.dumps(payload_t), flush=True)
#         except Exception:
#             pass
#     # ---- end timing line ----
#     envelope_headers = dict(resp_headers or {})
#     envelope_headers.update({
#         "X-Export-Id": export_id or "",
#         "X-Trace-Id": trace_id or "",
#         "X-Trace-Sig": trace_sig or "",
#         "X-Beacon-Url": beacon_url or "",
#         "X-Risk-Level": risk_level or "",
#     })


#     return await _emit_and_return(
#         status_code=200,
#         content=_final({
#             "status_code": status_code,   # keep this (emit uses it as inner_sc)
#             "headers": envelope_headers,
#             "body": body_out,
#             "risk_score": risk_score,
#             "risk_level": risk_level,
#             "deception_used": deception_used,
#             "deception_reason": deception_reason,
#         }),
#         effective_tenant_id=effective_tenant_id,
#         x_user_id=user_id,
#         x_session_id=session_id,
#         x_device_id=device_id,
#         target_url=target_url,
#         method=method,
#         client_ip=client_ip,
#         user_agent=user_agent,
#         action=action,  # IMPORTANT: this is what drives label_action_final
#         behavior_risk=behavior_risk or {},
#         drift_score=float(drift_score or 0.0),
#         tone_risk=float(tone_risk or 0.0),
#         deception_used=bool(deception_used),
#         session_tainted=bool(session_tainted),
#         risk_score=float(risk_score or 0.0),
#         risk_level=str(risk_level or "low"),
#         row_count=int(row_count or 0),
#         byte_size=int(byte_size or 0),
#     )


@router.get("/replay/session/{session_id}")
def replay_session_timeline(
    session_id: str,
    db: Session = Depends(get_db),
):
    """
    Return a simple forensic bundle for a session:
      - events
      - exports
      - risk findings
      - tones
    The UI can turn this into a timeline.
    """
    events = (
        db.query(Event)
        .filter(
            Event.session_id == session_id,
            Event.tenant_id == TENANT_ID,
        )
        .order_by(Event.timestamp_utc)
        .all()
    )

    exports = (
        db.query(Export)
        .filter(
            Export.session_id == session_id,
            Export.tenant_id == TENANT_ID,
        )
        .order_by(Export.created_at_utc)
        .all()
    )

    risk_findings = (
        db.query(RiskFinding)
        .filter(
            RiskFinding.session_id == session_id,
            RiskFinding.tenant_id == TENANT_ID,
        )
        .order_by(RiskFinding.created_at_utc)
        .all()
    )

    tones = (
        db.query(EphemeralSessionKey)
        .filter(EphemeralSessionKey.session_id == session_id)
        .order_by(EphemeralSessionKey.inserted_at)
        .all()
    )

    return {
        "session_id": session_id,
        "events": [
            {
                "id": evt.id,
                "type": evt.event_type,
                "resource": evt.resource,
                "ip": evt.ip,
                "geo": evt.geo,
                "timestamp_utc": evt.timestamp_utc,
                "details": evt.details,
                "client_ip": getattr(evt, "client_ip", None),
                "user_agent": getattr(evt, "user_agent", None),
            }
            for evt in events
        ],
        "exports": [
            {
                "id": ex.id,
                "export_id": ex.export_id,
                "resource": ex.resource,
                "row_count": ex.row_count,
                "byte_size": ex.byte_size,
                "file_hash": ex.file_hash,
                "created_at_utc": ex.created_at_utc,
                "ip": ex.ip,
                "user_agent": ex.user_agent,
                "is_deception": ex.is_deception,
                "deception_reason": ex.deception_reason,
            }
            for ex in exports
        ],
        "risk_findings": [
            {
                "id": rf.id,
                "export_id": rf.export_id,
                "resource": rf.resource,
                "risk_score": rf.risk_score,
                "risk_level": rf.risk_level,
                "reason": rf.reason,
                "created_at_utc": rf.created_at_utc,
            }
            for rf in risk_findings
        ],
        "tones": [
            {
                "id": t.id,
                "user_id": t.user_id,
                "device_id": t.device_id,
                "user_tone": t.user_tone,
                "combined_tone": t.combined_tone,
                "expires_at": t.expires_at,
                "inserted_at": t.inserted_at,
            }
            for t in tones
        ],
    }

from starlette.responses import Response

@router.get("/beacon/t/{trace_id}")
async def beacon_hit(trace_id: str, request: Request, db: Session = Depends(get_db)):
    """
    Dormant beacon endpoint. Only logs if armed.
    """
    rc = getattr(request.app.state, "redis", None)
    if not rc:
        return Response(status_code=204)

    tenant_id = (
        request.headers.get("X-Org-Id")
        or request.headers.get("Org-Id")
        or os.getenv("SIDECAR_DEFAULT_TENANT")
        or TENANT_ID
        or "default"
    ).strip()

    print("BEACON redis?", bool(rc), "tenant_id", tenant_id, "trace_id", trace_id)
    armed_key = f"beacon:armed:{tenant_id}:{trace_id}"

    try:
        armed = bool(await rc.get(armed_key))
    except Exception:
        armed = False

    if not armed:
        return Response(status_code=204)

    # Prefer X-Forwarded-For (attacker simulation) then fall back to request.client.host
    xff = request.headers.get("x-forwarded-for") or request.headers.get("X-Forwarded-For")
    client_ip = None
    if xff:
        client_ip = xff.split(",")[0].strip()
    if not client_ip:
        # ---------------------------
        # CLIENT IP (safe XFF handling)
        # ---------------------------
        peer_ip = request.client.host if request.client else None

        TRUST_XFF = os.getenv("SIDECAR_TRUST_XFF", "0") == "1"
        trusted = {
            x.strip()
            for x in os.getenv("SIDECAR_TRUSTED_PROXIES", "127.0.0.1").split(",")
            if x.strip()
        }

        client_ip = peer_ip

        # Only trust XFF if the request came from a trusted proxy
        if TRUST_XFF and peer_ip and peer_ip in trusted:
            xff = (request.headers.get("X-Forwarded-For") or "").strip()
            if xff:
                # first IP in list is the original client
                client_ip = xff.split(",")[0].strip() or peer_ip
            else:
                xreal = (request.headers.get("X-Real-IP") or "").strip()
                if xreal:
                    client_ip = xreal


    ua = request.headers.get("user-agent")
    referer = request.headers.get("referer")
    geo = lookup_geo_label(client_ip)

    _log_event(
        db,
        tenant_id=tenant_id,
        user_id=None,
        device_id=None,
        session_id=None,
        source="beacon",
        event_type="beacon_hit",
        resource=trace_id,
        ip=client_ip,
        geo=geo,
        client_ip=client_ip,
        user_agent=ua,
        details={
            "trace_id": trace_id,
            "armed": True,
            "user_agent": ua,
            "referer": referer,
        },
    )

    rf = RiskFinding(
        tenant_id=tenant_id,
        user_id=None,
        session_id=None,
        export_id=None,
        resource=f"/proxy/beacon/t/{trace_id}",
        risk_score=100,
        risk_level="critical",
        reason=json.dumps([
            "Beacon hit detected",
            f"trace_id={trace_id}",
            f"ip={client_ip}",
            f"user_agent={ua}",
            f"referer={referer}" if referer else "referer=<none>",
        ]),
        created_at_utc=datetime.utcnow(),
        is_acknowledged=False,
        acknowledged_by=None,
        acknowledged_at_utc=None,
    )
    db.add(rf)

    try:
        db.commit()
    except Exception:
        db.rollback()
        raise

    return Response(status_code=204)


class ArmBeaconRequest(BaseModel):
    trace_id: str
    ttl_days: int = 365  # default: 1 year for confirmed hostile

@router.post("/beacon/arm")
async def arm_beacon(req: ArmBeaconRequest, request: Request, db: Session = Depends(get_db)):
    rc = getattr(request.app.state, "redis", None)
    if not rc:
        raise HTTPException(status_code=503, detail="redis_required")

    tenant_id = (
        request.headers.get("X-Org-Id")
        or request.headers.get("Org-Id")
        or os.getenv("SIDECAR_DEFAULT_TENANT")
        or TENANT_ID
        or "default"
    ).strip()

    # You arm *one specific trace_id*, so you never enable random beacons.
    armed_key = f"beacon:armed:{tenant_id}:{req.trace_id}"
    ttl_s = max(60, int(req.ttl_days) * 86400)

    await rc.setex(armed_key, ttl_s, "1")

    _log_event(
        db,
        tenant_id=tenant_id,
        user_id=None,
        device_id=None,
        session_id=None,
        source="beacon",
        event_type="beacon_armed",
        resource=req.trace_id,
        ip=request.client.host if request.client else None,
        geo=None,
        details={"trace_id": req.trace_id, "ttl_days": req.ttl_days},
        user_agent=request.headers.get("user-agent"),
    )
    try:
        db.commit()
    except Exception:
        db.rollback()
        raise

    return {"ok": True, "trace_id": req.trace_id, "ttl_days": req.ttl_days}
