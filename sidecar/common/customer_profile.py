import json, os
from functools import lru_cache
from typing import Dict, Any, Optional, List

PROFILE_PATH_DEFAULT = "/etc/sidecar/customer_profile.json"

@lru_cache(maxsize=1)
def load_profile() -> Dict[str, Any]:
    path = os.getenv("SIDECAR_CUSTOMER_PROFILE", PROFILE_PATH_DEFAULT)
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}

def pick_first_header(headers, names: List[str]) -> Optional[str]:
    for n in names:
        v = headers.get(n)
        if v:
            return str(v)
    return None

def extract_identity_from_headers(headers) -> Dict[str, str]:
    p = load_profile()
    fields = (((p.get("identity") or {}).get("fields")) or {})
    out = {}
    for canonical in ("tenant_id", "user_id", "session_id", "device_id"):
        candidates = fields.get(canonical) or []
        out[canonical] = pick_first_header(headers, candidates) or ""
    return out

def outbound_header_name(canonical: str) -> str:
    p = load_profile()
    m = (p.get("outbound_headers") or {})
    return m.get(canonical) or canonical

def switch(name: str, default: bool=False) -> bool:
    p = load_profile()
    s = (p.get("switches") or {})
    v = s.get(name, default)
    return bool(v)

def fail_mode(control: str, default: str="closed") -> str:
    p = load_profile()
    fm = (p.get("fail_modes") or {})
    v = (fm.get(control) or default).lower()
    return v if v in ("open", "closed") else default

def reauth_proof_header_name() -> str:
    p = load_profile()
    r = (p.get("reauth") or {})
    return r.get("proof_header") or "X-Reauth-Proof"

def reauth_jwks_url() -> str:
    p = load_profile()
    r = (p.get("reauth") or {})
    return r.get("jwks_url") or ""
