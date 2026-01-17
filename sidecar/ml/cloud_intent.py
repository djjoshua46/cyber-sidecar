from __future__ import annotations

import os
import re
from dataclasses import dataclass
from typing import Any, Dict
from urllib.parse import urlparse, parse_qs

try:
    import yaml
except Exception:  # pragma: no cover
    yaml = None


@dataclass(frozen=True)
class CloudIntent:
    cloud_provider: str = "unknown"      # aws|azure|gcp|unknown
    cloud_plane: str = "unknown"         # identity|control|data|unknown
    cloud_service: str = "unknown"       # iam|sts|s3|ec2|kms|cloudtrail|...
    cloud_action_family: str = "unknown" # enumeration|mutation|credential_mgmt|persistence|privilege_escalation|logging_change|key_mgmt|exfil|...
    cloud_sensitivity: str = "low"       # low|med|high|critical
    cloud_operation: str = ""            # best-effort (e.g., AWS Action)
    cloud_is_cloud: int = 0              # 1 if we think this is cloud API traffic
    # Kill-chain hints (booleans)
    ato_priv_escalation_hint: int = 0
    ato_persistence_hint: int = 0
    ato_defense_evasion_hint: int = 0
    ato_exfil_hint: int = 0


def _load_rules() -> Dict[str, Any]:
    # Allow override path for deployments
    rules_path = os.getenv("SIDECAR_CLOUD_INTENT_RULES", "")
    if not rules_path:
        # default relative location
        rules_path = os.path.join(os.path.dirname(__file__), "cloud_intent_rules.yaml")

    if not yaml:
        return {}

    try:
        with open(rules_path, "r", encoding="utf-8") as f:
            return yaml.safe_load(f) or {}
    except Exception:
        return {}


_RULES = _load_rules()


def classify_cloud_intent(target_url: str, method: str = "", user_agent: str = "") -> Dict[str, Any]:
    """
    Best-effort classification based on URL + query params.
    Returns a dict of stable, trainable features.
    """
    try:
        u = urlparse(target_url or "")
    except Exception:
        u = None

    host = (u.hostname if u else "") or ""
    path = (u.path if u else "") or ""
    qs = parse_qs((u.query if u else "") or "")

    # Default result
    intent = CloudIntent()

    # No rules loaded -> return empty-ish intent
    providers = (_RULES.get("providers") or {}) if isinstance(_RULES, dict) else {}
    aws = providers.get("aws") if isinstance(providers, dict) else None
    if not aws or not host:
        return intent.__dict__

    # Provider detect (AWS)
    suffixes = aws.get("host_suffixes", []) or []
    is_aws = any(host.endswith(sfx) for sfx in suffixes)
    if not is_aws:
        return intent.__dict__

    cloud_provider = "aws"
    cloud_is_cloud = 1

    # Identify AWS service best-effort:
    # e.g., iam.amazonaws.com, sts.us-east-1.amazonaws.com, s3.amazonaws.com
    service = host.split(".")[0].lower() if "." in host else "unknown"

    # Query API style: Action=...
    action = ""
    if "Action" in qs and qs["Action"]:
        action = str(qs["Action"][0] or "").strip()
    elif "action" in qs and qs["action"]:
        action = str(qs["action"][0] or "").strip()

    plane = "unknown"
    family = "unknown"
    sensitivity = "low"

    # S3 REST heuristics
    if service.startswith("s3"):
        plane = "data"
        cloud_service = "s3"
        # Heuristic: GETs are reads, PUT/POST/DELETE are writes
        m = (method or "").upper()
        if m == "GET":
            family = "data_read"
            sensitivity = "high"
            # exfil hint if it looks like object download patterns
            ato_exfil_hint = 1
        elif m in ("PUT", "POST"):
            family = "data_write"
            sensitivity = "med"
            ato_exfil_hint = 0
        elif m == "DELETE":
            family = "data_write"
            sensitivity = "high"
            ato_exfil_hint = 0
        else:
            family = "unknown"
            ato_exfil_hint = 0

        out = CloudIntent(
            cloud_provider=cloud_provider,
            cloud_plane=plane,
            cloud_service=cloud_service,
            cloud_action_family=family,
            cloud_sensitivity=sensitivity,
            cloud_operation="",
            cloud_is_cloud=cloud_is_cloud,
            ato_exfil_hint=ato_exfil_hint,
        )
        return out.__dict__

    # Query API mapping via Action rules
    if action:
        amap = aws.get("action_map", []) or []
        for rule in amap:
            try:
                pat = rule.get("match", "")
                if not pat:
                    continue
                if re.search(pat, action):
                    service = rule.get("service", service) or service
                    plane = rule.get("plane", "unknown") or "unknown"
                    family = rule.get("family", "unknown") or "unknown"
                    sensitivity = rule.get("sensitivity", "low") or "low"
                    break
            except Exception:
                continue

    # If we still don't know, at least mark likely control-plane for known query-api services
    if plane == "unknown":
        qsvc = set((aws.get("query_api_services") or []))
        if service in qsvc:
            plane = "control"

    # Kill-chain hints
    ato_priv = 1 if family == "privilege_escalation" else 0
    ato_persist = 1 if family == "persistence" else 0
    ato_evasion = 1 if family == "logging_change" else 0
    ato_exfil = 1 if family in ("data_read", "exfil") and plane == "data" else 0

    out = CloudIntent(
        cloud_provider=cloud_provider,
        cloud_plane=plane,
        cloud_service=service or "unknown",
        cloud_action_family=family,
        cloud_sensitivity=sensitivity,
        cloud_operation=action or "",
        cloud_is_cloud=cloud_is_cloud,
        ato_priv_escalation_hint=ato_priv,
        ato_persistence_hint=ato_persist,
        ato_defense_evasion_hint=ato_evasion,
        ato_exfil_hint=ato_exfil,
    )
    return out.__dict__
