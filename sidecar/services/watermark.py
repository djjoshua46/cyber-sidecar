# sidecar/watermark.py
from __future__ import annotations

import os
import hmac
import hashlib

TRACE_HMAC_SECRET = os.getenv("SIDECAR_TRACE_HMAC_SECRET", "dev-secret-change-me").encode("utf-8")

def make_trace_sig(*, trace_id: str, export_id: str, tenant_id: str) -> str:
    """
    Stable signature proving this trace was minted by Sidecar.
    """
    msg = f"{tenant_id}|{export_id}|{trace_id}".encode("utf-8")
    return hmac.new(TRACE_HMAC_SECRET, msg, hashlib.sha256).hexdigest()

def should_watermark(content_type: str, target_url: str) -> bool:
    ct = (content_type or "").lower()
    u = (target_url or "").lower()
    # Start with CSV/text exports. Expand later (json, xlsx, pdf, etc.).
    if "text/csv" in ct:
        return True
    if "application/csv" in ct:
        return True
    if "download" in u or "export" in u:
        # fallback heuristic (safe) if CT is missing
        return True
    return False

def apply_watermark_csv_bytes(
    data: bytes,
    *,
    tenant_id: str,
    export_id: str,
    trace_id: str,
    trace_sig: str,
    beacon_url: str,
    add_trace_columns: bool = True,
) -> bytes:
    """
    CSV watermarking:
      - Adds a comment header line with trace metadata
      - Optionally inserts trace columns into the header + each row
    """
    if not data:
        return data

    text = data.decode("utf-8", errors="replace")
    lines = text.splitlines()

    header_line = f"# trace_id={trace_id} trace_sig={trace_sig} export_id={export_id} tenant_id={tenant_id} beacon={beacon_url}"
    if not lines:
        return (header_line + "\n").encode("utf-8")

    # Prepend header line (easy forensic visibility)
    # NOTE: Some CSV parsers choke on comment lines.
    # If your environment can't accept it, set SIDECAR_WM_COMMENT=0.
    if os.getenv("SIDECAR_WM_COMMENT", "1") in ("1", "true", "yes"):
        lines.insert(0, header_line)

    # Add explicit columns too (stronger + machine-friendly)
    if add_trace_columns and lines:
        # Find the first non-comment line as actual CSV header
        idx = 0
        while idx < len(lines) and lines[idx].startswith("#"):
            idx += 1
        if idx < len(lines):
            csv_header = lines[idx]
            cols = csv_header.split(",")
            # Avoid duplicating if already present
            if "_trace_id" not in cols:
                cols += ["_trace_id", "_trace_sig", "_beacon"]
                lines[idx] = ",".join(cols)

                # Append values to each data row (very simple CSV; if you need RFC-compliant, we can use csv module)
                for r in range(idx + 1, len(lines)):
                    if not lines[r].strip() or lines[r].startswith("#"):
                        continue
                    lines[r] = lines[r] + f",{trace_id},{trace_sig},{beacon_url}"

    out = "\n".join(lines) + "\n"
    return out.encode("utf-8")

def apply_watermark_bytes(
    data: bytes,
    *,
    content_type: str,
    target_url: str,
    tenant_id: str,
    export_id: str,
    trace_id: str,
    trace_sig: str,
    beacon_url: str,
) -> bytes:
    ct = (content_type or "").lower()
    if "text/csv" in ct or "application/csv" in ct or should_watermark(ct, target_url):
        add_cols = os.getenv("SIDECAR_WM_COLUMNS", "1") in ("1", "true", "yes")
        return apply_watermark_csv_bytes(
            data,
            tenant_id=tenant_id,
            export_id=export_id,
            trace_id=trace_id,
            trace_sig=trace_sig,
            beacon_url=beacon_url,
            add_trace_columns=add_cols,
        )
    return data
