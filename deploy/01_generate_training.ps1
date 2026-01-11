Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$REPO = "C:\Cybersecurity\cyber-sidecar"
$COMPOSE = Join-Path $REPO "deploy\docker-compose.local.yml"
$BASE = "http://127.0.0.1:8085"

# Where to save the generated dataset (host path)
$OUT_DIR = Join-Path $REPO "training"
$STAMP = (Get-Date).ToString("yyyyMMdd_HHmmss")
$OUT_PATH = Join-Path $OUT_DIR "generated_training_$STAMP.jsonl"

# Request payload file (avoids curl JSON escaping issues)
$REQ_PATH = Join-Path $PSScriptRoot "req_small.json"
@'
{
  "target_url": "http://fake_backend:8099/export/small.csv",
  "method": "GET",
  "headers": {},
  "body": null
}
'@ | Set-Content -Path $REQ_PATH -Encoding utf8

function Wait-Healthy {
  for ($i=0; $i -lt 45; $i++) {
    try {
      $r = iwr "$BASE/health" -UseBasicParsing -TimeoutSec 2
      if ($r.StatusCode -eq 200) { return }
    } catch { Start-Sleep 1 }
  }
  throw "sidecar not healthy"
}

function Recreate-Sidecar {
  # recreate ONLY sidecar so env changes apply
  docker compose -f $COMPOSE up -d --no-deps --force-recreate sidecar | Out-Null
  Wait-Healthy
}

function Has-Prop($o, $name) {
  return ($null -ne $o) -and ($o.PSObject.Properties.Name -contains $name)
}

function Get-Prop($o, $name, $default=$null) {
  if (Has-Prop $o $name) { return $o.$name }
  return $default
}

function Get-Path($o, [string[]]$path, $default=$null) {
  $cur = $o
  foreach ($p in $path) {
    if ($null -eq $cur) { return $default }
    if (-not (Has-Prop $cur $p)) { return $default }
    $cur = $cur.$p
  }
  if ($null -eq $cur) { return $default }
  return $cur
}

function Curl-Proxy([hashtable]$Headers) {
  $args = @("-sS", "$BASE/proxy/http")
  foreach ($k in $Headers.Keys) {
    $args += @("-H", ("{0}: {1}" -f $k, $Headers[$k]))
  }
  $args += @("--data-binary", "@$REQ_PATH")

  $raw = & curl.exe @args
  if (-not $raw) { return $null }

  try { return ($raw | ConvertFrom-Json) } catch { return $null }
}

function Write-Row([string]$case_id, [string]$label, $obj, [hashtable]$sentHeaders) {
    $riskLevel     = Get-Prop $obj "risk_level" (Get-Path $obj @("reason_detail","risk_level") $null)
    $riskScore     = Get-Prop $obj "risk_score" (Get-Path $obj @("reason_detail","risk_score") $null)
    $behaviorLevel = Get-Path $obj @("reason_detail","behavior_level") $null
    $behaviorScore = Get-Path $obj @("reason_detail","behavior_score") $null
    $traceId       = Get-Path $obj @("headers","X-Trace-Id") $null
    $exportId      = Get-Path $obj @("headers","X-Export-Id") $null

    $rec = [ordered]@{
        ts = (Get-Date).ToString("o")
        case_id = $case_id
        label = $label
        ok_json = [bool]($obj -ne $null)

        # decision + why (safe reads)
        error = Get-Prop $obj "error" $null
        decision_action = Get-Prop $obj "decision_action" $null
        reason_codes = Get-Prop $obj "reason_codes" @()
        status_outer = Get-Prop $obj "status_code_outer" $null
        status_effective = Get-Prop $obj "status_code_effective" $null

        # may exist on allow (and sometimes nested)
        risk_level = $riskLevel
        risk_score = $riskScore
        behavior_level = $behaviorLevel
        behavior_score = $behaviorScore

        # tone + trace headers
        tone_returned = Get-Prop $obj "tone" $null
        trace_id = $traceId
        export_id = $exportId

        # what we actually sent (useful for ML + audits)
        sent_headers = $sentHeaders
    }

  ($rec | ConvertTo-Json -Depth 12 -Compress) + "`n" | Add-Content -Path $OUT_PATH -Encoding utf8
}

# Base “customer” identity headers (your canonical ones)
$BASE_HEADERS = @{
  "Content-Type" = "application/json"
  "X-Org-Id"     = "org-1"
  "X-User-Id"    = "user-1"
  "X-Session-Id" = "sess-1"
  "X-Device-Id"  = "dev-1"
  "User-Agent"   = "customer/1.0"
}

# Scenario runners (each returns one row)
function Do-AllowFlow {
  $h1 = @{} + $BASE_HEADERS
  $obj1 = Curl-Proxy $h1
  Write-Row "allow_get_tone" "expect_tone_required" $obj1 $h1

  $tone = $obj1.tone
  $h2 = @{} + $BASE_HEADERS
  $h2["X-Tone"] = $tone
  $obj2 = Curl-Proxy $h2
  Write-Row "allow_with_tone" "expect_allow" $obj2 $h2
}

function Do-MissingIdentity {
  $h = @{
    "Content-Type"="application/json"
    "X-Org-Id"="org-1"
    "User-Agent"="customer/1.0"
  }
  $obj = Curl-Proxy $h
  Write-Row "missing_identity" "expect_identity_required" $obj $h
}

function Do-DeviceSwapReplay {
  $h1 = @{} + $BASE_HEADERS
  $obj1 = Curl-Proxy $h1
  Write-Row "replay_get_tone" "expect_tone_required" $obj1 $h1

  $tone = $obj1.tone
  $h2 = @{} + $BASE_HEADERS
  $h2["X-Tone"] = $tone
  $h2["X-Device-Id"] = "dev-999"
  $obj2 = Curl-Proxy $h2
  Write-Row "device_swap" "expect_tone_invalid" $obj2 $h2
}

function Do-ReauthSpoof {
  $h = @{} + $BASE_HEADERS
  $h.Remove("X-User-Id")
  $h.Remove("X-Session-Id")
  $h.Remove("X-Device-Id")
  $h["X-Reauth-Result"] = "ok"
  $obj = Curl-Proxy $h
  Write-Row "reauth_spoof" "expect_tone_required_or_identity_required" $obj $h
}

function Do-UAChangeAllowed {
  $h1 = @{} + $BASE_HEADERS
  $obj1 = Curl-Proxy $h1
  Write-Row "ua_get_tone" "expect_tone_required" $obj1 $h1

  $tone = $obj1.tone
  $h2 = @{} + $BASE_HEADERS
  $h2["X-Tone"] = $tone
  $h2["User-Agent"] = "attacker/9.9"
  $obj2 = Curl-Proxy $h2
  Write-Row "ua_change" "expect_allow_or_stepup" $obj2 $h2
}

# ===== Main generation plan =====
# We generate a mix of:
# - realistic “good user” allow flows
# - common tampering attempts (missing identity, device swap, spoof reauth)
# - drift-like changes (UA)
#
# Then we do forced-action runs to balance labels for ML.

$TOTAL_PER_PHASE = 5000   # bump this to 50000+ per phase for big datasets

Write-Host "Writing generated dataset to: $OUT_PATH"
Write-Host "REQ file: $REQ_PATH"
Write-Host "Phase 1: Realistic mixed traffic ($TOTAL_PER_PHASE rows-ish)..."

for ($i=0; $i -lt $TOTAL_PER_PHASE; $i++) {
  $pick = Get-Random -Minimum 1 -Maximum 101
  if ($pick -le 45) { Do-AllowFlow; continue }
  if ($pick -le 65) { Do-DeviceSwapReplay; continue }
  if ($pick -le 80) { Do-MissingIdentity; continue }
  if ($pick -le 90) { Do-ReauthSpoof; continue }
  Do-UAChangeAllowed
}

# ===== Forced balancing phases (optional but strongly recommended) =====
# Requires docker-compose env line:
#   SIDECAR_FORCE_ACTION: ${SIDECAR_FORCE_ACTION:-}
#
# These phases create “clean labels” for deep training: allow/block/honeypot/reauth.

$FORCED = @("allow","block","honeypot","reauth_biometric")

foreach ($action in $FORCED) {
  Write-Host "Phase 2: Forced action = $action ($TOTAL_PER_PHASE allow-like calls)..."
  $env:SIDECAR_FORCE_ACTION = $action
  Recreate-Sidecar

  for ($j=0; $j -lt $TOTAL_PER_PHASE; $j++) {
    # still run the allow flow (tone gate + retry) so the model learns full context
    $h1 = @{} + $BASE_HEADERS
    $obj1 = Curl-Proxy $h1
    Write-Row "forced_${action}_get_tone" "forced_$action" $obj1 $h1

    $tone = $obj1.tone
    $h2 = @{} + $BASE_HEADERS
    $h2["X-Tone"] = $tone
    $obj2 = Curl-Proxy $h2
    Write-Row "forced_${action}_with_tone" "forced_$action" $obj2 $h2
  }
}

# clear force action and recreate sidecar to normal
$env:SIDECAR_FORCE_ACTION = ""
Recreate-Sidecar

Write-Host "DONE. Dataset: $OUT_PATH"
Write-Host "Tip: Your primary stream is still being written to training\policy_training_v2_*.jsonl too."
