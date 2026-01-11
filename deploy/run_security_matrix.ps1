# run_security_matrix.ps1
# Writes a JSONL security-matrix into ..\training\security_matrix_results_YYYYMMDD_HHMMSS.jsonl
# Safe under Set-StrictMode: does NOT crash when JSON fields are missing.

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ====== CONFIG ======
$BASE = "http://127.0.0.1:8085"

# Request body written to a temp JSON file (avoids curl quoting bugs)
$REQ_PATH = Join-Path $PSScriptRoot "req_small.json"
@'
{
  "target_url": "http://host.docker.internal:8099/export/small.csv",
  "method": "GET",
  "headers": {},
  "body": null
}
'@ | Set-Content -Path $REQ_PATH -Encoding utf8

# Where to write results (in your mounted training folder)
$tsName = (Get-Date).ToString("yyyyMMdd_HHmmss")
$RESULTS_PATH = Join-Path $PSScriptRoot "..\training\security_matrix_results_${tsName}.jsonl"
"Writing results to: $RESULTS_PATH"

# ====== HELPERS ======
function Get-Prop {
  param(
    [Parameter(Mandatory=$false)] $Obj,
    [Parameter(Mandatory=$true)] [string] $Name
  )
  if ($null -eq $Obj) { return $null }
  $p = $Obj.PSObject.Properties[$Name]
  if ($null -eq $p) { return $null }
  return $p.Value
}

function Get-Nested {
  param(
    [Parameter(Mandatory=$false)] $Obj,
    [Parameter(Mandatory=$true)] [string[]] $Path
  )
  $cur = $Obj
  foreach ($k in $Path) {
    if ($null -eq $cur) { return $null }
    $cur = Get-Prop -Obj $cur -Name $k
  }
  return $cur
}

function Invoke-Proxy {
  param(
    [Parameter(Mandatory=$true)] [hashtable] $Headers,
    [Parameter(Mandatory=$true)] [string] $ReqPath
  )

  # Build curl args safely (NO "$k: $v" parsing bug)
  $args = @()
  $args += "-sS"
  $args += "$BASE/proxy/http"
  $args += "-H"; $args += "Content-Type: application/json"

  foreach ($k in $Headers.Keys) {
    $v = $Headers[$k]
    if ($null -ne $v -and "$v" -ne "") {
      $args += "-H"
      $args += ("{0}: {1}" -f $k, $v)
    }
  }

  $args += "--data-binary"
  $args += "@$ReqPath"

  $raw = & curl.exe @args 2>$null

  # curl returns body only (no status line) because we did not pass -i
  # Body should be JSON from sidecar.
  try {
    return ($raw | ConvertFrom-Json)
  } catch {
    # If sidecar ever returns non-JSON, preserve raw.
    return $null
  }
}

function Write-Record {
  param(
    [Parameter(Mandatory=$true)] [string] $CaseId,
    [Parameter(Mandatory=$true)] [string] $Label,
    [Parameter(Mandatory=$false)] $Obj,
    [Parameter(Mandatory=$false)] [hashtable] $HeadersUsed
  )

  $reqTarget = $null
  try { $reqTarget = (Get-Content $REQ_PATH -Raw | ConvertFrom-Json).target_url } catch {}

  # IMPORTANT:
  # - On 200 responses, risk_level/risk_score are top-level.
  # - On 401 responses, risk_level/risk_score live under reason_detail.
  $riskLevel = (Get-Prop $Obj "risk_level")
  if ($null -eq $riskLevel) { $riskLevel = Get-Nested $Obj @("reason_detail","risk_level") }

  $riskScore = (Get-Prop $Obj "risk_score")
  if ($null -eq $riskScore) { $riskScore = Get-Nested $Obj @("reason_detail","risk_score") }

  $traceId  = Get-Nested $Obj @("headers","X-Trace-Id")
  $exportId = Get-Nested $Obj @("headers","X-Export-Id")

  $record = [ordered]@{
    ts               = (Get-Date).ToString("o")
    case_id          = $CaseId
    label            = $Label

    ok_json          = [bool]($null -ne $Obj)

    error            = (Get-Prop $Obj "error")
    decision_action  = (Get-Prop $Obj "decision_action")
    reason_codes     = (Get-Prop $Obj "reason_codes")

    status_outer     = (Get-Prop $Obj "status_code_outer")
    status_effective = (Get-Prop $Obj "status_code_effective")

    risk_level       = $riskLevel
    risk_score       = $riskScore

    behavior_level   = Get-Nested $Obj @("reason_detail","behavior_level")
    behavior_score   = Get-Nested $Obj @("reason_detail","behavior_score")

    tone_returned    = (Get-Prop $Obj "tone")

    trace_id         = $traceId
    export_id        = $exportId
    target_url       = $reqTarget

    # Echo what we actually sent (helps training)
    sent_org_id      = $HeadersUsed["X-Org-Id"]
    sent_user_id     = $HeadersUsed["X-User-Id"]
    sent_session_id  = $HeadersUsed["X-Session-Id"]
    sent_device_id   = $HeadersUsed["X-Device-Id"]
    sent_client_ip   = $HeadersUsed["X-Client-Ip"]
    sent_user_agent  = $HeadersUsed["User-Agent"]
    sent_tone        = $HeadersUsed["X-Tone"]
    sent_reauth      = $HeadersUsed["X-Reauth-Result"]
  }

  ($record | ConvertTo-Json -Depth 12 -Compress) + "`n" |
    Add-Content -Path $RESULTS_PATH -Encoding utf8
}

# ====== BASE HEADERS (GOOD CLIENT) ======
$H_GOOD = @{
  "X-Org-Id"      = "org-1"
  "X-User-Id"     = "user-1"
  "X-Session-Id"  = "sess-1"
  "X-Device-Id"   = "dev-1"
  "X-Client-Ip"   = "10.0.0.10"
  "User-Agent"    = "customer/1.0"
}

# ====== TEST MATRIX ======
# Goal: generate diverse training rows: allow / tone_required / tone_invalid / identity_required / spoof attempts / replay / etc.

# Case A: Missing identity -> expect identity_required
$h = @{} + $H_GOOD
$h.Remove("X-User-Id")
$h.Remove("X-Session-Id")
$h.Remove("X-Device-Id")
$obj = Invoke-Proxy -Headers $h -ReqPath $REQ_PATH
Write-Record -CaseId "A_missing_identity" -Label "reauth_biometric" -Obj $obj -HeadersUsed $h

# Case B: No tone first -> expect tone_required + tone returned
$h = @{} + $H_GOOD
$h.Remove("X-Tone")
$obj = Invoke-Proxy -Headers $h -ReqPath $REQ_PATH
Write-Record -CaseId "B_get_tone" -Label "reauth_biometric" -Obj $obj -HeadersUsed $h
$tone = Get-Prop $obj "tone"

# Case C: Retry with tone -> expect allow(200)
if ($null -ne $tone -and "$tone" -ne "") {
  $h = @{} + $H_GOOD
  $h["X-Tone"] = $tone
  $obj = Invoke-Proxy -Headers $h -ReqPath $REQ_PATH
  Write-Record -CaseId "C_valid_tone_allows" -Label "allow" -Obj $obj -HeadersUsed $h
}

# Case D: Replay tone with different device -> expect tone_invalid
if ($null -ne $tone -and "$tone" -ne "") {
  $h = @{} + $H_GOOD
  $h["X-Tone"] = $tone
  $h["X-Device-Id"] = "dev-999"
  $obj = Invoke-Proxy -Headers $h -ReqPath $REQ_PATH
  Write-Record -CaseId "D_tone_replay_device_swap" -Label "reauth_biometric" -Obj $obj -HeadersUsed $h
}

# Case E: Spoof X-Reauth-Result without actually doing reauth -> should NOT bypass tone
$h = @{} + $H_GOOD
$h.Remove("X-Tone")
$h["X-Reauth-Result"] = "ok"
$obj = Invoke-Proxy -Headers $h -ReqPath $REQ_PATH
Write-Record -CaseId "E_spoof_reauth_result" -Label "reauth_biometric" -Obj $obj -HeadersUsed $h

# Case F: UA change WITH valid tone (should still allow in your current behavior)
# (This intentionally generates more 'allow' rows but with changed UA features.)
# Get fresh tone first
$h0 = @{} + $H_GOOD
$h0.Remove("X-Tone")
$obj0 = Invoke-Proxy -Headers $h0 -ReqPath $REQ_PATH
$t2 = Get-Prop $obj0 "tone"

if ($null -ne $t2 -and "$t2" -ne "") {
  $h = @{} + $H_GOOD
  $h["X-Tone"] = $t2
  $h["User-Agent"] = "attacker/9.9"
  $obj = Invoke-Proxy -Headers $h -ReqPath $REQ_PATH
  Write-Record -CaseId "F_valid_tone_ua_changed" -Label "allow" -Obj $obj -HeadersUsed $h
}

# Case G: Hammer tone-required path (generates lots of reauth_biometric)
for ($i=0; $i -lt 25; $i++) {
  $h = @{} + $H_GOOD
  $h.Remove("X-Tone")
  $obj = Invoke-Proxy -Headers $h -ReqPath $REQ_PATH
  Write-Record -CaseId ("G_no_tone_burst_{0}" -f $i) -Label "reauth_biometric" -Obj $obj -HeadersUsed $h
}

# Case H: Invalid/malformed tone -> expect tone_invalid
$h = @{} + $H_GOOD
$h["X-Tone"] = "not-a-real-tone"
$obj = Invoke-Proxy -Headers $h -ReqPath $REQ_PATH
Write-Record -CaseId "H_bad_tone_string" -Label "reauth_biometric" -Obj $obj -HeadersUsed $h

"Done. Results written to: $RESULTS_PATH"
