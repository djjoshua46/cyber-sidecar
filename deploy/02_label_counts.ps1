Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$REPO = "C:\Cybersecurity\cyber-sidecar"
$TRAIN = Join-Path $REPO "training"

Write-Host "==> Latest generated_training_*.jsonl"
$latest = Get-ChildItem $TRAIN -Filter "generated_training_*.jsonl" | Sort-Object LastWriteTime -Descending | Select-Object -First 1
if (-not $latest) { throw "No generated_training_*.jsonl found in $TRAIN" }

Write-Host "File: $($latest.FullName)"

# Count by decision_action (from responses) + by label (our intended label)
python -c @"
import json, collections
p = r'''$($latest.FullName)'''
c_dec = collections.Counter()
c_lab = collections.Counter()
n=0
with open(p,'r',encoding='utf-8',errors='replace') as f:
  for line in f:
    line=line.strip()
    if not line: continue
    try: o=json.loads(line)
    except: continue
    n += 1
    c_dec[o.get('decision_action')] += 1
    c_lab[o.get('label')] += 1
print('rows:', n)
print('decision_action:', dict(c_dec))
print('label:', dict(c_lab))
"@
