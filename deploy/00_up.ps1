Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$REPO = "C:\Cybersecurity\cyber-sidecar"
$COMPOSE = Join-Path $REPO "deploy\docker-compose.local.yml"
$BASE = "http://127.0.0.1:8085"

Write-Host "==> Down/up docker stack..."
docker compose -f $COMPOSE down | Out-Null
docker compose -f $COMPOSE up -d --build

Write-Host "==> Waiting for sidecar /health ..."
for ($i=0; $i -lt 45; $i++) {
  try {
    $r = iwr "$BASE/health" -UseBasicParsing -TimeoutSec 2
    if ($r.StatusCode -eq 200) { Write-Host "ready"; break }
  } catch {
    Start-Sleep -Seconds 1
  }
  if ($i -eq 44) { throw "sidecar not healthy after wait" }
}

Write-Host "==> Tail sidecar logs"
docker compose -f $COMPOSE logs --tail 40 sidecar

Write-Host "==> Tail fake_backend logs"
docker compose -f $COMPOSE logs --tail 20 fake_backend
