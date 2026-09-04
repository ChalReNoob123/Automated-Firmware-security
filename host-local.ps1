# SentinelForge - host the full stack on localhost.
# Usage:
#   powershell -ExecutionPolicy Bypass -File host-local.ps1        # start API :4000 + Web :3005
#   powershell -ExecutionPolicy Bypass -File host-local.ps1 -Stop  # stop both
param([switch]$Stop)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $MyInvocation.MyCommand.Path

function Get-PidsOnPort([int]$port) {
  $out = netstat -ano -p tcp | Select-String "LISTENING" | Select-String ":$port\s"
  $out | ForEach-Object { ($_ -split '\s+' | Where-Object { $_ } | Select-Object -Last 1) } | Sort-Object -Unique
}

if ($Stop) {
  foreach ($port in @(4000, 3005)) {
    foreach ($procId in Get-PidsOnPort $port) {
      try { Stop-Process -Id $procId -Force; Write-Host "stopped pid $procId (port $port)" } catch { }
    }
  }
  exit 0
}

foreach ($port in @(4000, 3005)) {
  $pids = Get-PidsOnPort $port
  if ($pids) { Write-Host "port $port already in use by pid(s): $($pids -join ', ') - stop first with -Stop"; exit 1 }
}

Start-Process powershell -ArgumentList '-NoExit', '-Command', "cd '$root\apps\api'; npm run dev"
Start-Process powershell -ArgumentList '-NoExit', '-Command', "cd '$root\apps\web'; npm run dev"

Write-Host 'waiting for API http://localhost:4000/health ...'
$ok = $false
for ($i = 0; $i -lt 30; $i++) {
  try { (Invoke-WebRequest -UseBasicParsing 'http://localhost:4000/health' -TimeoutSec 3).Content | Out-Null; $ok = $true; break } catch { Start-Sleep -Seconds 2 }
}
if (-not $ok) { Write-Host 'API did not come up - check the api window for errors'; exit 1 }

Write-Host ''
Write-Host 'SentinelForge is up:'
Write-Host '  Web  http://localhost:3005/  (landing, emulator, graph, copilot pages)'
Write-Host '  API  http://localhost:4000/health  (try /v1/modules and /v1/graph/demo)'
Write-Host ''
Write-Host 'Demo login bootstrap (dev stub - any 6-digit 2FA code works):'
Write-Host '  Step 1 - login (copy the tempToken from the output):'
Write-Host "  Invoke-WebRequest -UseBasicParsing http://localhost:4000/v1/auth/login -Method Post -ContentType 'application/json' -Body '{`"identifier`":`"demo`",`"password`":`"x`"}'"
Write-Host '  Step 2 - POST tempToken + code to /v1/auth/verify-2fa, paste accessToken into the UI token fields'
