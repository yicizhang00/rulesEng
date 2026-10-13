# Start rules-server (dev mode, real MySQL persistence)
# Usage:
#   1. Copy .env.example to .env, fill in DATABASE_URL
#   2. Make sure MySQL is running and `CREATE DATABASE rules_eng`
#   3. Run: powershell -File start-server.ps1

$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

if (Test-Path ".env") {
    Get-Content ".env" | ForEach-Object {
        if ($_ -match '^\s*([^#=]+)=(.*)$') {
            $key = $matches[1].Trim()
            $val = $matches[2].Trim()
            [Environment]::SetEnvironmentVariable($key, $val, 'Process')
        }
    }
    Write-Host "[ok] loaded .env" -ForegroundColor Green
} else {
    Write-Host "[warn] .env not found, using in-memory store (data lost on restart)" -ForegroundColor Yellow
    Write-Host "       Copy .env.example to .env and fill DATABASE_URL" -ForegroundColor Yellow
}

$env:Path = "C:\Users\zyc\.cargo\bin;$env:Path"

Write-Host "Starting rules-server ..." -ForegroundColor Cyan
cargo run -p rules-server
