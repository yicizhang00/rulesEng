# Start Vue dev server (Vite, hot reload)
# Usage: powershell -File start-web.ps1
Set-Location $PSScriptRoot\web
Write-Host "Frontend: http://127.0.0.1:8080" -ForegroundColor Cyan
npm run dev
