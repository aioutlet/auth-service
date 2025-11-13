#!/usr/bin/env pwsh
# Run Auth Service directly (without Dapr)
# Usage: .\run.ps1

Write-Host "Starting Auth Service (Direct mode - no Dapr)..." -ForegroundColor Green
Write-Host "Service will be available at: http://localhost:1004" -ForegroundColor Cyan
Write-Host "Health check: http://localhost:1004/health" -ForegroundColor Cyan
Write-Host ""

npm run dev
