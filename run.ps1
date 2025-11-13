#!/usr/bin/env pwsh
# Run Auth Service with Dapr sidecar
# Usage: .\run.ps1

Write-Host "Starting Auth Service with Dapr..." -ForegroundColor Green
Write-Host "Service will be available at: http://localhost:1004" -ForegroundColor Cyan
Write-Host "Dapr HTTP endpoint: http://localhost:3504" -ForegroundColor Cyan
Write-Host "Dapr gRPC endpoint: localhost:50004" -ForegroundColor Cyan
Write-Host ""

dapr run `
  --app-id auth-service `
  --app-port 1004 `
  --dapr-http-port 3504 `
  --dapr-grpc-port 50004 `
  --resources-path .dapr/components `
  --config .dapr/config.yaml `
  --log-level warn `
  -- nodemon src/server.js
