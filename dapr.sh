#!/usr/bin/env bash
# Run Auth Service with Dapr sidecar
# Usage: ./dapr.sh

echo -e "\033[0;32mStarting Auth Service with Dapr...\033[0m"
echo -e "\033[0;36mService will be available at: http://localhost:1004\033[0m"
echo -e "\033[0;36mHealth check: http://localhost:1004/health\033[0m"
echo -e "\033[0;36mDapr HTTP endpoint: http://localhost:3504\033[0m"
echo -e "\033[0;36mDapr gRPC endpoint: localhost:50004\033[0m"
echo ""

# Get the script directory
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

dapr run \
  --app-id auth-service \
  --app-port 1004 \
  --dapr-http-port 3504 \
  --dapr-grpc-port 50004 \
  --resources-path "$SCRIPT_DIR/.dapr/components" \
  --config "$SCRIPT_DIR/.dapr/config.yaml" \
  --log-level warn \
  -- node src/server.js
