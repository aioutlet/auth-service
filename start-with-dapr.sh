#!/bin/bash

# Start auth-service with Dapr sidecar
dapr run \
  --app-id auth-service \
  --app-port 3001 \
  --dapr-http-port 3500 \
  --dapr-grpc-port 50001 \
  --components-path ./.dapr/components \
  --log-level info \
  -- npm run dev
