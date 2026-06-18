#!/usr/bin/env bash
set -euo pipefail
IMAGE=${1:-your-registry/domain-monitor:latest}
docker build -t "$IMAGE" .
docker push "$IMAGE"
echo "Pushed $IMAGE"
