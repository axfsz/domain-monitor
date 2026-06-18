#!/usr/bin/env bash
set -euo pipefail
kubectl apply -f k8s/
kubectl -n monitor rollout status deploy/domain-monitor-postgres
kubectl -n monitor rollout status deploy/domain-monitor-redis
kubectl -n monitor rollout status deploy/domain-monitor-web
kubectl -n monitor rollout status deploy/domain-monitor-worker
