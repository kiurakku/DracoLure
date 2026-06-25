#!/usr/bin/env bash
set -euo pipefail

echo "==> Waiting for Flask app"
for _ in $(seq 1 30); do
  if curl -fsS http://localhost:5000/health >/dev/null 2>&1; then
    break
  fi
  sleep 2
done

echo "==> POST /attack"
curl -fsS -X POST http://localhost:5000/attack \
  -H 'Content-Type: application/json' \
  -d '{"attack_type":"smoke-test","source_ip":"127.0.0.1"}'

echo
echo "==> GET /log via Go service"
curl -fsS http://localhost:8080/log

echo
echo "==> Smoke test passed"
