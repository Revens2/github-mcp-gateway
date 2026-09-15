#!/bin/bash
# Verification canary github : sante + fail-closed, prod intacte. Lecture seule.
set -u
export HOME=/home/juliann
echo "=== canary :18999 ==="
curl -s --max-time 5 http://127.0.0.1:18999/health; echo
curl -s --max-time 5 http://127.0.0.1:18999/ready; echo
curl -s -o /dev/null -w "POST /mcp sans auth -> %{http_code}\n" --max-time 5 \
  -X POST http://127.0.0.1:18999/mcp -H "content-type: application/json" -d '{}' || true
systemctl is-active github-gateway-rs.service
echo "=== prod :8799 intacte ==="
curl -s --max-time 5 http://127.0.0.1:8799/health; echo
systemctl is-active github-mcp-gateway.service github-mcp-upstream.service
