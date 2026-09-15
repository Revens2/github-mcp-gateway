#!/bin/bash
# Rollback canary lot 3 : stoppe le canary, verifie la prod intacte.
# Aucune modification du service prod (jamais pointe vers le binaire Rust).
set -euo pipefail
sudo systemctl stop github-gateway-rs.service || true
sudo systemctl is-active github-mcp-gateway.service
curl -s http://127.0.0.1:8799/health; echo
echo "[rollback] prod :8799 intacte, canary stoppe"
