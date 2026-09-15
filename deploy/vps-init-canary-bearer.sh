#!/bin/bash
# Genere le Bearer canary DEDIE (VPS uniquement, valeur jamais affichee ni
# rapatriee). Idempotent : ne regenere jamais un fichier existant non vide.
# JAMAIS le Bearer prod (/srv/github/secrets/github.env).
set -euo pipefail
F=/opt/github-gateway-rs/.mcp_token
sudo install -d -o github-app -g github-app -m 0755 /opt/github-gateway-rs
if [ -s "$F" ]; then
  echo "[bearer] deja present (longueur seule) :"
  sudo wc -c "$F"
  exit 0
fi
sudo -u github-app python3 -c 'import secrets; open("/opt/github-gateway-rs/.mcp_token", "w").write(secrets.token_urlsafe(48))'
sudo chmod 600 "$F"
echo "[bearer] genere (longueur seule) :"
sudo wc -c "$F"
