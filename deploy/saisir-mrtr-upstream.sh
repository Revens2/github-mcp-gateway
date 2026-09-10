#!/usr/bin/env bash
# Regenere /srv/github/secrets/upstream.env avec une cle MRTR aleatoire.
# A executer sur le VPS : sudo bash chemin/du/repo/deploy/saisir-mrtr-upstream.sh
# La cle ne transite jamais hors du VPS (ni chat, ni log, ni argument).
set -euo pipefail

FICHIER=/srv/github/secrets/upstream.env

MRTR=$(openssl rand -base64 32 | tr -d '\n')
umask 077
printf 'GITHUB_MCP_SERVER_MRTR_STATE_KEY=%s\nGITHUB_TOOLSETS=all\n' "$MRTR" > "$FICHIER"
chown root:root "$FICHIER"
chmod 600 "$FICHIER"
unset MRTR
systemctl restart github-mcp-upstream.service
echo "upstream.env regenere (MRTR aleatoire) et upstream redemarre."
