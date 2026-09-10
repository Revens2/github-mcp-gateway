#!/usr/bin/env bash
# Pose la phrase de passe du consentement de la passerelle GitHub.
# Seule l'empreinte PBKDF2 est ecrite dans /srv/github/secrets/github.env (0600).
# A executer sur le VPS :  sudo bash chemin/du/repo/deploy/creer-phrase-github-mcp.sh
# La phrase est saisie sans echo, jamais transmise a l'agent, jamais ecrite en clair.
set -euo pipefail

APP=/srv/github
FICHIER="$APP/secrets/github.env"
VENV="$APP/venv"

echo "Saisissez la phrase de passe du consentement GitHub (aucun echo, >= 12 caracteres)."
read -r -s -p "Phrase : " P1
echo
read -r -s -p "Confirmation : " P2
echo
if [ "$P1" != "$P2" ]; then
    echo "Erreur : les deux saisies different." >&2
    exit 1
fi
if [ "${#P1}" -lt 12 ]; then
    echo "Erreur : phrase trop courte (12 caracteres minimum)." >&2
    exit 1
fi

# La phrase transite par stdin (jamais en argv : invisible de ps), puis les
# variables sont detruites.
HASH=$(printf '%s' "$P1" | PYTHONPATH="$APP" "$VENV/bin/python" -c \
    'import sys; from github_gateway.oauth import hacher_phrase; print(hacher_phrase(sys.stdin.read()))')
unset P1 P2

if grep -q '^GITHUB_MCP_CONSENT_HASH=' "$FICHIER"; then
    sed -i "s|^GITHUB_MCP_CONSENT_HASH=.*|GITHUB_MCP_CONSENT_HASH=$HASH|" "$FICHIER"
else
    printf '\nGITHUB_MCP_CONSENT_HASH=%s\n' "$HASH" >> "$FICHIER"
fi
chown github-app:github-app "$FICHIER"
chmod 600 "$FICHIER"
systemctl restart github-mcp-gateway.service
echo "Empreinte mise a jour et service redemarre."
