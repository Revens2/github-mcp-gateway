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

# Mise a jour du fichier env via python+stdin : l'empreinte ne transite jamais
# en argv (invisible de ps), contrairement a un sed -i "...$HASH".
printf '%s\n%s' "$HASH" "$FICHIER" | "$VENV/bin/python" -c \
    'import sys; empreinte, chemin = sys.stdin.read().split("\n", 1)
lignes = []
try:
    with open(chemin, encoding="utf-8") as f:
        lignes = f.read().splitlines()
except FileNotFoundError:
    pass
lignes = [l for l in lignes if not l.startswith("GITHUB_MCP_CONSENT_HASH=")]
lignes.append(f"GITHUB_MCP_CONSENT_HASH={empreinte.strip()}")
with open(chemin, "w", encoding="utf-8") as f:
    f.write("\n".join(lignes) + "\n")'
unset HASH
chown github-app:github-app "$FICHIER"
chmod 600 "$FICHIER"
systemctl restart github-mcp-gateway.service
echo "Empreinte mise a jour et service redemarre."
