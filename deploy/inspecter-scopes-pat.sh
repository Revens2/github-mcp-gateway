#!/usr/bin/env bash
# Affiche les scopes du PAT GitHub interne SANS jamais afficher le token.
# Usage : sudo bash chemin/du/repo/deploy/inspecter-scopes-pat.sh
# Sortie : la seule ligne X-OAuth-Scopes (classic) ou une note fine-grained.
set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
    echo "Erreur : relancez avec sudo." >&2
    exit 1
fi

FICHIER=/srv/github/secrets/github-pat
[ -s "$FICHIER" ] || { echo "PAT absent ou vide : $FICHIER" >&2; exit 1; }

SCOPES=$(curl -sI -H "Authorization: Bearer $(cat "$FICHIER")" https://api.github.com/user | grep -i '^x-oauth-scopes:' || true)
if [ -n "$SCOPES" ]; then
    echo "PAT classic — scopes : $SCOPES"
else
    echo "Pas de X-OAuth-Scopes : PAT fine-grained probable (permissions via l'UI GitHub)."
fi
