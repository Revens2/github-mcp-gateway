#!/usr/bin/env bash
# Affiche les scopes du PAT GitHub interne SANS jamais afficher le token.
# Usage : sudo bash chemin/du/repo/deploy/inspecter-scopes-pat.sh
# Sortie : la seule ligne X-OAuth-Scopes (classic) ou une note fine-grained.
# Le token est lu par python3 directement dans son fichier 0600 (seul le chemin
# transite en argv) : invisible de ps, hors historique, hors logs.
set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
    echo "Erreur : relancez avec sudo." >&2
    exit 1
fi

FICHIER=/srv/github/secrets/github-pat
[ -s "$FICHIER" ] || { echo "PAT absent ou vide : $FICHIER" >&2; exit 1; }

SCOPES=$(python3 - "$FICHIER" <<'PY'
import sys
import urllib.request

with open(sys.argv[1], encoding="utf-8") as f:
    pat = f.read().strip()
req = urllib.request.Request(
    "https://api.github.com/user",
    headers={"Authorization": f"Bearer {pat}", "User-Agent": "github-mcp-gateway-inspect"},
)
try:
    with urllib.request.urlopen(req, timeout=30) as rep:
        print(rep.headers.get("X-OAuth-Scopes", ""))
except Exception as exc:  # panne reseau/API : diagnostic sans secret
    print(f"ERREUR-API:{exc.__class__.__name__}", file=sys.stderr)
    sys.exit(1)
PY
)
if [ -n "$SCOPES" ]; then
    echo "PAT classic — scopes : x-oauth-scopes: $SCOPES"
else
    echo "Pas de X-OAuth-Scopes : PAT fine-grained probable (permissions via l'UI GitHub)."
fi
