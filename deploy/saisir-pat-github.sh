#!/usr/bin/env bash
# Saisie interactive du PAT GitHub dedie au MCP (une seule commande a lancer).
# Usage : sudo bash chemin/du/repo/deploy/saisir-pat-github.sh
#   1. le script demande le PAT (saisie silencieuse : rien ne s'affiche) ;
#   2. collez le token, Entree : il est ecrit dans /srv/github/secrets/github-pat (0600) ;
#   3. la variable est detruite, la gateway redemarre, /health est verifie.
# Le token ne transite ni en argument, ni dans l'historique, ni dans les logs.
set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
    echo "Erreur : relancez avec sudo." >&2
    exit 1
fi

FICHIER=/srv/github/secrets/github-pat
[ -d /srv/github/secrets ] || { echo "Erreur : /srv/github/secrets absent (installeur non lance ?)." >&2; exit 1; }

printf 'Collez le PAT GitHub dedie au MCP (saisie invisible), puis Entree : '
read -r -s PAT
echo
if [ "${#PAT}" -lt 20 ]; then
    echo "Erreur : valeur trop courte, abandon (rien n'a ete ecrit)." >&2
    unset PAT
    exit 1
fi
case "$PAT" in
    ghp_*|github_pat_*|gho_*|ghs_*) ;;
    *) echo "Avertissement : prefixe inattendu (on continue quand meme)." ;;
esac

umask 077
printf '%s' "$PAT" > "$FICHIER"
chown github-app:github-app "$FICHIER"
chmod 600 "$FICHIER"
unset PAT

systemctl restart github-mcp-gateway.service
sleep 3
SANTE=$(curl -s http://127.0.0.1:8799/health)
case "$SANTE" in
    *'"upstream_auth":"configure"'*)
        echo "OK : PAT enregistre (0600), gateway redemarree, upstream_auth=configure." ;;
    *)
        echo "ATTENTION : reponse inattendue de /health : $SANTE" >&2
        exit 1 ;;
esac
