#!/usr/bin/env bash
# Installation de la passerelle GitHub (a executer root sur le VPS etude).
# Aucun secret ne transite par le terminal de l'operateur : le jeton statique est
# genere sur la machine dans /srv/github/secrets/github.env (0600).
# Le PAT GitHub et la cle MRTR sont saisis separement (voir README § PAT),
# jamais dans le chat, jamais en argument visible.
set -euo pipefail

APP=/srv/github
SRC="$(cd "$(dirname "$0")/.." && pwd)"

# --- compte dedie --------------------------------------------------------------
if ! id github-app >/dev/null 2>&1; then
    useradd --system --no-create-home --home-dir "$APP" --shell /usr/sbin/nologin github-app
fi
install -d -o root -g juliann "$APP"
install -d -o github-app -g github-app "$APP/secrets" "$APP/data" "$APP/data/oauth" "$APP/tests"
chmod 700 "$APP/secrets" "$APP/data"

# --- code + venv ----------------------------------------------------------------
rm -rf "$APP/github_gateway"
cp -r "$SRC/github_gateway" "$APP/"
cp "$SRC/requirements.txt" "$APP/"
cp -r "$SRC"/tests/* "$APP/tests/" 2>/dev/null || true

python3 -m venv "$APP/venv"
"$APP/venv/bin/pip" install -q --disable-pip-version-check -r "$APP/requirements.txt"
chown -R root:juliann "$APP/github_gateway" "$APP/requirements.txt"
chown -R github-app:github-app "$APP/data" "$APP/venv"

# --- environnement gateway (secrets generes sur place, jamais affiches) ---------
TOKEN=$("$APP/venv/bin/python" -c 'import secrets; print(secrets.token_urlsafe(48))')
umask 077
cat > "$APP/secrets/github.env" <<ENV
GITHUB_MCP_PORT=8799
GITHUB_MCP_ISSUER=https://mymcps.duckdns.org/oauth/github
GITHUB_MCP_UPSTREAM=http://127.0.0.1:8800
GITHUB_MCP_TOKEN=${TOKEN}
GITHUB_MCP_TOKEN_SCOPES=github:lecture github:ecriture
GITHUB_MCP_OAUTH_DIR=/srv/github/data/oauth
GITHUB_MCP_UPSTREAM_TOKEN_FILE=/srv/github/secrets/github-pat
ENV
chown github-app:github-app "$APP/secrets/github.env"
chmod 600 "$APP/secrets/github.env"
unset TOKEN

# --- PAT GitHub interne : fichier dedie 0600 (squelette vide, valeur saisie ensuite)
# La passerelle l'injecte en Bearer vers l'upstream (http exige un Authorization
# par requete) ; l'Authorization du client n'est jamais retransmis.
if [ ! -f "$APP/secrets/github-pat" ]; then
    : > "$APP/secrets/github-pat"
    chown github-app:github-app "$APP/secrets/github-pat"
    chmod 600 "$APP/secrets/github-pat"
    echo "Squelette $APP/secrets/github-pat cree (0600, vide) : y ecrire le PAT (voir README)."
else
    echo "$APP/secrets/github-pat existe deja : inchange."
fi

# --- fichier upstream (MRTR) : squelette 0600, valeur saisie ensuite ------------
if [ ! -f "$APP/secrets/upstream.env" ]; then
    cat > "$APP/secrets/upstream.env" <<ENV
GITHUB_MCP_SERVER_MRTR_STATE_KEY=
GITHUB_TOOLSETS=all
ENV
    chown root:root "$APP/secrets/upstream.env"
    chmod 600 "$APP/secrets/upstream.env"
    echo "Squelette $APP/secrets/upstream.env cree (0600) : saisir la cle MRTR (voir README)."
else
    echo "$APP/secrets/upstream.env existe deja : inchange."
fi

# --- unites systemd ---------------------------------------------------------------
cp "$SRC/deploy/github-mcp-upstream.service" /etc/systemd/system/
cp "$SRC/deploy/github-mcp-gateway.service" /etc/systemd/system/

systemctl daemon-reload
systemctl enable github-mcp-upstream.service github-mcp-gateway.service
echo "OK : fichiers installes. Etapes suivantes (voir README) :"
echo "  1. saisir PAT + MRTR dans $APP/secrets/upstream.env (0600)"
echo "  2. sudo bash $SRC/deploy/creer-phrase-github-mcp.sh (phrase consentement)"
echo "  3. inserer deploy/nginx-mymcps-github-snippet.conf dans mymcps.duckdns.org.conf"
echo "  4. systemctl start github-mcp-upstream && valider, puis start gateway"
