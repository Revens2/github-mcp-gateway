# github-mcp-gateway

Passerelle d'authentification pour le serveur MCP **GitHub** officiel
(upstream : [`github/github-mcp-server`](https://github.com/github/github-mcp-server)
`v1.12.0`, image `ghcr.io/github/github-mcp-server:v1.12.0`, non incluse ici).

Elle n'est **pas** un serveur MCP de plein exercice : elle valide le jeton d'accès
(OAuth colocalisé ou Bearer statique) puis relaie tel quel le trafic Streamable HTTP
vers l'upstream (`127.0.0.1:8800`, mode `http --base-path /mcp`). Aucun tool GitHub
n'est réimplémenté ici : catalogue, schémas, appels REST/GraphQL et évolutions
restent fournis par le serveur officiel.

- `/authorize`, `/token`, `/register`, `/revoke`, `/consentement` — serveur
  d'autorisation OAuth colocalisé (RFC 8414/9728) + page de consentement à phrase de passe.
- `/mcp` — middleware d'authentification puis proxy transparent vers l'upstream.
- Tout le reste répond 404.

Endpoint public (via nginx `mymcps.duckdns.org`) : `https://mymcps.duckdns.org/github/mcp`
(OAuth issuer `https://mymcps.duckdns.org/oauth/github`, scopes
`github:lecture` / `github:ecriture`).

## Rôle métier

Donner à ChatGPT Web un accès lecture + écriture aux dépôts GitHub de Titou
(dépôts actuels et futurs), avec la surface officielle maximale
(`GITHUB_TOOLSETS=all`, read-only **désactivé**). Les protections natives GitHub
(branch protection, rulesets, permissions du compte) continuent de s'appliquer.

## Profil d'outils

Deux couches indépendantes doivent être alignées pour qu'un outil soit réellement exposé :

1. **Upstream** (`GITHUB_TOOLSETS=all`, voir `deploy/github-mcp-upstream.env.example`) :
   le serveur officiel enregistre ses 22 toolsets (94 tools en v1.12.0).
2. **Passerelle** (`github_gateway/politique.py`) : chaque outil est classé
   lecture / écriture. Non classé ⇒ jamais annoncé, jamais exécutable
   (fail-closed), même si l'upstream l'expose.

Profil voulu (94 outils : 59 lecture + 35 écriture) : tout le catalogue local
officiel, y compris `delete_repository` (gate MRTR côté upstream : exige
`GITHUB_MCP_SERVER_MRTR_STATE_KEY` stable, sinon l'outil est masqué par
l'upstream lui-même). Aucun outil en `admin`.

Les scopes GitHub requis côté PAT classique : `repo`, `read:org`, `user:email`,
`gist`, `notifications`, `workflow` (+ `delete_repo` si suppression de dépôts
voulue). Vérifier contre la version déployée (`tools/list` + raisons d'absence).

## Contenu

```
github_gateway/     passerelle ASGI (app, auth/oauth, politique, consentement, proxy upstream)
tests/                suite pytest (test_gateway.py, test_oauth_magasin.py, test_redaction.py)
deploy/
  install-gateway.sh               installation (compte dédié, venv, env, unités systemd)
  github-mcp-gateway.service       unité systemd durcie (boucle locale stricte)
  github-mcp-upstream.service      unité systemd upstream (docker run loopback)
  nginx-mymcps-github-snippet.conf fragment à insérer dans mymcps.duckdns.org.conf
  docker-compose.upstream.example.yml  alternative compose pour l'upstream (boucle locale)
  github-mcp-upstream.env.example  template env upstream (noms uniquement, aucun secret)
  creer-phrase-github-mcp.sh       pose l'empreinte PBKDF2 de la phrase de consentement
  val_github.py                    validation de bout en bout via la passerelle
```

## PAT GitHub (action humaine, une fois)

1. Créer un **PAT dédié au MCP** (classic si les toolsets voulus dépassent le
   fine-grained, sinon fine-grained `All repositories`). Scopes minimaux pour le
   maximum fonctionnel : voir § Profil d'outils.
2. Sur le VPS, en root : saisir le PAT + générer la clé MRTR **dans le terminal
   uniquement** (jamais dans le chat, jamais en argument de commande) :
   ```bash
   umask 077
   read -r -s -p "PAT GitHub : " PAT; echo
   MRTR=$(openssl rand -base64 32 | tr -d '\n')
   printf 'GITHUB_PERSONAL_ACCESS_TOKEN=%s\nGITHUB_MCP_SERVER_MRTR_STATE_KEY=%s\n' \
     "$PAT" "$MRTR" > /srv/github/secrets/upstream.env
   chown root:github-app /srv/github/secrets/upstream.env; chmod 600 /srv/github/secrets/upstream.env
   unset PAT MRTR
   ```
3. Poser la phrase de consentement : `sudo bash deploy/creer-phrase-github-mcp.sh`.
4. `systemctl start github-mcp-upstream github-mcp-gateway`, puis
   `sudo /srv/github/venv/bin/python deploy/val_github.py` (lecture) et
   `sudo /srv/github/venv/bin/python deploy/val_github.py --create --repo PROPRIO/DEPOT-TEST`
   (écriture réversible : issue créée, relue, fermée).

## Rollback

- Supprimer les 5 blocs `/github` du vhost mymcps, `nginx -t && systemctl reload nginx`.
- `systemctl disable --now github-mcp-gateway github-mcp-upstream`, supprimer
  `/srv/github` si voulu. Vault/Astra/Tasks/Calendar inchangés (registres,
  passphrases et scopes séparés, ports distincts 8800/8799).
