# Plan — MCP GitHub privé RW pour ChatGPT Web (VPS étude)

## Décision d'architecture (Phase 2, 2026-09-10) : CAS A — OFFICIEL HTTP DIRECT

Preuves (audits Phase 1) :
- `github/github-mcp-server` v1.12.0 (release 2026-09-03) expose `http` :
  `cmd/github-mcp-server/main.go` (`stdioCmd` + `httpCmd`), `docs/streamable-http.md`
  (`github-mcp-server http` → `:8082`, `--base-path /mcp`, `--scope-challenge`,
  `--base-url`, PAT per-request via `Authorization: Bearer`), handler stateless
  (`pkg/http/handler.go:ServeHTTP`, `Stateless:true`). Pas de SSE legacy.
- Image `ghcr.io/github/github-mcp-server:v1.12.0` (`golang:1.27.1-alpine`,
  distroless, `EXPOSE 8082`, `CMD ["stdio"]` → override `http ...`).
- `GITHUB_TOOLSETS=all` = tous les toolsets ; 22 toolsets, 94 tools en v1.12.0 ;
  pas de `tools/list_changed` ; Resources (`repo://` ×5) + Prompts (×2) inclus ;
  OAuth-login et GitHub App = stdio uniquement → PAT obligatoire en `http`.
- Pattern Titou éprouvé : gateway Python OAuth colocalisé + proxy transparent
  (`calendar-mcp-gateway`, `tasks`, `astra`), nginx mono-vhost `mymcps.duckdns.org`,
  systemd `EnvironmentFile` 0600 (jamais `LoadCredential`), ports 8798/8799 libres,
  `Requires=` upstream, `stateless` côté ChatGPT.

Donc : **aucun bridge Rust**. Couche propriétaire = gateway Python
(copie-adaptation `calendar-mcp-gateway`) + upstream officiel en Docker loopback.

```
ChatGPT Web --HTTPS/OAuth--> mymcps.duckdns.org:443 --/github/mcp-->
github-mcp-gateway :8799 --127.0.0.1--> github-mcp-upstream :8798
(github-mcp-server v1.12.0 http --base-path /mcp, GITHUB_TOOLSETS=all) --> api.github.com
Token/OAuth ChatGPT = accès AU MCP ; PAT interne = MCP VERS GitHub (jamais exposé).
```

## Registre des choix

- Upstream : Docker officiel pinné `v1.12.0` (+ digest relevé au pull), `--base-path /mcp`
  (le proxy gateway transmet le chemin `/mcp`), sans `--base-url` public (métadonnées
  OAuth upstream masquées par le 404 gateway ; seule la gateway parle aux connecteurs).
- PAT : classic dédié si toolsets voulus dépassent le fine-grained, sinon fine-grained
  `All repositories`. Scopes : `repo, read:org, user:email, gist, notifications, workflow`
  (+ `delete_repo` si suppression voulue). Saisie terminal VPS uniquement.
- MRTR : `GITHUB_MCP_SERVER_MRTR_STATE_KEY` base64-32 stable (sinon `delete_repository`
  masqué par l'upstream — comportement officiel, pas une panne).
- Politique gateway : 59 lecture + 35 écriture = 94/94 catalogue v1.12.0, `admin` vide,
  inconnu → fail-closed (les futurs tools upstream restent masqués jusqu'au classement).
- Fait marquant : pas de `delete_branch` côté officiel → E2E écriture = issue créée,
  relue, fermée (jamais `main`, `--repo` explicite obligatoire).

## Rollback

Avant toute modif VPS : `cp mymcps.duckdns.org.conf /srv/archives/...-pre-github`,
snapshot `systemctl cat` + `ss -tlnp`. Rollback = supprimer les 5 blocs `/github`,
`nginx -t && reload`, `disable --now github-*`. Vault/Astra/Tasks/Calendar intacts
(registres/scopes/ports séparés).
