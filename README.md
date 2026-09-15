# github-gateway-rs — facade Rust devant l'upstream docker fige v1.12.0

Miroir de `github_gateway` Python : validation Bearer + politique explicite
59 lectures / 35 ecritures / 0 admin + proxy vers `github-mcp-server:v1.12.0`
(`:8800`, loopback, PAT injecte, jamais retransmis depuis le client).

## Contrat conserve

`initialize` (session `mcp-session-id` upstream, passthrough), `tools/list`
filtree par portees (59 en lecture, 94 en lecture+ecriture), `tools/call`
avec refus local AVANT envoi (ecriture sans portee, inconnu → -32000 sans
contacter l'upstream), `resources/list` (4) + `prompts/list` (2) relayes
verbatim, `get_file_contents` normalise en texte direct (anti-materialisation
ChatGPT), compat Go stricte : `Accept` dual, coherence `mcp-protocol-version`,
strip `_meta` non supportee.

## Differences assumees (contrat outils intact)

401 au format framework (URL PRM exacte presente), PRM sans
`bearer_methods_supported`, metadata AS format framework (`none` seul) servie
a la racine (le suffixe `/oauth/github` = 404 comme le Python), rewrite
`mcp-protocol-version` 2026-07-28 → 2025-11-25, ajout `/ready`, `/health` +
champ `upstream_auth` (`configure`/`missing`, jamais la valeur). OAuth
JWT/Python vs opaque/Rust : canary via Bearer statique dedie.

## Environnement (`GITHUB_MCP_RS_*`)

| Variable | Defaut | Role |
|---|---|---|
| `GITHUB_MCP_RS_ISSUER` | issuer prod | HTTPS requis |
| `GITHUB_MCP_RS_UPSTREAM` | `http://127.0.0.1:8800` | loopback requis |
| `GITHUB_MCP_RS_PORT` | `18999` (canary) | `8799` a la bascule (GATEE) |
| `GITHUB_MCP_RS_TOKEN` / `_TOKEN_FILE` | `/opt/github-gateway-rs/.mcp_token` | Bearer dedie >= 32, fail-closed |
| `GITHUB_MCP_RS_UPSTREAM_TOKEN` / `_FILE` | `/srv/github/secrets/github-pat` | PAT 600 partage lecture seule ; absent = relais fail-closed |
| `GITHUB_MCP_RS_TOKEN_SCOPES` | lecture+ecriture | quoté dans l'unit (lecon lot 2) |
| `GITHUB_MCP_RS_CONSENT_HASH` | vide (= refuse) | PBKDF2 consentement |

## Preuves lot 3

- `cargo fmt --check` 0, `cargo clippy --all-targets -- -D warnings` 0.
- `cargo test` : politique 59/35, visibles 59/94/0, 401, health `upstream_auth`,
  PRM exacte, refus local avant upstream (inconnu, ecriture sans portee, sans
  PAT), injection PAT via mock, normalisation fichier, compat version/Accept.
- Canary VPS `:18999` + diff contrat zero vs `:8799` : voir `progress.md`.
- Bascule `:8799` GATEE (rotation Bearer prod + hash consentement = action
  exploitant, voir baseline-github-mcp.md) : prod Python intacte.
