# Mission state

## Objectif
MCP GitHub privé RW pour ChatGPT Web sur VPS étude : upstream officiel
`github-mcp-server` v1.12.0 + gateway OAuth `github-mcp-gateway`, endpoint
`https://mymcps.duckdns.org/github/mcp`, E2E lecture + écriture réversible prouvée
depuis ChatGPT Web.

## Étape courante
Phase 3 terminée (repo + gateway + tests verts en local). En attente : déploiement
VPS (phases 6-7), PAT humain (phase 5), E2E (phases 8-10), revue + GO (11-12).

## Fait
- Phase 1 : 4 audits read-only (RAG, VPS live, serveur officiel, patterns).
- Phase 2 : décision CAS A documentée (pas de bridge Rust), ports 8798/8799.
- Phase 3 : repo `github-mcp-gateway` (copie-adaptation calendar), politique 94 tools,
  units systemd ×2, snippet nginx 5 blocs, compose, install, val_github.py, README,
  CI gitleaks+pytest, tests redaction/canary. 96/96 tests gateway+redaction verts
  (Windows) ; 6 tests oauth_magasin hérités échouent sur Windows comme sur le
  template d'origine (perms/flock) — CI Ubuntu fera foi.

## À faire
- [ ] Créer le dépôt GitHub `Revens2/github-mcp-gateway` + push.
- [ ] VPS : backup nginx/systemd, `/srv/github`, pull image + digest, install gateway.
- [ ] PAT : action humaine (création + saisie terminal, jamais dans le chat).
- [ ] nginx 5 blocs + reload, OAuth + MCP exterieur, E2E lecture puis écriture.
- [ ] Connecteur ChatGPT Web + E2E RW depuis ChatGPT + cleanup.
- [ ] `github-code-review` (GO/NO-GO), revue Astra, GO production, rapport final.

## Décisions
- CAS A : officiel HTTP direct, pas de Rust (preuves : main.go, streamable-http.md).
- PAT dédié MCP (classic si besoin max), séparé du token OAuth ChatGPT.
- Politique full RW 94/94, admin vide, fail-closed sur inconnu.
- /srv/github (modèle tasks/astra), secrets 0600, upstream Docker loopback.

## Blocages actifs
- PAT GitHub : saisie humaine sur le VPS requise (phase 5).
- Consentement ChatGPT : configuration connecteur + phrase, côté Titou.

## Validation
- [x] Catalogue 94 tools (README v1.12.0) classés 59L/35E.
- [x] pytest gateway+redaction : 96 passed.
- [ ] CI verte (après push).
- [ ] E2E VPS lecture/écriture + ChatGPT Web.
