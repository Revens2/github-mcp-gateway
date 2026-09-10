# Mission state

## Objectif
MCP GitHub privé RW pour ChatGPT Web sur VPS étude : upstream officiel
`github-mcp-server` v1.12.0 + gateway OAuth `github-mcp-gateway`, endpoint
`https://mymcps.duckdns.org/github/mcp`, E2E lecture + écriture réversible prouvée
depuis ChatGPT Web.

## Étape courante
Phase 7 terminée sans PAT : nginx public OK (PRM/AS/401 vérifiés depuis l'extérieur,
astra/tasks/calendar non régressés). En attente : PAT humain (phase 5), phrase de
consentement, E2E (phases 8-10), revue + GO (11-12).

## Fait
- Phase 1 : 4 audits read-only (RAG, VPS live, serveur officiel, patterns).
- Phase 2 : décision CAS A documentée (pas de bridge Rust), ports 8800/8799
  (8798 occupé par activity-mcp.service, dérive vs audit).
- Phase 3 : repo `github-mcp-gateway` poussé, CI verte sur run précédent.
- Phase 4 : fix OAuth discovery (ressource sans /oauth, resource_metadata doc URL)
  + injection PAT par la gateway (upstream http exige Bearer par requête, preuve
  token.go v1.12.0). 104/104 tests gateway+redaction verts.
- Phase 6 : /srv/github installé, image v1.12.0@sha256:46cdbbd8 pinnée, MRTR généré,
  upstream+gateway actifs loopback, code+venv root:root, discovery loopback OK.
- Phase 7 : 7 blocs nginx insérés (script idempotent, backup, nginx -t OK),
  PRM/AS/401 vérifiés depuis Internet, autres MCP à 200.
- Phases 8-9 : lecture OK (86 tools, get_me Revens2), écriture OK (issue #2 créée,
  relue, fermée ; #1 fermée en cleanup). Absences : voir plan.md (scopes PAT).
- Phase 11 (revue 1) : NO-GO conditionnel, 4 bloquants LEVÉS (argv PAT/phrase via
  stdin, EtatOAuthCorrompu→503 + handler global, garde loopback upstream, expiry
  lire_code) + hygiène (venv root, FICHIER_CLIENTS, 5/7 blocs, docstrings).
  Revalidation : 104 tests verts, val_github lecture verte post-déploiement.

## À faire
- [x] Créer le dépôt GitHub `Revens2/github-mcp-gateway` + push.
- [x] VPS : backup nginx/systemd, `/srv/github`, pull image + digest, install gateway.
- [ ] PAT : action humaine (création + saisie terminal, jamais dans le chat).
- [ ] Phrase de consentement via `creer-phrase-github-mcp.sh` (humain).
- [ ] `val_github.py` lecture + `--create --repo PROPRIO/DEPOT` (moi, dès PAT présent).
- [ ] Connecteur ChatGPT Web + E2E RW depuis ChatGPT + cleanup (Titou).
- [ ] `github-code-review` (GO/NO-GO), revue Astra, GO production, rapport final.

## Décisions
- CAS A : officiel HTTP direct, pas de Rust (preuves : main.go, streamable-http.md).
- PAT dédié MCP (classic si besoin max), séparé du token OAuth ChatGPT.
- Politique full RW 94/94, admin vide, fail-closed sur inconnu.
- /srv/github (modèle tasks/astra), secrets 0600, upstream Docker loopback.
- Ports : upstream **8800** + gateway **8799** (8798 pris par `activity-mcp.service`,
  résident permanent découvert en live le 2026-09-10 — dérive vs audit) ; 8799 libre.

## Blocages actifs
- PAT GitHub : saisie humaine sur le VPS requise (phase 5).
- Consentement ChatGPT : configuration connecteur + phrase, côté Titou.

## Validation
- [x] Catalogue 94 tools (README v1.12.0) classés 59L/35E.
- [x] pytest gateway+redaction : 96 passed.
- [ ] CI verte (après push).
- [ ] E2E VPS lecture/écriture + ChatGPT Web.
