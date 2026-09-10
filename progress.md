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


## Revue contre-revue Phase 11 (delta 9f50a4d..HEAD, 504cf3f2)

### Perimetre
12 fichiers, delta 9f50a4d..HEAD (d9e2d3d, 5e831b1) : 4 correctifs bloquants + hygiene + 4 tests. Diff relu en brut (proxy, sans resume RTK — le resume avait masque le doublon val_github, leve au brut) + graphe : build 19 fichiers / 219 noeuds / 1772 aretes, update base 9f50a4d : 12 fichiers, 16 symboles, score 0,85, 0 flot affecte. Blast radius app.py profondeur 2 : 166 noeuds (consentement, FournisseurOAuth, MagasinOAuth, ProxyMCP, server.main, tests).
### Blast radius
- inspecter-scopes-pat.sh : usage manuel sudo uniquement ; cible api.github.com inchangee.
- creer-phrase-github-mcp.sh : ecrit GITHUB_MCP_CONSENT_HASH dans /srv/github/secrets/github.env ; restart service.
- consentement.py afficher/valider + app.py handler global : routes SDK (/register, /token), /consentement ; /mcp authentifie via BearerAuthBackend externe : hors handler (voir Risques).
- oauth.py lire_code : load_authorization_code / exchange_authorization_code (SDK).
- _config garde loopback : construire_application / server.main (demarrage) ; aucun appelant prod ne passe upstream en parametre (server.py:19 sans args).
- REPERTOIRE_DEFAUT : MagasinOAuth par defaut, fichier_clients(), install-gateway.sh, unite systemd.
### Risques
- Bloquant : aucun. Les 4 fermetures sont confirmees (voir Verdict) ; fail-closed conserve partout ; zero secret dans le delta (balayage brut des lignes + : rien).
- Majeur (reserve, pas de NO-GO) : /mcp + etat corrompu non couvert. Le handler global vit sur le Starlette interne (app.py:185) mais l’authentification tourne dans le middleware externe BearerAuthBackend (app.py:190-193). Un GET /mcp avec Bearer OAuth alors que etat.json est corrompu leve EtatOAuthCorrompu dans load_access_token hors du handler : 500 probable au lieu du 503 annonce (/mcp via le SDK, app.py:178-179). Tests ajoutes ne couvrent que /consentement et /register. Fail-closed (pas de token, pas de fuite) ; impact = diagnostic en situation deja en panne. A lever : corrompre etat.json puis GET /mcp avec Bearer valide ; si 500, attraper dans le backend auth + ajouter le test.
- Mineur : creer_code non wrappe. consentement.py:187 hors try/except ; TOCTOU entre apercu et pose : remonte au handler global, 503 JSON au lieu de 503 HTML (jamais de 500). Uniformiser ou laisser.
- Mineur : commentaire inexact. inspecter-scopes-pat.sh:5-6 dit stdin vers python3, en realite lecture fichier via sys.argv[1] (le chemin seul transite en argv, pas le secret : secu OK, corriger le commentaire).
- Mineur : HASH en argv de sed. creer-phrase-github-mcp.sh:33 expose l’empreinte PBKDF2 salee 600k dans ps un bref instant (pas la phrase ; pattern pre-existant). Acceptable.
- Mineur : garde contournable par parametre. construire_application(upstream=...) ecrase apres validation sans re-valider (app.py:124-126) ; aucun appelant prod concerne. Durcir en validant la valeur finale.
- Test gap outil (relativise) : le graphe liste main, _config, _etat_corrompu, _indisponible, routes_consentement non testes alors que les 4 nouveaux tests les exercent (rattachement TESTED_BY incomplet de l’outil, pas un vrai trou).
### Tests a lancer (non executes : mission lecture seule)
- python -m pytest tests/test_gateway.py -q -k loopback_or_corrompu_or_lire_code (4 nouveaux)
- python -m pytest tests/ -q (104 annonces : gateway + redaction + oauth_magasin)
- bash -n deploy/inspecter-scopes-pat.sh ; bash -n deploy/creer-phrase-github-mcp.sh ; bash -n deploy/install-gateway.sh
- A AJOUTER avant prod : test /mcp etat corrompu avec Bearer (cf. reserve majeure).
### Verdict
GO avec une reserve (test /mcp corrompu a ajouter, durcir si 500 confirme). Confirmations : (1) PAT hors argv — inspecter-scopes-pat.sh:17-33 lit le fichier en process, erreur sans secret (nom de classe seul) ; (2) phrase hors argv — creer-phrase-github-mcp.sh:28-30 via stdin (builtin printf, pas de process) + unset P1 P2, chemin /srv/github/secrets/github.env corrige ; (3) EtatOAuthCorrompu vers 503 — consentement.py:131-134,161-164,180-183 + app.py:177-185 JSON + oauth.py:300-306 expiry (flux normal intact : poser_code expire_a now+90, legacy sans expire_a en fail-closed) ; (4) garde loopback — app.py:82-86, allowlist exacte (127.0.0.1/localhost/::1 ; [::1] OK via urlparse, localhost.evil.com refuse), prod 127.0.0.1:8800 passe. Hygiene verifiee : venv+code root:root (install-gateway.sh:30), FICHIER_CLIENTS zero reference, REPERTOIRE_DEFAUT /srv/github/data/oauth aligne (install:17,42), 7 blocs docs, init docstring, doublon val_github retire (9f50a4d:224-225, usages intacts). GET vs HEAD sans regression (headers equivalents, echec reseau desormais exit 1 explicite). Aucun commentaire gh poste (attente accord explicite).
