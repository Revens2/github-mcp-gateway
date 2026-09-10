#!/usr/bin/env python3
"""Validation de la chaine MCP GitHub a travers la passerelle (127.0.0.1:8799).

Lit le jeton statique dans /srv/github/secrets/github.env (jamais affiche),
ouvre une session MCP, puis execute des appels reels. Contenus prives limites
aux compteurs et a l'artefact de test cree ici.

Profil attendu (voir github_gateway/politique.py, upstream v1.12.0) :
- 59 outils de lecture + 35 mutateurs = 94 tools avec un jeton portant
  github:lecture + github:ecriture ;
- outils critiques toujours presents : get_me, get_file_contents,
  create_branch, create_or_update_file, issue_write, pull_request_read...

Avec `--create --repo PROPRIO/DEPOT`, un E2E ecriture reversible est execute :
creation d'une issue jetable `TEST-MCP-GITHUB-E2E-<timestamp>` -> relecture ->
fermeture. L'issue fermee reste visible (GitHub ne supprime pas les issues),
son titre la marque comme artefact de test. Jamais de push sur main/branche
par defaut, jamais de depot non designe : --repo est obligatoire en ecriture.

Usage : sudo /srv/github/venv/bin/python chemin/du/repo/deploy/val_github.py [--create --repo X/Y]
(httpx requis : fourni par le venv de la passerelle).
"""

from __future__ import annotations

import json
import sys

import httpx
from datetime import datetime, timezone

BASE = "http://127.0.0.1:8799/mcp"  # nosemgrep: passerelle en boucle locale (127.0.0.1), jamais exposee
ENV = "/srv/github/secrets/github.env"

# Outils critiques : absence = echec. Les extras futurs (upstream plus recent
# que la politique) donnent une alerte, pas un echec.
OUTILS_LECTURE_CRITIQUES: tuple[str, ...] = (
    "get_me",
    "get_file_contents",
    "search_repositories",
    "issue_read",
    "list_issues",
    "pull_request_read",
)
OUTILS_ECRITURE_CRITIQUES: tuple[str, ...] = (
    "create_branch",
    "create_or_update_file",
    "issue_write",
    "create_pull_request",
)


def lire_jeton() -> str:
    with open(ENV, encoding="utf-8") as f:
        for ligne in f:
            if ligne.startswith("GITHUB_MCP_TOKEN="):
                return ligne.split("=", 1)[1].strip().strip('"')
    raise SystemExit("GITHUB_MCP_TOKEN absent de l'environnement")


def appeler(session: str | None, ident: int, methode: str, params: dict) -> tuple[str | None, dict]:
    # Boucle locale uniquement : la passerelle n'ecoute que sur 127.0.0.1:8799,
    # nginx est le seul point d'entree externe. HTTP local = configuration voulue.
    corps = {"jsonrpc": "2.0", "id": ident, "method": methode, "params": params}
    entetes = {
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
        "Authorization": f"Bearer {lire_jeton()}",
    }
    if session:
        entetes["mcp-session-id"] = session
    with httpx.Client(timeout=120.0) as client:  # nosemgrep: python.lang.security.audit.insecure-transport -- boucle locale 127.0.0.1 voulue, jamais exposee
        reponse = client.post(BASE, json=corps, headers=entetes)
        reponse.raise_for_status()
        session_id = reponse.headers.get("mcp-session-id") or session
        brut = reponse.text
    payload: dict | None = None
    for ligne in brut.splitlines():
        if ligne.startswith("data: "):
            payload = json.loads(ligne[6:])
    if payload is None:
        payload = json.loads(brut)
    return session_id, payload


def texte(paquet: dict) -> str:
    resultat = paquet.get("result") or {}
    for contenu in resultat.get("content") or []:
        if contenu.get("type") == "text":
            return str(contenu.get("text", ""))
    if paquet.get("error"):
        return f"ERREUR JSON-RPC: {paquet['error']}"
    return json.dumps(paquet, ensure_ascii=False)[:500]


def est_erreur(paquet: dict, t: str) -> bool:
    resultat = paquet.get("result") or {}
    return (
        bool(paquet.get("error"))
        or resultat.get("isError") is True
        or t.startswith("ERREUR")
    )


def verifier_tools_list(r: dict) -> list[str]:
    outils = r["result"]["tools"]
    noms = [t["name"] for t in outils]
    print(f"tools/list        : {len(noms)} outils")
    manquants = [n for n in (*OUTILS_LECTURE_CRITIQUES, *OUTILS_ECRITURE_CRITIQUES) if n not in noms]
    if manquants:
        print("tools/list        : ECHEC -> outils critiques absents :", ", ".join(manquants))
        sys.exit(1)
    print("tools/list        : OK (critiques lecture+ecriture presents)")
    return noms


def e2e_issue(session: str, repo: str) -> None:
    """Cree, relit puis ferme une issue jetable sur `repo` (PROPRIO/DEPOT)."""
    try:
        proprio, depot = repo.split("/", 1)
    except ValueError:
        print("E2E               : ECHEC -> --repo doit valoir PROPRIO/DEPOT")
        sys.exit(1)
    horodatage = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    titre = f"TEST-MCP-GITHUB-E2E-{horodatage}"
    numero: int | None = None

    # 1. creation
    session, r = appeler(session, 10, "tools/call", {
        "name": "issue_write",
        "arguments": {
            "method": "create", "owner": proprio, "repo": depot,
            "title": titre,
            "body": "Artefact de test automatique du MCP GitHub (E2E reversible, sera ferme).",
        },
    })
    t = texte(r)
    if est_erreur(r, t):
        print("issue_write/create: ECHEC ->", t[:400])
        sys.exit(1)
    import re
    m = re.search(r'"number"\s*:\s*(\d+)', t)
    numero = int(m.group(1)) if m else None
    if numero is None:
        print("issue_write/create: ECHEC -> numero introuvable :", t[:400])
        sys.exit(1)
    print(f"issue_write/create: OK -> {repo}#{numero} ({titre})")

    try:
        # 2. relecture
        session, r = appeler(session, 11, "tools/call", {
            "name": "issue_read",
            "arguments": {"method": "get", "owner": proprio, "repo": depot, "issue_number": numero},
        })
        t = texte(r)
        if est_erreur(r, t) or titre not in t:
            print("issue_read        : ECHEC ->", t[:400])
            sys.exit(1)
        print(f"issue_read        : OK -> titre retrouve sur #{numero}")

        # 3. fermeture (cleanup : GitHub ne supprime pas les issues)
        session, r = appeler(session, 12, "tools/call", {
            "name": "issue_write",
            "arguments": {"method": "update", "owner": proprio, "repo": depot,
                          "issue_number": numero, "state": "closed"},
        })
        t = texte(r)
        if est_erreur(r, t):
            print("issue_write/close : ECHEC ->", t[:400])
            sys.exit(1)
        print(f"issue_write/close : OK -> #{numero} fermee (artefact nettoye)")
    except SystemExit:
        raise
    except Exception as exc:  # cleanup best-effort en cas d'imprevu
        print(f"E2E               : incident ({exc}), tentative de fermeture #{numero}")
        try:
            appeler(session, 13, "tools/call", {
                "name": "issue_write",
                "arguments": {"method": "update", "owner": proprio, "repo": depot,
                              "issue_number": numero, "state": "closed"},
            })
        except Exception:
            pass
        sys.exit(1)


def main() -> None:
    creer = "--create" in sys.argv
    repo = ""
    if "--repo" in sys.argv:
        try:
            repo = sys.argv[sys.argv.index("--repo") + 1]
        except IndexError:
            repo = ""
    if creer and not repo:
        print("E2E ecriture : --repo PROPRIO/DEPOT obligatoire (jamais de depot par defaut).")
        sys.exit(1)

    session, r = appeler(None, 1, "initialize", {
        "protocolVersion": "2025-06-18",
        "capabilities": {},
        "clientInfo": {"name": "val-github", "version": "1"},
    })
    assert "result" in r, texte(r)
    print("initialize        : OK")

    session, r = appeler(session, 2, "tools/list", {})
    verifier_tools_list(r)

    session, r = appeler(session, 3, "tools/call", {"name": "get_me", "arguments": {}})
    t = texte(r)
    if est_erreur(r, t):
        print("get_me            : ECHEC ->", t[:300])
        sys.exit(1)
    print("get_me            : OK ->", t[:160].replace("\n", " "))

    if creer:
        e2e_issue(session, repo)
        print("E2E ECRITURE      : OK (issue creee, relue, fermee)")
    else:
        print("(mode lecture seule : ajouter --create --repo PROPRIO/DEPOT pour l'E2E ecriture)")


if __name__ == "__main__":
    main()
