"""Garde-fous secrets de la passerelle GitHub : redaction, fail-closed, canary.

- /health, 401 et 404 ne fuient jamais le jeton statique ni le PAT ;
- demarrage sans issuer : erreur immediate (fail-closed) ;
- consentement sans empreinte configuree : 503 (jamais d'ouverture) ;
- tools/list preserve les schemas/annotation upstream (proxy transparent) ;
- catalogue : 59 lecture + 35 ecriture, disjoints ;
- aucun secret/canary (ghp_*, github_pat_*, PAT renseigne) dans le depot.
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import threading
import uuid
from pathlib import Path

import httpx
import pytest
import uvicorn
from starlette.applications import Starlette
from starlette.responses import JSONResponse, Response
from starlette.routing import Route

from github_gateway.app import construire_application
from github_gateway.oauth import hacher_phrase
from github_gateway.politique import OUTILS_ECRITURE, OUTILS_LECTURE

EMETTEUR = "https://github.example.test"
CANARY_JETON = "canary-" + "z" * 33  # 40 car., jamais un vrai secret
CANARY_PAT = "pat-" + "q" * 36  # PAT interne factice, jamais un vrai secret
PHRASE = "phrase-de-test-2026"


@pytest.fixture()
def environ(tmp_path, monkeypatch):
    monkeypatch.setenv("GITHUB_MCP_ISSUER", EMETTEUR)
    monkeypatch.setenv("GITHUB_MCP_UPSTREAM", "http://127.0.0.1:9")  # port ferme
    monkeypatch.setenv("GITHUB_MCP_OAUTH_DIR", str(tmp_path))
    monkeypatch.setenv("GITHUB_MCP_TOKEN", CANARY_JETON)
    monkeypatch.setenv("GITHUB_MCP_TOKEN_SCOPES", "github:lecture github:ecriture")
    monkeypatch.setenv("GITHUB_MCP_CONSENT_HASH", hacher_phrase(PHRASE))
    return tmp_path


def _client(pat: str | None = CANARY_PAT) -> httpx.AsyncClient:
    return httpx.AsyncClient(
        transport=httpx.ASGITransport(app=construire_application(jeton_upstream=pat)),
        base_url=EMETTEUR,
    )


def _courir(coro):
    return asyncio.run(coro)


def test_sante_ne_fuit_pas_le_jeton(environ):
    async def _t():
        async with _client() as c:
            r = await c.get("/health")
            assert r.status_code == 200
            assert CANARY_JETON not in r.text
            assert CANARY_PAT not in r.text
            assert r.json()["upstream_auth"] == "configure"

    _courir(_t())


def test_erreur_metier_ne_fuit_pas_le_pat(environ):
    """Un refus local (outil inconnu) ne contient ni le PAT ni le jeton."""
    import socket
    import time

    async def _post(request):
        corps = json.loads(await request.body())
        return JSONResponse({"jsonrpc": "2.0", "id": corps.get("id"), "result": {"tools": []}})

    app_stub = Starlette(routes=[Route("/mcp", _post, methods=["POST"])])
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.listen(128)
    serveur = uvicorn.Server(uvicorn.Config(app_stub, log_level="error"))
    threading.Thread(target=serveur.run, kwargs={"sockets": [sock]}, daemon=True).start()
    for _ in range(300):
        if serveur.started:
            break
        time.sleep(0.02)
    try:
        os.environ["GITHUB_MCP_UPSTREAM"] = f"http://127.0.0.1:{port}"

        async def _t():
            async with _client() as c:
                entetes = {
                    "Content-Type": "application/json",
                    "Accept": "application/json, text/event-stream",
                    "Authorization": f"Bearer {CANARY_JETON}",
                }
                r = await c.post(
                    "/mcp",
                    content=json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}).encode(),
                    headers=entetes,
                )
                session = r.headers.get("mcp-session-id")
                r = await c.post(
                    "/mcp",
                    content=json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                                        "params": {"name": "outil-inexistant", "arguments": {}}}).encode(),
                    headers={**entetes, **({"mcp-session-id": session} if session else {})},
                )
                assert CANARY_PAT not in r.text
                assert CANARY_JETON not in r.text

        _courir(_t())
    finally:
        serveur.should_exit = True
        sock.close()


def test_401_et_404_ne_fuient_pas_le_jeton(environ):
    async def _t():
        async with _client() as c:
            r = await c.post(
                "/mcp",
                content=json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}).encode(),
                headers={"Content-Type": "application/json", "Accept": "application/json, text/event-stream"},
            )
            assert r.status_code == 401
            assert CANARY_JETON not in r.text
            assert CANARY_JETON not in str(r.headers)
            r = await c.get("/chemin-inexistant")
            assert r.status_code == 404
            assert CANARY_JETON not in r.text

    _courir(_t())


def test_demarrage_sans_issuer_fail_closed(environ, monkeypatch):
    monkeypatch.delenv("GITHUB_MCP_ISSUER")
    with pytest.raises(RuntimeError):
        construire_application()


def test_consentement_sans_empreinte_503(environ, monkeypatch):
    """Sans GITHUB_MCP_CONSENT_HASH : le consentement refuse (503), jamais 302."""
    monkeypatch.delenv("GITHUB_MCP_CONSENT_HASH")

    async def _t():
        async with _client() as c:
            r = await c.post(
                "/register",
                json={
                    "client_name": "t",
                    "redirect_uris": ["https://chatgpt.com/aip/callback"],
                    "grant_types": ["authorization_code", "refresh_token"],
                    "response_types": ["code"],
                    "token_endpoint_auth_method": "client_secret_post",
                    "scope": "github:lecture",
                },
            )
            assert r.status_code == 201, r.text
            client = r.json()
            import base64
            import hashlib

            verifier = base64.urlsafe_b64encode(os.urandom(32)).rstrip(b"=").decode()
            challenge = base64.urlsafe_b64encode(
                hashlib.sha256(verifier.encode()).digest()
            ).rstrip(b"=").decode()
            r = await c.get(
                "/authorize",
                params={
                    "client_id": client["client_id"],
                    "redirect_uri": client["redirect_uris"][0],
                    "response_type": "code",
                    "code_challenge_method": "S256",
                    "code_challenge": challenge,
                    "state": "s",
                    "scope": "github:lecture",
                },
            )
            assert r.status_code in (302, 307), r.text
            demande = r.headers["location"].split("demande=", 1)[1]
            r = await c.post("/consentement", data={"demande": demande, "phrase": PHRASE})
            assert r.status_code == 503
            assert CANARY_JETON not in r.text

    _courir(_t())


def _serveur_stub_schemas() -> tuple:
    """Upstream factice renvoyant des schemas/annotations riches a preserver."""
    import socket
    import time

    outil = {
        "name": "get_me",
        "description": "Get my user profile",
        "inputSchema": {"type": "object", "properties": {"x": {"type": "string"}}},
        "annotations": {"readOnlyHint": True, "destructiveHint": False},
    }

    async def _post(request):
        corps = json.loads(await request.body())
        id_ = corps.get("id")
        session = request.headers.get("mcp-session-id", "")
        if corps.get("method") == "initialize":
            return JSONResponse(
                {"jsonrpc": "2.0", "id": id_, "result": {"protocolVersion": "2025-06-18", "capabilities": {}}},
                headers={"mcp-session-id": str(uuid.uuid4())},
            )
        return JSONResponse(
            {"jsonrpc": "2.0", "id": id_, "result": {"tools": [outil]}},
            headers={"mcp-session-id": session},
        )

    app = Starlette(routes=[Route("/mcp", _post, methods=["POST"])])
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.listen(128)
    serveur = uvicorn.Server(uvicorn.Config(app, log_level="error"))
    threading.Thread(target=serveur.run, kwargs={"sockets": [sock]}, daemon=True).start()
    for _ in range(300):
        if serveur.started:
            break
        time.sleep(0.02)
    return serveur, f"http://127.0.0.1:{port}", sock


def test_tools_list_preserve_schemas_et_annotations(environ):
    """Le proxy transmet schemas et annotations upstream sans les reecrire."""
    serveur, url, sock = _serveur_stub_schemas()
    try:
        os.environ["GITHUB_MCP_UPSTREAM"] = url

        async def _t():
            async with _client() as c:
                entetes = {
                    "Content-Type": "application/json",
                    "Accept": "application/json, text/event-stream",
                    "Authorization": f"Bearer {CANARY_JETON}",
                }
                r = await c.post(
                    "/mcp",
                    content=json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}).encode(),
                    headers=entetes,
                )
                session = r.headers["mcp-session-id"]
                r = await c.post(
                    "/mcp",
                    content=json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}).encode(),
                    headers={**entetes, "mcp-session-id": session},
                )
                outils = r.json()["result"]["tools"]
                assert len(outils) == 1
                assert outils[0]["description"] == "Get my user profile"
                assert outils[0]["inputSchema"]["type"] == "object"
                assert outils[0]["annotations"]["readOnlyHint"] is True

        _courir(_t())
    finally:
        serveur.should_exit = True
        sock.close()


def test_catalogue_94_outils_disjoints():
    assert len(OUTILS_LECTURE) == 59, len(OUTILS_LECTURE)
    assert len(OUTILS_ECRITURE) == 35, len(OUTILS_ECRITURE)
    assert not (set(OUTILS_LECTURE) & set(OUTILS_ECRITURE))
    assert all(nom and " " not in nom for nom in (*OUTILS_LECTURE, *OUTILS_ECRITURE))


def test_pas_de_secret_dans_le_depot():
    """Canary : aucun PAT (ghp_*/github_pat_*) ni PAT renseigne versionne."""
    racine = Path(__file__).resolve().parent.parent
    motif_pat = re.compile("ghp" + "_" + r"[A-Za-z0-9]{10,}")
    motif_fgp = re.compile("github_pat" + "_" + r"[A-Za-z0-9_]{10,}")
    # Assignation avec une vraie valeur, ligne par ligne : les placeholders de
    # documentation (%s, ${...}, $VAR, <...>, vide) ne sont pas des secrets.
    motif_assign = re.compile(r"GITHUB_PERSONAL_ACCESS_TOKEN\s*=\s*(\S+)")
    fautifs: list[str] = []

    def _assigne_un_secret(texte: str) -> bool:
        for ligne in texte.splitlines():
            m = motif_assign.search(ligne)
            if not m:
                continue
            valeur = m.group(1).strip("\"'")
            if valeur and not valeur.startswith(("$", "%", "<")):
                return True
        return False
    for chemin in racine.rglob("*"):
        if not chemin.is_file() or ".git" in chemin.parts or "__pycache__" in chemin.parts:
            continue
        try:
            texte = chemin.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        if __file__ in str(chemin):
            # Ce fichier de test construit ses motifs par concatenation : il ne
            # doit pas se denoncer lui-meme ; on ne verifie que l'assignation.
            if _assigne_un_secret(texte):
                fautifs.append(str(chemin))
            continue
        if motif_pat.search(texte) or motif_fgp.search(texte) or _assigne_un_secret(texte):
            fautifs.append(str(chemin))
    assert fautifs == [], f"secret/canary detecte dans : {fautifs}"
