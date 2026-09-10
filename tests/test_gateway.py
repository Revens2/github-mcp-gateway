"""Tests d'integration de la passerelle GitHub (pattern vault-mcp).

Couvre le contrat que ChatGPT/claude.ai exigent :
- decouverte (RFC 8414 + RFC 9728) ;
- enregistrement dynamique (RFC 7591) ;
- consentement humain (phrase de passe) puis echange du code (PKCE S256) ;
- /mcp anonyme -> 401 avec resource_metadata ;
- /mcp avec jeton -> proxy vers l'upstream, autorisation outil par outil :
    * outil inconnu ou non classe : jamais annonce, tools/call forge refuse
      meme avec un jeton portant github:ecriture (l'upstream ne recoit
      jamais l'appel) ;
    * jeton `github:lecture` : outils de lecture uniquement, aucune mutation ;
    * jeton `github:lecture github:ecriture` : lecture + ecriture (94 tools) ;
    * `delete_repository` (gate MRTR cote upstream) : autorise avec la portee
      ecriture, comme toute ecriture officielle.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import os
import threading
import uuid

import httpx
import pytest
import uvicorn
from starlette.applications import Starlette
from starlette.responses import JSONResponse, Response
from starlette.routing import Route

from github_gateway.app import construire_application
from github_gateway.oauth import PORTEE, hacher_phrase
from github_gateway.politique import OUTILS_ADMIN, OUTILS_ECRITURE, OUTILS_LECTURE, PolitiqueOutils

EMETTEUR = "https://github.example.test"
JETON_LECTURE = "l" * 40
JETON_ECRITURE = "e" * 40
PHRASE = "phrase-de-test-2026"
SCOPES_LECTURE = "github:lecture"
SCOPES_ECRITURE = "github:lecture github:ecriture"


def _normaliser_issuer(valeur: str) -> str:
    return valeur.rstrip("/")


@pytest.fixture()
def environ(tmp_path, monkeypatch):
    monkeypatch.setenv("GITHUB_MCP_ISSUER", EMETTEUR)
    monkeypatch.setenv("GITHUB_MCP_UPSTREAM", "http://127.0.0.1:9")  # port ferme
    monkeypatch.setenv("GITHUB_MCP_OAUTH_DIR", str(tmp_path))
    monkeypatch.setenv("GITHUB_MCP_TOKEN", JETON_ECRITURE)
    monkeypatch.setenv("GITHUB_MCP_CONSENT_HASH", hacher_phrase(PHRASE))
    return tmp_path


def _app(jeton: str, portees: str):
    """Application construite pour un jeton statique portant exactement `portees`."""
    os.environ["GITHUB_MCP_TOKEN_SCOPES"] = portees
    return construire_application(jeton_statique=jeton)


def _client(jeton: str, portees: str) -> httpx.AsyncClient:
    app = _app(jeton, portees)
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url=EMETTEUR)


def _json_rpc(methode: str, identifiant: int | None, params: dict | None = None) -> bytes:
    return json.dumps(
        {
            "jsonrpc": "2.0",
            "id": identifiant,
            "method": methode,
            "params": params or {},
        }
    ).encode()


def _verifier_s256(longueur: int = 48) -> tuple[str, str]:
    """(code_verifier, code_challenge S256) conformes RFC 7636."""
    verifier = base64.urlsafe_b64encode(os.urandom(longueur)).rstrip(b"=").decode()
    empreinte = hashlib.sha256(verifier.encode()).digest()
    challenge = base64.urlsafe_b64encode(empreinte).rstrip(b"=").decode()
    return verifier, challenge


def _courir(coro):
    return asyncio.run(coro)


# --- Decouverte -----------------------------------------------------------------------
def test_metadonnees_serveur_autorisation(environ):
    async def _t():
        async with _client(JETON_ECRITURE, SCOPES_ECRITURE) as c:
            r = await c.get("/.well-known/oauth-authorization-server")
            assert r.status_code == 200
            d = r.json()
            assert _normaliser_issuer(d["issuer"]) == EMETTEUR
            assert d["registration_endpoint"].startswith(EMETTEUR)
            assert "S256" in d["code_challenge_methods_supported"]
            assert "client_secret_post" in d["token_endpoint_auth_methods_supported"]
            portees = d.get("scopes_supported") or []
            assert PORTEE in portees

    _courir(_t())


def test_metadonnees_ressource_protegee(environ):
    async def _t():
        async with _client(JETON_ECRITURE, SCOPES_ECRITURE) as c:
            r = await c.get("/.well-known/oauth-protected-resource/mcp")
            assert r.status_code == 200
            d = r.json()
            assert d["resource"] == f"{EMETTEUR}/mcp"
            assert [_normaliser_issuer(x) for x in d["authorization_servers"]] == [EMETTEUR]
            assert "github:ecriture" in d["scopes_supported"]

    _courir(_t())


def test_ressource_derivee_issuer_oauth_sans_prefixe(environ, monkeypatch):
    """Non-regression live (astra/tasks/calendar) : avec un issuer path-scope
    https://h/oauth/github, la ressource annoncee est https://h/github/mcp
    (sans /oauth), dans la PRM comme dans le 401 — octet-pour-octet avec nginx."""
    emetteur_oauth = "https://github.example.test/oauth/github"
    monkeypatch.setenv("GITHUB_MCP_ISSUER", emetteur_oauth)
    app = construire_application(jeton_statique=JETON_ECRITURE)

    async def _t():
        # Base SANS chemin : en production nginx transmet les chemins absolus
        # (/.well-known/...) tels quels a la passerelle (root_path /).
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="https://github.example.test") as c:
            r = await c.get("/.well-known/oauth-protected-resource/github/mcp")
            assert r.status_code == 200, r.text
            d = r.json()
            assert d["resource"] == "https://github.example.test/github/mcp"
            assert [_normaliser_issuer(x) for x in d["authorization_servers"]] == [emetteur_oauth]
            r = await c.post(
                "/mcp",
                content=_json_rpc("initialize", 1),
                headers={"Content-Type": "application/json", "Accept": "application/json, text/event-stream"},
            )
            assert r.status_code == 401
            assert 'resource_metadata="https://github.example.test/.well-known/oauth-protected-resource/github/mcp"' in r.headers.get(
                "www-authenticate", ""
            )

    _courir(_t())


# --- Acces /mcp sans jeton -------------------------------------------------------------
def test_mcp_anonyme_refuse_post(environ):
    async def _t():
        async with _client(JETON_ECRITURE, SCOPES_ECRITURE) as c:
            r = await c.post(
                "/mcp",
                content=_json_rpc("initialize", 1),
                headers={"Content-Type": "application/json", "Accept": "application/json, text/event-stream"},
            )
            assert r.status_code == 401
            assert "resource_metadata" in r.headers.get("www-authenticate", "")

    _courir(_t())


def test_mcp_anonyme_refuse_get(environ):
    async def _t():
        async with _client(JETON_ECRITURE, SCOPES_ECRITURE) as c:
            r = await c.get("/mcp")
            assert r.status_code == 401

    _courir(_t())


def test_mcp_chemin_inconnu(environ):
    async def _t():
        async with _client(JETON_ECRITURE, SCOPES_ECRITURE) as c:
            r = await c.get("/")
            assert r.status_code == 404

    _courir(_t())


# --- Enregistrement + consentement + token --------------------------------------------
def test_flux_oauth_complet(environ):
    async def _t():
        async with _client(JETON_ECRITURE, SCOPES_ECRITURE) as c:
            # 1. Enregistrement dynamique (RFC 7591)
            r = await c.post(
                "/register",
                json={
                    "client_name": "chatgpt-test",
                    "redirect_uris": ["https://chatgpt.com/aip/callback"],
                    "grant_types": ["authorization_code", "refresh_token"],
                    "response_types": ["code"],
                    "token_endpoint_auth_method": "client_secret_post",
                    "scope": PORTEE,
                },
            )
            assert r.status_code == 201, r.text
            client = r.json()
            assert client["client_id"] and client["client_secret"]

            # 2. Demande d'autorisation (PKCE S256)
            verifier, challenge = _verifier_s256()
            params = {
                "client_id": client["client_id"],
                "redirect_uri": client["redirect_uris"][0],
                "response_type": "code",
                "code_challenge_method": "S256",
                "code_challenge": challenge,
                "state": "etat-123",
                "scope": PORTEE,
            }
            r = await c.get("/authorize", params=params)
            assert r.status_code in (302, 307), r.text
            location = r.headers["location"]
            assert location.startswith(f"{EMETTEUR}/consentement?demande=")
            demande = location.split("demande=", 1)[1]

            # 3. Page de consentement affichee
            r = await c.get(f"/consentement?demande={demande}")
            assert r.status_code == 200
            assert "depots GitHub" in r.text

            # 4. Mauvaise phrase -> 401 ; bonne phrase -> code
            r = await c.post(
                "/consentement",
                data={"demande": demande, "phrase": "mauvaise"},
            )
            assert r.status_code == 401
            r = await c.post(
                "/consentement",
                data={"demande": demande, "phrase": PHRASE},
            )
            assert r.status_code == 302, r.text
            cible = r.headers["location"]
            assert "code=" in cible and "state=etat-123" in cible
            code = cible.split("code=", 1)[1].split("&", 1)[0]

            # 5. Echange du code
            r = await c.post(
                "/token",
                data={
                    "grant_type": "authorization_code",
                    "code": code,
                    "redirect_uri": client["redirect_uris"][0],
                    "client_id": client["client_id"],
                    "client_secret": client["client_secret"],
                    "code_verifier": verifier,
                },
            )
            assert r.status_code == 200, r.text
            jetons = r.json()
            assert jetons["token_type"] == "Bearer"
            assert jetons["access_token"] and jetons["refresh_token"]
            portees = jetons["scope"].split()
            assert PORTEE in portees and "github:ecriture" in portees

            # 6. Un code ne s'echange qu'une fois
            r = await c.post(
                "/token",
                data={
                    "grant_type": "authorization_code",
                    "code": code,
                    "redirect_uri": client["redirect_uris"][0],
                    "client_id": client["client_id"],
                    "client_secret": client["client_secret"],
                    "code_verifier": verifier,
                },
            )
            assert r.status_code == 400
            assert "invalid_grant" in r.text

    _courir(_t())


# --- Jeton statique + proxy + politique -----------------------------------------------
# Inventaire de l'upstream github-mcp-server v1.12.0 (94 tools) : les outils
# classes par la politique + un nom totalement inconnu (garde fail-closed : une
# future version upstream ne doit jamais exposer silencieusement un outil).
_OUTILS_UPSTREAM = sorted(
    OUTILS_LECTURE
    | OUTILS_ECRITURE
    | OUTILS_ADMIN
    | {"outil-upstream-inconnu"}
)

# Profil complet voulu : l'integralite du catalogue officiel (59 lecture + 35 ecriture).
_PROFIL_COMPLET = frozenset(set(OUTILS_LECTURE) | set(OUTILS_ECRITURE))


def _serveur_stub(outils: list[str] | None = None) -> tuple[uvicorn.Server, str, object, list]:
    """Upstream factice : initialize/session, tools/list, tools/call comptabilises.

    Retourne (serveur, url, socket, recus) ou `recus` recoit chaque tools/call
    relaye par le proxy : {"name": ..., "id": ...}.
    """
    import socket
    import time

    recus: list[dict] = []

    async def _post(request):
        def _reponse(donnees, session):
            """Repond en SSE (comme l'upstream reel 2.6.3) quand le client ne demande
            que text/event-stream, sinon en JSON nu."""
            accept = request.headers.get("accept", "")
            if "text/event-stream" in accept and "application/json" not in accept:
                corps = "event: message\ndata: " + json.dumps(donnees, ensure_ascii=False) + "\n\n"
                return Response(corps, media_type="text/event-stream", headers={"mcp-session-id": session})
            return JSONResponse(donnees, headers={"mcp-session-id": session})

        corps = await request.body()
        donnees = json.loads(corps)
        methode = donnees.get("method")
        id_ = donnees.get("id")
        session = request.headers.get("mcp-session-id", "")
        if methode == "initialize":
            return _reponse(
                {"jsonrpc": "2.0", "id": id_, "result": {"protocolVersion": "2025-06-18", "capabilities": {}, "serverInfo": {"name": "github-mcp-server", "version": "v1.12.0"}}},
                str(uuid.uuid4()),
            )
        if methode == "tools/list":
            return _reponse(
                {
                    "jsonrpc": "2.0",
                    "id": id_,
                    "result": {
                        "tools": [
                            {"name": nom, "description": nom} for nom in (outils or _OUTILS_UPSTREAM)
                        ]
                    },
                },
                session,
            )
        if methode == "tools/call":
            params = donnees.get("params") or {}
            recus.append({"name": params.get("name"), "id": id_})
            return _reponse(
                {"jsonrpc": "2.0", "id": id_, "result": {"content": [{"type": "text", "text": "ok"}]}},
                session,
            )
        return _reponse({"jsonrpc": "2.0", "id": id_, "result": {}}, session)

    app = Starlette(routes=[Route("/mcp", _post, methods=["POST"])])
    socket_ecoute = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    socket_ecoute.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    socket_ecoute.bind(("127.0.0.1", 0))
    port = socket_ecoute.getsockname()[1]
    socket_ecoute.listen(128)
    config = uvicorn.Config(app, log_level="error")
    serveur = uvicorn.Server(config)
    thread = threading.Thread(target=serveur.run, kwargs={"sockets": [socket_ecoute]}, daemon=True)
    thread.start()
    for _ in range(300):
        if serveur.started:
            break
        time.sleep(0.02)
    return serveur, f"http://127.0.0.1:{port}", socket_ecoute, recus


def _entetes_autorises(jeton: str) -> dict[str, str]:
    return {
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
        "Authorization": f"Bearer {jeton}",
    }


def test_outil_inconnu_jamais_liste(environ):
    """P0 : un outil non classe n'est annonce a personne, meme avec un jeton full."""

    async def _t():
        serveur, url, _socket_ecoute, recus = _serveur_stub()
        try:
            os.environ["GITHUB_MCP_UPSTREAM"] = url
            async with _client(JETON_ECRITURE, SCOPES_ECRITURE) as c:
                entetes = _entetes_autorises(JETON_ECRITURE)
                r = await c.post("/mcp", content=_json_rpc("initialize", 1), headers=entetes)
                session = r.headers["mcp-session-id"]
                r = await c.post(
                    "/mcp", content=_json_rpc("tools/list", 2), headers={**entetes, "mcp-session-id": session}
                )
                assert r.status_code == 200
                noms = {t["name"] for t in r.json()["result"]["tools"]}
                assert "outil-upstream-inconnu" not in noms
                assert "delete_repository" in noms
        finally:
            serveur.should_exit = True
            if _socket_ecoute:
                _socket_ecoute.close()

    _courir(_t())


def test_outil_inconnu_call_forge_refuse_meme_avec_ecriture(environ):
    """P0 : tools/call forge vers un outil inconnu est refuse AVANT l'upstream,
    meme avec un jeton portant github:ecriture. Le stub prouve que l'upstream
    n'a jamais recu la requete."""

    async def _t():
        serveur, url, _socket_ecoute, recus = _serveur_stub()
        try:
            os.environ["GITHUB_MCP_UPSTREAM"] = url
            async with _client(JETON_ECRITURE, SCOPES_ECRITURE) as c:
                entetes = _entetes_autorises(JETON_ECRITURE)
                r = await c.post("/mcp", content=_json_rpc("initialize", 1), headers=entetes)
                session = r.headers["mcp-session-id"]
                r = await c.post(
                    "/mcp",
                    content=_json_rpc("tools/call", 4, {"name": "outil-upstream-inconnu", "arguments": {}}),
                    headers={**entetes, "mcp-session-id": session},
                )
                assert r.status_code == 200
                corps = r.json()
                assert "error" in corps, corps
                assert corps["error"]["code"] == -32000
                assert recus == [], f"outil inconnu a atteint l'upstream: {recus}"
        finally:
            serveur.should_exit = True
            if _socket_ecoute:
                _socket_ecoute.close()

    _courir(_t())


def test_lecture_seul_peut_appeler_outil_lecture(environ):
    """Lecture : get_me (outil de lecture) est relaye jusqu'a l'upstream."""

    async def _t():
        serveur, url, _socket_ecoute, recus = _serveur_stub()
        try:
            os.environ["GITHUB_MCP_UPSTREAM"] = url
            async with _client(JETON_LECTURE, SCOPES_LECTURE) as c:
                entetes = _entetes_autorises(JETON_LECTURE)
                r = await c.post("/mcp", content=_json_rpc("initialize", 1), headers=entetes)
                session = r.headers["mcp-session-id"]
                r = await c.post(
                    "/mcp",
                    content=_json_rpc("tools/call", 3, {"name": "get_me", "arguments": {}}),
                    headers={**entetes, "mcp-session-id": session},
                )
                assert r.status_code == 200
                assert "ok" in r.text
                assert [a["name"] for a in recus] == ["get_me"]
        finally:
            serveur.should_exit = True
            if _socket_ecoute:
                _socket_ecoute.close()

    _courir(_t())


@pytest.mark.parametrize("outil", sorted(OUTILS_ECRITURE))
def test_lecture_seul_refuse_toute_mutation(environ, outil):
    """Un jeton github:lecture ne peut executer AUCUNE mutation (create_branch,
    delete_repository), meme en forgeant tools/call. L'upstream ne recoit rien."""

    async def _t():
        serveur, url, _socket_ecoute, recus = _serveur_stub()
        try:
            os.environ["GITHUB_MCP_UPSTREAM"] = url
            async with _client(JETON_LECTURE, SCOPES_LECTURE) as c:
                entetes = _entetes_autorises(JETON_LECTURE)
                r = await c.post("/mcp", content=_json_rpc("initialize", 1), headers=entetes)
                session = r.headers["mcp-session-id"]
                r = await c.post(
                    "/mcp",
                    content=_json_rpc("tools/call", 7, {"name": outil, "arguments": {}}),
                    headers={**entetes, "mcp-session-id": session},
                )
                assert r.status_code == 200
                corps = r.json()
                assert "error" in corps, f"mutation {outil} non refusee: {corps}"
                assert corps["error"]["code"] == -32000
                assert recus == [], f"l'upstream a recu un appel interdit: {recus}"
        finally:
            serveur.should_exit = True
            if _socket_ecoute:
                _socket_ecoute.close()

    _courir(_t())


def _reponse_json_rpc(r: httpx.Response) -> dict:
    """Parse une reponse MCP : JSON nu ou enveloppe SSE."""
    if "text/event-stream" in r.headers.get("content-type", ""):
        blocs = [
            ligne[len("data: "):]
            for ligne in r.text.splitlines()
            if ligne.startswith("data: ")
        ]
        return json.loads("".join(blocs))
    return r.json()


def test_outil_inconnu_jamais_liste_en_sse(environ):
    """Un outil inconnu n'est pas annonce non plus quand l'upstream repond en SSE."""

    async def _t():
        serveur, url, _socket_ecoute, recus = _serveur_stub()
        try:
            os.environ["GITHUB_MCP_UPSTREAM"] = url
            async with _client(JETON_ECRITURE, SCOPES_ECRITURE) as c:
                entetes = _entetes_autorises(JETON_ECRITURE)
                r = await c.post("/mcp", content=_json_rpc("initialize", 1), headers=entetes)
                session = r.headers["mcp-session-id"]
                entetes_sse = {**entetes, "Accept": "text/event-stream", "mcp-session-id": session}
                r = await c.post("/mcp", content=_json_rpc("tools/list", 2), headers=entetes_sse)
                assert r.status_code == 200
                assert "text/event-stream" in r.headers.get("content-type", "")
                noms = {t["name"] for t in _reponse_json_rpc(r)["result"]["tools"]}
                assert "outil-upstream-inconnu" not in noms
                assert "delete_repository" in noms
        finally:
            serveur.should_exit = True
            if _socket_ecoute:
                _socket_ecoute.close()

    _courir(_t())


def test_lecture_seul_liste_uniquement_les_outils_lecture(environ):
    """tools/list pour un jeton lecture seule n'annonce que les outils de lecture."""

    async def _t():
        serveur, url, _socket_ecoute, recus = _serveur_stub()
        try:
            os.environ["GITHUB_MCP_UPSTREAM"] = url
            async with _client(JETON_LECTURE, SCOPES_LECTURE) as c:
                entetes = _entetes_autorises(JETON_LECTURE)
                r = await c.post("/mcp", content=_json_rpc("initialize", 1), headers=entetes)
                session = r.headers["mcp-session-id"]
                r = await c.post(
                    "/mcp", content=_json_rpc("tools/list", 2), headers={**entetes, "mcp-session-id": session}
                )
                assert r.status_code == 200
                noms = {t["name"] for t in r.json()["result"]["tools"]}
                assert noms == set(OUTILS_LECTURE), noms
                assert not (noms & set(OUTILS_ECRITURE))
                assert "outil-upstream-inconnu" not in noms
        finally:
            serveur.should_exit = True
            if _socket_ecoute:
                _socket_ecoute.close()

    _courir(_t())


@pytest.mark.parametrize("outil", sorted(OUTILS_ECRITURE))
def test_ecriture_peut_appeler_outil_ecriture(environ, outil):
    """Un jeton lecture+ecriture peut executer une mutation (relayee a l'upstream)."""

    async def _t():
        serveur, url, _socket_ecoute, recus = _serveur_stub()
        try:
            os.environ["GITHUB_MCP_UPSTREAM"] = url
            async with _client(JETON_ECRITURE, SCOPES_ECRITURE) as c:
                entetes = _entetes_autorises(JETON_ECRITURE)
                r = await c.post("/mcp", content=_json_rpc("initialize", 1), headers=entetes)
                session = r.headers["mcp-session-id"]
                r = await c.post(
                    "/mcp",
                    content=_json_rpc("tools/call", 7, {"name": outil, "arguments": {}}),
                    headers={**entetes, "mcp-session-id": session},
                )
                assert r.status_code == 200
                assert "ok" in r.text
                assert [a["name"] for a in recus] == [outil]
        finally:
            serveur.should_exit = True
            if _socket_ecoute:
                _socket_ecoute.close()

    _courir(_t())


def test_outil_inconnu_fail_closed_meme_avec_ecriture(environ):
    """Un outil non classe (inconnu de la politique) est refuse, meme avec un jeton full."""

    async def _t():
        serveur, url, _socket_ecoute, recus = _serveur_stub()
        try:
            os.environ["GITHUB_MCP_UPSTREAM"] = url
            async with _client(JETON_ECRITURE, SCOPES_ECRITURE) as c:
                entetes = _entetes_autorises(JETON_ECRITURE)
                r = await c.post("/mcp", content=_json_rpc("initialize", 1), headers=entetes)
                session = r.headers["mcp-session-id"]
                r = await c.post(
                    "/mcp",
                    content=_json_rpc("tools/call", 9, {"name": "outil-upstream-inconnu", "arguments": {}}),
                    headers={**entetes, "mcp-session-id": session},
                )
                assert r.status_code == 200
                corps = r.json()
                assert "error" in corps
                assert corps["error"]["code"] == -32000
                assert recus == [], "l'upstream ne doit pas recevoir un outil inconnu"
        finally:
            serveur.should_exit = True
            if _socket_ecoute:
                _socket_ecoute.close()

    _courir(_t())


def test_batch_jsonrpc_refuse(environ):
    """Un corps JSON-RPC par lot est refuse en bloc (jamais relaye)."""

    async def _t():
        serveur, url, _socket_ecoute, recus = _serveur_stub()
        try:
            os.environ["GITHUB_MCP_UPSTREAM"] = url
            async with _client(JETON_ECRITURE, SCOPES_ECRITURE) as c:
                entetes = _entetes_autorises(JETON_ECRITURE)
                r = await c.post("/mcp", content=_json_rpc("initialize", 1), headers=entetes)
                session = r.headers["mcp-session-id"]
                lot = json.dumps(
                    [
                        {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "get_me", "arguments": {}}},
                        {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "outil-upstream-inconnu", "arguments": {}}},
                    ]
                ).encode()
                r = await c.post("/mcp", content=lot, headers={**entetes, "mcp-session-id": session})
                assert r.status_code == 200
                corps = r.json()
                assert "error" in corps
                assert recus == [], "aucun element du lot ne doit etre relaye"
        finally:
            serveur.should_exit = True
            if _socket_ecoute:
                _socket_ecoute.close()

    _courir(_t())


def test_proxy_upstream_indisponible(environ):
    async def _t():
        async with _client(JETON_ECRITURE, SCOPES_ECRITURE) as c:
            r = await c.post(
                "/mcp",
                content=_json_rpc("initialize", 1),
                headers={
                    "Content-Type": "application/json",
                    "Accept": "application/json, text/event-stream",
                    "Authorization": f"Bearer {JETON_ECRITURE}",
                },
            )
            assert r.status_code == 502

    _courir(_t())


def test_politique_visible_et_refus(environ):
    """Tests unitaires de la politique (sans HTTP)."""
    politique = PolitiqueOutils()
    lecture = {politique.portee_lecture}
    full = {politique.portee_lecture, politique.portee_ecriture}

    assert politique.visibles(lecture) == set(OUTILS_LECTURE)
    assert politique.visibles(full) == set(OUTILS_LECTURE) | set(OUTILS_ECRITURE)
    assert politique.visibles(set()) == set()

    assert politique.autoriser_call("get_me", lecture) is None
    assert politique.autoriser_call("create_branch", lecture) is not None
    assert politique.autoriser_call("create_branch", full) is None
    # delete_repository : ecriture comme les autres (gate MRTR cote upstream)
    assert politique.autoriser_call("delete_repository", full) is None
    assert politique.autoriser_call("delete_repository", lecture) is not None
    # inconnu refuse
    assert politique.autoriser_call("nimporte-quoi", full) is not None


def test_politique_classe_delete_repository_et_get_file_contents():
    """delete_repository (mutateur) et get_file_contents (lecture) sont classes et
    autorisables par les jetons portant la bonne portee."""
    politique = PolitiqueOutils()
    lecture = {politique.portee_lecture}
    full = {politique.portee_lecture, politique.portee_ecriture}

    assert "delete_repository" in OUTILS_ECRITURE
    assert "get_file_contents" in OUTILS_LECTURE
    # delete_repository est une mutation : portee ecriture exigee, lecture seule refuse
    assert politique.autoriser_call("delete_repository", full) is None
    assert politique.autoriser_call("delete_repository", lecture) is not None
    # get_file_contents est de la lecture seule
    assert politique.autoriser_call("get_file_contents", lecture) is None


def test_tools_list_annonce_exactement_le_catalogue_complet(environ):
    """Le proxy n'annonce QUE le catalogue classe (59 lecture + 35 ecriture)
    meme quand l'upstream enregistre davantage (inconnu) : jamais plus large
    que la politique, jamais moins (surface maximale RW)."""

    async def _t():
        serveur, url, _socket_ecoute, recus = _serveur_stub()
        try:
            os.environ["GITHUB_MCP_UPSTREAM"] = url
            async with _client(JETON_ECRITURE, SCOPES_ECRITURE) as c:
                entetes = _entetes_autorises(JETON_ECRITURE)
                r = await c.post("/mcp", content=_json_rpc("initialize", 1), headers=entetes)
                session = r.headers["mcp-session-id"]
                r = await c.post(
                    "/mcp", content=_json_rpc("tools/list", 2), headers={**entetes, "mcp-session-id": session}
                )
                assert r.status_code == 200
                noms = {t["name"] for t in r.json()["result"]["tools"]}
                assert noms == _PROFIL_COMPLET, noms - _PROFIL_COMPLET
                assert "outil-upstream-inconnu" not in noms
        finally:
            serveur.should_exit = True
            if _socket_ecoute:
                _socket_ecoute.close()

    _courir(_t())


def test_tools_list_masque_ecriture_sans_portee_ecriture(environ):
    """Un jeton lecture seule voit get_file_contents mais PAS delete_repository."""

    async def _t():
        serveur, url, _socket_ecoute, recus = _serveur_stub()
        try:
            os.environ["GITHUB_MCP_UPSTREAM"] = url
            async with _client(JETON_LECTURE, SCOPES_LECTURE) as c:
                entetes = _entetes_autorises(JETON_LECTURE)
                r = await c.post("/mcp", content=_json_rpc("initialize", 1), headers=entetes)
                session = r.headers["mcp-session-id"]
                r = await c.post(
                    "/mcp", content=_json_rpc("tools/list", 2), headers={**entetes, "mcp-session-id": session}
                )
                noms = {t["name"] for t in r.json()["result"]["tools"]}
                assert "get_file_contents" in noms
                assert "delete_repository" not in noms
                # un call forge vers delete_repository est refuse AVANT l'upstream
                r = await c.post(
                    "/mcp",
                    content=_json_rpc("tools/call", 8, {"name": "delete_repository", "arguments": {}}),
                    headers={**entetes, "mcp-session-id": session},
                )
                assert r.json()["error"]["code"] == -32000
                assert recus == []
        finally:
            serveur.should_exit = True
            if _socket_ecoute:
                _socket_ecoute.close()

    _courir(_t())


def test_sante(environ):
    async def _t():
        async with _client(JETON_ECRITURE, SCOPES_ECRITURE) as c:
            r = await c.get("/health")
            assert r.status_code == 200
            assert r.json()["status"] == "ok"

    _courir(_t())
