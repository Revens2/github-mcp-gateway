"""Tests de la normalisation anti-materialisation `get_file_contents`.

Couvre le contrat : fichier texte avec ressource integree -> texte direct
sans aucune ressource ; SHA/path conserves ; autre outil / erreur /
repertoire en texte -> octets strictement inchanges ; binaire et gros
fichier (resource_link) -> texte borne sans piece jointe ; enveloppes JSON
et SSE ; integration gateway (stub upstream au format reel observe).
"""

from __future__ import annotations

import json
import os

import pytest

from github_gateway.lecture_fichier import (
    OUTIL_FICHIER,
    nom_outil_requete,
    normaliser_reponse_fichier,
)

SHA = "a1c119c10eaa0c3d3c9daa02e53687da2b004523"
URI_FICHIER = (
    "repo://Revens2/github-mcp-gateway/sha/"
    "b0ab8e27ceb5bfd5f5bcbab44648325ccf01415c/contents/README.md"
)
MESSAGE_TEXTE = f"successfully downloaded text file (SHA: {SHA})"
CONTENU_TEXTE = "# github-mcp-gateway\nContenu de test avec accents : éè.\n"


def _requete(nom: str, identifiant: int = 2) -> bytes:
    return json.dumps(
        {
            "jsonrpc": "2.0",
            "id": identifiant,
            "method": "tools/call",
            "params": {"name": nom, "arguments": {"owner": "o", "repo": "r", "path": "p"}},
        }
    ).encode()


REQUETE_FICHIER = _requete(OUTIL_FICHIER)


def _reponse_texte() -> bytes:
    return json.dumps(
        {
            "jsonrpc": "2.0",
            "id": 2,
            "result": {
                "content": [
                    {"type": "text", "text": MESSAGE_TEXTE},
                    {
                        "type": "resource",
                        "resource": {
                            "uri": URI_FICHIER,
                            "mimeType": "text/plain; charset=utf-8",
                            "text": CONTENU_TEXTE,
                        },
                    },
                ]
            },
        },
        ensure_ascii=False,
    ).encode()


def _types(blocs: list) -> list:
    return [b.get("type") for b in blocs]


def test_nom_outil_requete():
    assert nom_outil_requete(REQUETE_FICHIER) == OUTIL_FICHIER
    assert nom_outil_requete(_requete("get_me")) == "get_me"
    assert nom_outil_requete(b'{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}') is None
    assert nom_outil_requete(b"pas-du-json") is None
    assert nom_outil_requete(None) is None


def test_texte_avec_resource_devient_texte_direct_sans_resource():
    brut = _reponse_texte()
    nouveau = normaliser_reponse_fichier(REQUETE_FICHIER, brut, "application/json")
    donnees = json.loads(nouveau)
    contenu = donnees["result"]["content"]
    assert _types(contenu) == ["text"], contenu
    assert not any(b.get("type") in ("resource", "resource_link") for b in contenu)
    texte = contenu[0]["text"]
    # Contenu du fichier present en clair, sans double serialisation.
    assert CONTENU_TEXTE in texte
    assert "éè" in texte
    # Aucun bloc/champ structure de fichier restant.
    assert "repo://" not in json.dumps(contenu, ensure_ascii=False)


def test_sha_et_chemin_conserves_sans_uri_telechargeable():
    brut = _reponse_texte()
    nouveau = normaliser_reponse_fichier(REQUETE_FICHIER, brut, "application/json")
    texte = json.loads(nouveau)["result"]["content"][0]["text"]
    assert SHA in texte  # SHA du message d'origine conservee
    assert "README.md" in texte  # chemin preserve en texte (pas en ressource)
    # Pas de champ uri / resource / resource_link dans le resultat.
    resultat = json.loads(nouveau)["result"]
    for bloc in resultat["content"]:
        assert "resource" not in bloc
        assert "uri" not in bloc


def test_autre_tool_inchange_a_loctet_pres():
    requete = _requete("get_me")
    brut = json.dumps(
        {"jsonrpc": "2.0", "id": 3, "result": {"content": [{"type": "text", "text": '{"login":"x"}'}]}},
    ).encode()
    nouveau = normaliser_reponse_fichier(requete, brut, "application/json")
    assert nouveau is brut


def test_erreur_upstream_inchangee():
    brut = json.dumps(
        {"jsonrpc": "2.0", "id": 2, "error": {"code": -32602, "message": "boom"}}
    ).encode()
    assert normaliser_reponse_fichier(REQUETE_FICHIER, brut, "application/json") is brut


def test_repertoire_en_texte_inchange():
    # Lecture de repertoire : texte JSON, aucune ressource -> intact.
    brut = json.dumps(
        {
            "jsonrpc": "2.0",
            "id": 2,
            "result": {
                "content": [
                    {"type": "text", "text": '[{"name":"a","path":"a","type":"file"}]'}
                ]
            },
        }
    ).encode()
    assert normaliser_reponse_fichier(REQUETE_FICHIER, brut, "application/json") is brut


def test_binaire_blob_sans_materialisation():
    brut = json.dumps(
        {
            "jsonrpc": "2.0",
            "id": 2,
            "result": {
                "content": [
                    {"type": "text", "text": f"successfully downloaded binary file (SHA: {SHA})"},
                    {
                        "type": "resource",
                        "resource": {
                            "uri": "repo://o/r/sha/abc/contents/logo.png",
                            "mimeType": "image/png",
                            "blob": "iVBORw0KGgoAAAANSUhEUg==",
                        },
                    },
                ]
            },
        }
    ).encode()
    nouveau = normaliser_reponse_fichier(REQUETE_FICHIER, brut, "application/json")
    donnees = json.loads(nouveau)
    contenu = donnees["result"]["content"]
    assert _types(contenu) == ["text"]
    texte = contenu[0]["text"]
    assert SHA in texte
    assert "logo.png" in texte
    assert "iVBORw0KGgoAAAANSUhEUg==" not in texte  # blob jamais reinjecte
    assert "blob" not in json.dumps(donnees)


def test_gros_fichier_resource_link_sans_materialisation():
    brut = json.dumps(
        {
            "jsonrpc": "2.0",
            "id": 2,
            "result": {
                "content": [
                    {
                        "type": "text",
                        "text": "File big.bin is too large to display (2097152 bytes). "
                        "Use the download URL to fetch the content: "
                        f"https://raw.githubusercontent.com/o/r/main/big.bin (SHA: {SHA})",
                    },
                    {
                        "type": "resource_link",
                        "uri": "repo://o/r/refs/heads/main/contents/big.bin",
                        "name": "big.bin",
                        "title": "File: big.bin",
                        "size": 2097152,
                    },
                ]
            },
        }
    ).encode()
    nouveau = normaliser_reponse_fichier(REQUETE_FICHIER, brut, "application/json")
    donnees = json.loads(nouveau)
    contenu = donnees["result"]["content"]
    assert _types(contenu) == ["text"]
    assert "resource_link" not in json.dumps(donnees)
    assert SHA in contenu[0]["text"]


def test_fichier_vide_sans_resource():
    brut = json.dumps(
        {
            "jsonrpc": "2.0",
            "id": 2,
            "result": {
                "content": [
                    {"type": "text", "text": f"successfully downloaded empty file (SHA: {SHA})"},
                    {
                        "type": "resource",
                        "resource": {"uri": URI_FICHIER, "mimeType": "text/plain", "text": ""},
                    },
                ]
            },
        }
    ).encode()
    nouveau = normaliser_reponse_fichier(REQUETE_FICHIER, brut, "application/json")
    contenu = json.loads(nouveau)["result"]["content"]
    assert _types(contenu) == ["text"]
    assert SHA in contenu[0]["text"]


def test_enveloppe_sse_normalisee_lignes_non_data_conservees():
    sse = (
        b"event: message\n"
        b"data: " + _reponse_texte() + b"\n\n"
    )
    nouveau = normaliser_reponse_fichier(REQUETE_FICHIER, sse, "text/event-stream")
    assert nouveau.startswith(b"event: message\n")
    assert b'"type": "resource"' not in nouveau and b'"type":"resource"' not in nouveau
    ligne_data = [ln for ln in nouveau.split(b"\n") if ln.startswith(b"data: ")][0]
    contenu = json.loads(ligne_data[len(b"data: "):])["result"]["content"]
    assert _types(contenu) == ["text"]
    assert CONTENU_TEXTE in contenu[0]["text"]


def test_sse_sans_resource_inchange_a_loctet_pres():
    sse = (
        b"event: message\n"
        b'data: {"jsonrpc": "2.0", "id": 2, "result": {"content": [{"type": "text", "text": "ok"}]}}\n\n'
    )
    assert normaliser_reponse_fichier(REQUETE_FICHIER, sse, "text/event-stream") is sse


def test_corps_illisible_inchange():
    assert normaliser_reponse_fichier(REQUETE_FICHIER, b"\x00\x01", "application/json") == b"\x00\x01"
    assert normaliser_reponse_fichier(None, _reponse_texte(), "application/json") is not None


# --- Integration gateway : stub upstream au format reel observe -----------------

def test_integration_gateway_texte_sans_resource():
    """Le client du gateway recoit du texte direct, zero bloc fichier."""
    pytest.importorskip("fcntl")  # pile ASGI POSIX uniquement (VPS/CI Linux)
    import asyncio
    import socket
    import threading
    import time
    import uuid

    import httpx
    import uvicorn
    from starlette.applications import Starlette
    from starlette.responses import JSONResponse
    from starlette.routing import Route

    from github_gateway.app import construire_application
    from github_gateway.oauth import hacher_phrase

    emetteur = "https://github.example.test"
    jeton = "e" * 40
    pat = "p" * 40

    async def _post(request):
        corps = json.loads(await request.body())
        assert request.headers.get("authorization", "") == f"Bearer {pat}"
        if corps.get("method") == "tools/call":
            return JSONResponse(
                {
                    "jsonrpc": "2.0",
                    "id": corps.get("id"),
                    "result": {
                        "content": [
                            {"type": "text", "text": MESSAGE_TEXTE},
                            {
                                "type": "resource",
                                "resource": {
                                    "uri": URI_FICHIER,
                                    "mimeType": "text/plain; charset=utf-8",
                                    "text": CONTENU_TEXTE,
                                },
                            },
                        ]
                    },
                },
                headers={"mcp-session-id": request.headers.get("mcp-session-id", "") or str(uuid.uuid4())},
            )
        return JSONResponse(
            {"jsonrpc": "2.0", "id": corps.get("id"), "result": {}},
            headers={"mcp-session-id": request.headers.get("mcp-session-id", "") or str(uuid.uuid4())},
        )

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
        os.environ["GITHUB_MCP_ISSUER"] = emetteur
        os.environ["GITHUB_MCP_UPSTREAM"] = f"http://127.0.0.1:{port}"
        os.environ["GITHUB_MCP_TOKEN"] = jeton
        os.environ["GITHUB_MCP_TOKEN_SCOPES"] = "github:lecture github:ecriture"
        os.environ["GITHUB_MCP_CONSENT_HASH"] = hacher_phrase("phrase-test")
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            os.environ["GITHUB_MCP_OAUTH_DIR"] = tmp
            app = construire_application(jeton_statique=jeton, jeton_upstream=pat)

            async def _t():
                transport = httpx.ASGITransport(app=app)
                async with httpx.AsyncClient(transport=transport, base_url=emetteur) as c:
                    entetes = {
                        "Content-Type": "application/json",
                        "Accept": "application/json, text/event-stream",
                        "Authorization": f"Bearer {jeton}",
                    }
                    corps = json.dumps(
                        {
                            "jsonrpc": "2.0",
                            "id": 2,
                            "method": "tools/call",
                            "params": {
                                "name": "get_file_contents",
                                "arguments": {"owner": "o", "repo": "r", "path": "README.md"},
                            },
                        }
                    ).encode()
                    r = await c.post("/mcp", content=corps, headers=entetes)
                    assert r.status_code == 200, r.text
                    donnees = r.json()
                    contenu = donnees["result"]["content"]
                    assert [b["type"] for b in contenu] == ["text"], contenu
                    assert CONTENU_TEXTE in contenu[0]["text"]
                    assert SHA in contenu[0]["text"]
                    for bloc in contenu:
                        assert bloc.get("type") not in ("resource", "resource_link")
                        assert "resource" not in bloc
                        assert "uri" not in bloc

            asyncio.run(_t())
    finally:
        serveur.should_exit = True
        sock.close()
