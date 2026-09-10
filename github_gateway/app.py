"""Assemblage de l'application ASGI de la passerelle GitHub.

Composition calquee sur ce que fait le SDK `mcp` pour le vault (adr/0015) :
- routes du serveur d'autorisation (`/authorize`, `/token`, `/register`, `/revoke`,
  metadonnees RFC 8414) via `mcp.server.auth.routes` ;
- metadonnees de ressource protegee RFC 9728 (les connecteurs y lisent les portees) ;
- page `/consentement` (phrase de passe) ;
- `/mcp` : middleware d'authentification (OAuth + Bearer statique) puis proxy transparent
  vers le conteneur upstream.

Tout le reste repond 404 : la passerelle n'expose que ce qui doit l'etre.
"""

from __future__ import annotations

import os

from mcp.server.auth.middleware.bearer_auth import BearerAuthBackend, RequireAuthMiddleware
from mcp.server.auth.provider import ProviderTokenVerifier
from mcp.server.auth.routes import (
    build_resource_metadata_url,
    create_auth_routes,
    create_protected_resource_routes,
)
from mcp.server.auth.settings import ClientRegistrationOptions
from pydantic import AnyHttpUrl
from starlette.applications import Starlette
from starlette.middleware.authentication import AuthenticationMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, PlainTextResponse
from starlette.routing import Route

from github_gateway.consentement import routes_consentement
from github_gateway.oauth import PORTEE, PORTEES, FournisseurOAuth, MagasinOAuth
from github_gateway.politique import PolitiqueOutils
from github_gateway.upstream import ProxyMCP

PORT_PAR_DEFAUT = 8799
CHEMIN_MCP = "/mcp"
# Politique d'autorisation explicite : lecture/ecriture par outil (94 tools v1.12.0),
# surface maximale RW voulue ; inconnu -> fail-closed.
POLITIQUE = PolitiqueOutils()


def _config() -> tuple[str, str, int, str, str]:
    """(emetteur, upstream, port, jeton statique, repertoire oauth)."""

    def _requise(nom: str) -> str:
        valeur = os.environ.get(nom, "").strip().rstrip("/")
        if not valeur:
            raise RuntimeError(f"{nom} absent de l'environnement")
        return valeur

    emetteur = _requise("GITHUB_MCP_ISSUER")
    if not emetteur.startswith("https://"):
        raise RuntimeError("GITHUB_MCP_ISSUER doit etre en HTTPS")
    upstream = _requise("GITHUB_MCP_UPSTREAM")
    if not upstream.startswith("http://"):
        raise RuntimeError("GITHUB_MCP_UPSTREAM doit etre en HTTP (boucle locale)")
    port = int(os.environ.get("GITHUB_MCP_PORT", str(PORT_PAR_DEFAUT)))
    jeton = os.environ.get("GITHUB_MCP_TOKEN", "")
    if jeton and len(jeton) < 32:
        raise RuntimeError("GITHUB_MCP_TOKEN trop court : 32 caracteres minimum")
    return emetteur, upstream, port, jeton, os.environ.get("GITHUB_MCP_OAUTH_DIR", "")


def _sante(_: Request) -> JSONResponse:
    return JSONResponse(
        {
            "status": "ok",
            "service": "github-mcp-gateway",
            "mcp": CHEMIN_MCP,
        }
    )


def _defaut(_: Request) -> PlainTextResponse:
    return PlainTextResponse("Not Found", status_code=404)


def construire_application(
    emetteur: str | None = None,
    upstream: str | None = None,
    jeton_statique: str | None = None,
    repertoire_oauth: str | None = None,
) -> Starlette:
    """Construit l'application. Les parametres remplacent l'environnement (tests)."""
    emetteur_reel, upstream_reel, _, jeton_reel, oauth_reel = _config()
    emetteur = (emetteur or emetteur_reel).rstrip("/")
    upstream = upstream or upstream_reel
    jeton = jeton_statique if jeton_statique is not None else jeton_reel

    fournisseur = FournisseurOAuth(
        emetteur,
        magasin=MagasinOAuth(repertoire=repertoire_oauth) if repertoire_oauth else None,
        jeton_statique=jeton,
    )
    proxy = ProxyMCP(upstream, politique=POLITIQUE)
    # Ressource MCP publique : l'issuer est path-scope (/oauth/{svc}) mais la
    # ressource est racine (/github/mcp) — pattern live astra/tasks/calendar :
    # resource = issuer sans "/oauth" + "/mcp". La route PRM du SDK en derive
    # (/.well-known/oauth-protected-resource/github/mcp) et le 401 annonce la
    # bonne resource_metadata, octet-pour-octet avec nginx.
    ressource = emetteur.replace("/oauth", "") + CHEMIN_MCP

    routes: list[Route] = [
        *create_auth_routes(
            fournisseur,
            issuer_url=AnyHttpUrl(emetteur),
            client_registration_options=ClientRegistrationOptions(
                enabled=True,
                valid_scopes=PORTEES,
                default_scopes=[PORTEE],
            ),
        ),
        *create_protected_resource_routes(
            resource_url=AnyHttpUrl(ressource),
            authorization_servers=[AnyHttpUrl(emetteur)],
            scopes_supported=PORTEES,
            resource_name="GitHub MCP (passerelle)",
        ),
        *routes_consentement(fournisseur),
        Route("/health", _sante, methods=["GET"]),
        Route(
            CHEMIN_MCP,
            endpoint=RequireAuthMiddleware(
                proxy,
                required_scopes=[PORTEE],
                resource_metadata_url=build_resource_metadata_url(AnyHttpUrl(ressource)),
            ),
            methods=["GET", "POST", "DELETE", "OPTIONS"],
        ),
        # Fourre-tout : la passerelle n'expose que ce qui precede.
        Route("/{chemin:path}", _defaut, methods=["GET", "POST", "DELETE", "PUT", "PATCH", "OPTIONS", "HEAD"]),
    ]

    application = Starlette(routes=routes)
    # L'AuthenticationMiddleware peuplie scope["user"]/scope["auth"] sur toutes les
    # requetes ; RequireAuthMiddleware (sur /mcp) refuse ensuite sans jeton valide.
    # Le controle fin lecture/ecriture par outil est applique dans ProxyMCP (politique),
    # sur la base des portees du jeton valide, jamais d'un en-tete client.
    return AuthenticationMiddleware(
        application,
        backend=BearerAuthBackend(ProviderTokenVerifier(fournisseur)),
    )
