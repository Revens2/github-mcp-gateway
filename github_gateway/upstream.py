"""Proxy vers le serveur MCP upstream (github-mcp-server officiel, 127.0.0.1:8800).

La passerelle n'est PAS un serveur MCP de plein exercice : elle valide le jeton
d'acces (OAuth ou Bearer statique) puis relaie le trafic Streamable HTTP vers
l'upstream. Les sessions MCP restent la propriete de l'upstream : l'en-tete
`mcp-session-id` est transmis sans modification dans les deux sens, ce qui rend
le proxy invisible pour le protocole.

Credential GitHub : l'upstream officiel en mode `http` exige un `Authorization:
Bearer <PAT>` PAR REQUETE (constate dans pkg/http/middleware/token.go v1.12.0 :
sans cet en-tete il repond 401, la variable d'environnement
GITHUB_PERSONAL_ACCESS_TOKEN n'est utilisee qu'en stdio). La passerelle injecte
donc elle-meme cet en-tete, lu depuis un fichier 0600 dedie (jamais depuis le
client, jamais vers le client) :
- l'`Authorization` du client (OAuth ChatGPT / Bearer statique) n'est JAMAIS
  retransmis a l'upstream (hors allowlist) ;
- seul le PAT interne, charge au demarrage depuis GITHUB_MCP_UPSTREAM_TOKEN_FILE,
  est envoye a l'upstream, en boucle locale uniquement ;
- sans PAT configure : la passerelle demarre quand meme (OAuth/discovery
  testables) mais tout relais est refuse en fail-closed (-32000), l'upstream
  n'est jamais contacte.


Autorisation (politique explicite, voir `politique.py`) appliquee AVANT l'envoi
vers l'upstream, sur la base des portees du jeton deja valide par le gateway :

- `tools/list` : la reponse upstream est filtree pour n'annoncer que les outils
  que le jeton a le droit d'utiliser (lecture seule sans portee ecriture) ;
- `tools/call` : refuse localement (erreur JSON-RPC) si l'outil demande est en
  ecriture sans portee d'ecriture, ou n'est pas classe ; l'upstream n'est alors
  JAMAIS contacte ;
- toute autre methode (`initialize`, `ping`, notifications) passe verbatim ;
- un corps illisible ou une requete par lot (batch JSON-RPC) est refuse
  (fail-closed), le batch n'etant pas utilise par les clients MCP.
"""

from __future__ import annotations

import json
import logging
import os
import time
from collections.abc import Awaitable, Callable, MutableMapping
from typing import Any

import httpx

from github_gateway.politique import PolitiqueOutils

# Journalisation minimale et structuree des echecs de relais : methode,
# destination locale et duree seulement, jamais de corps ni de credential.
_journal = logging.getLogger("uvicorn.error")

# Diagnostic temporaire (GITHUB_MCP_DEBUG_RELAY=1) : journalise methode,
# content-type/accept/version/session et statut upstream. Jamais l'Authorization
# (ni client ni interne), jamais le corps des tools/call (donnees privees).
_DEBUG_RELAY = os.environ.get("GITHUB_MCP_DEBUG_RELAY", "") == "1"

# Versions de protocole MCP que l'upstream officiel accepte (v1.12.0 : 400
# au-dela). ChatGPT annonce 2026-07-28 en en-tete avec un corps en version
# anterieure : desaccord => HTTP 400. Voir _entetes_upstream.
_VERSIONS_SUPPORTEES = frozenset({"2025-03-26", "2025-06-18", "2025-11-25"})


def _version_corps(corps: bytes | None) -> str | None:
    """protocolVersion du corps d'un `initialize`, ou None (autre methode)."""
    try:
        donnees = json.loads(corps or b"")
    except (ValueError, UnicodeDecodeError):
        return None
    if not isinstance(donnees, dict) or donnees.get("method") != "initialize":
        return None
    params = donnees.get("params")
    version = params.get("protocolVersion") if isinstance(params, dict) else None
    return version if isinstance(version, str) else None


def _methode_corps(corps: bytes | None) -> str | None:
    """Nom de methode JSON-RPC du corps (constante protocole), ou None."""
    try:
        donnees = json.loads(corps or b"")
    except (ValueError, UnicodeDecodeError):
        return None
    if not isinstance(donnees, dict):
        return None
    methode = donnees.get("method")
    return methode if isinstance(methode, str) else None

# Au-dela de cette attente de la reponse upstream, le relais est considere comme
# anormalement lent (session SSE exceptee) et journalise en warning.
_SEUIL_REPONSE_LENTE_S = 30.0

Scope = MutableMapping[str, Any]
Message = MutableMapping[str, Any]
Receive = Callable[[], Awaitable[Message]]
Send = Callable[[Message], Awaitable[None]]

# En-tetes de requete retransmis a l'upstream. Pas de host/content-length (httpx les
# gere), pas d'accept-encoding (on evite la compression intermediaire), pas d'origin
# (l'upstream le validerait comme non-localhost et repondrait 403).
_ENTETES_REQUETE = {
    "content-type",
    "accept",
    "mcp-session-id",
    "mcp-protocol-version",
    "last-event-id",
    "user-agent",
}

# En-tetes de reponse retransmis au client. content-length et transfer-encoding sont
# laisses a uvicorn (chunked), les autres (date, server...) n'ont pas lieu d'etre.
_ENTETES_REPONSE = {
    "content-type",
    "mcp-session-id",
    "cache-control",
}

_LIMITE_CORPS = 5 * 1024 * 1024  # 5 Mo : garde-fou contre un corps de requete aberrant.

# Codes d'erreur JSON-RPC utilises pour les refus locaux de la politique.
_CODE_ERREUR_AUTORISATION = -32000  # erreur applicative cote serveur
_CODE_PARSE = -32700  # corps JSON-RPC illisible
_CODE_BATCH = -32600  # requete par lot non prise en charge


def _lire_corps(receive: Receive) -> bytes:
    """Assemble le corps de la requete ASGI (avec garde-fou de taille)."""

    async def _lire() -> bytes:
        morceaux: list[bytes] = []
        total = 0
        while True:
            message = await receive()
            if message["type"] != "http.request":
                continue
            morceau = message.get("body", b"")
            morceaux.append(morceau)
            total += len(morceau)
            if total > _LIMITE_CORPS:
                raise ValueError("corps de requete trop volumineux")
            if not message.get("more_body"):
                break
        return b"".join(morceaux)

    return _lire()


def _entetes(scope: Scope) -> dict[str, str]:
    """En-tetes de requete autorises, depuis la liste ASGI (bytes -> str)."""
    resultat: dict[str, str] = {}
    for cle, valeur in scope.get("headers", []):
        nom = cle.decode("latin-1").lower()
        if nom in _ENTETES_REQUETE:
            resultat[nom] = valeur.decode("latin-1")
    return resultat


async def _envoyer_reponse_json(
    send: Send, statut: int, donnees: dict[str, Any]
) -> None:
    corps = json.dumps(donnees, ensure_ascii=False).encode()
    await send(
        {
            "type": "http.response.start",
            "status": statut,
            "headers": [(b"content-type", b"application/json")],
        }
    )
    await send({"type": "http.response.body", "body": corps, "more_body": False})


async def _envoyer_corps(
    send: Send, statut: int, entetes: httpx.Headers, corps: bytes
) -> None:
    entetes_asgi = [
        (cle.encode("latin-1"), valeur.encode("latin-1"))
        for cle, valeur in entetes.items()
        if cle.lower() in _ENTETES_REPONSE
    ]
    await send({"type": "http.response.start", "status": statut, "headers": entetes_asgi})
    await send({"type": "http.response.body", "body": corps, "more_body": False})


async def _relayer_flux(send: Send, reponse: httpx.Response) -> None:
    """Relai d'un corps eventuellement infini (SSE) morceau par morceau."""
    entetes_asgi = [
        (cle.encode("latin-1"), valeur.encode("latin-1"))
        for cle, valeur in reponse.headers.items()
        if cle.lower() in _ENTETES_REPONSE
    ]
    await send(
        {"type": "http.response.start", "status": reponse.status_code, "headers": entetes_asgi}
    )
    try:
        async for morceau in reponse.aiter_raw():
            await send({"type": "http.response.body", "body": morceau, "more_body": True})
    except (httpx.HTTPError, OSError) as exc:  # flux coupe cote upstream
        await send({"type": "http.response.body", "body": b"", "more_body": False})
        return
    await send({"type": "http.response.body", "body": b"", "more_body": False})


class ProxyMCP:
    """Endpoint ASGI : /mcp authentifie (par le middleware) puis relaye vers l'upstream."""

    def __init__(
        self,
        base_url: str,
        politique: PolitiqueOutils | None = None,
        jeton_upstream: str | None = None,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._politique = politique or PolitiqueOutils()
        self._jeton_upstream = (jeton_upstream or "").strip() or None
        self._client: httpx.AsyncClient | None = None

    @property
    def upstream_auth_configure(self) -> bool:
        """Vrai si le credential GitHub interne est charge (jamais sa valeur)."""
        return self._jeton_upstream is not None

    def _entetes_upstream(self, scope: Scope, corps: bytes | None = None) -> dict[str, str]:
        """En-tetes autorises + injection du credential GitHub interne.

        L'en-tete `Authorization` du client n'est jamais repris (hors allowlist
        de `_entetes`) : seul le PAT interne est envoye, et uniquement vers
        l'upstream en boucle locale.

        Compatibilite ChatGPT : le SDK Go upstream repond 400 des que `Accept`
        ne contient pas A LA FOIS `application/json` et `text/event-stream`
        (constate : ChatGPT n'envoie souvent que l'un des deux). On normalise
        donc vers les deux : le filtrage aval gere les deux enveloppes (JSON nu
        et SSE) et le relais GET retransmet l'octet-stream tel quel.

        Compatibilite versions : une version d'en-tete non supportee par
        l'upstream (ex. 2026-07-28 de ChatGPT) est remplacee par celle du corps
        d'`initialize` quand elle est supportee, sinon retiree (le corps parle
        alors seul — prouve 200 en diagnostic). Une version absente ou supportee
        n'est jamais touchee.
        """
        entetes = _entetes(scope)
        accept = entetes.get("accept", "")
        bas = accept.lower()
        if "application/json" not in bas or "text/event-stream" not in bas:
            entetes["accept"] = "application/json, text/event-stream"
        mcpv = entetes.get("mcp-protocol-version", "")
        if "mcp-protocol-version" in entetes and mcpv not in _VERSIONS_SUPPORTEES:
            version_corps = _version_corps(corps)
            if version_corps in _VERSIONS_SUPPORTEES:
                entetes["mcp-protocol-version"] = version_corps
            else:
                del entetes["mcp-protocol-version"]
        if self._jeton_upstream is not None:
            entetes["authorization"] = f"Bearer {self._jeton_upstream}"
        return entetes

    def _http(self) -> httpx.AsyncClient:
        if self._client is None:
            # Capacite large (300) pour encaisser les salves de sessions du
            # connecteur, attente de creneau bornee (30 s) pour echouer vite et
            # de facon explicite au lieu de stall silencieusement (lecon live :
            # pool sature par des sessions SSE longue duree => 502/504).
            # Read/connect inchanges : 3600 s pour une session SSE legitime.
            self._client = httpx.AsyncClient(
                timeout=httpx.Timeout(3600.0, connect=5.0, pool=30.0),
                limits=httpx.Limits(max_connections=300, max_keepalive_connections=50),
            )
        return self._client

    # --- autorisation ---------------------------------------------------------------
    @staticmethod
    def _portees(scope: Scope) -> frozenset[str]:
        """Portees du jeton valide par le gateway : source UNIQUE d'autorisation.

        Les en-tetes envoyes par le client ne sont jamais consultes ici.
        """
        utilisateur = scope.get("user")
        jeton = getattr(utilisateur, "access_token", None)
        portees = getattr(jeton, "scopes", None)
        if not isinstance(portees, (list, tuple, set, frozenset)):
            return frozenset()
        return frozenset(str(p) for p in portees)

    async def _repondre_erreur_jsonrpc(
        self, send: Send, identifiant: Any, code: int, message: str
    ) -> None:
        await _envoyer_reponse_json(
            send,
            200,
            {
                "jsonrpc": "2.0",
                "id": identifiant,
                "error": {"code": code, "message": message},
            },
        )

    async def _decider(self, send: Send, corps: bytes, portees: set[str]) -> bool:
        """Applique la politique au corps JSON-RPC avant tout envoi upstream.

        Retourne ``True`` si une reponse locale a deja ete envoyee (refus) et
        que la requete ne doit pas etre relayee.
        """
        try:
            donnees = json.loads(corps)
        except (ValueError, UnicodeDecodeError):
            await self._repondre_erreur_jsonrpc(
                send, None, _CODE_PARSE, "corps JSON-RPC illisible (fail-closed)"
            )
            return True
        if isinstance(donnees, list):
            # Le batch n'est pas utilise par les clients MCP ; fail-closed.
            await self._repondre_erreur_jsonrpc(
                send, None, _CODE_BATCH, "requetes par lot non prises en charge"
            )
            return True
        if not isinstance(donnees, dict) or donnees.get("method") != "tools/call":
            # initialize, ping, notifications, tools/list, ... : relais verbatim
            # (tools/list sera filtre sur la reponse).
            return False
        params = donnees.get("params")
        nom = params.get("name") if isinstance(params, dict) else None
        if not isinstance(nom, str) or not nom:
            await self._repondre_erreur_jsonrpc(
                send, donnees.get("id"), _CODE_ERREUR_AUTORISATION,
                "tools/call sans nom d'outil (fail-closed)",
            )
            return True
        raison = self._politique.autoriser_call(nom, portees)
        if raison is None:
            return False
        await self._repondre_erreur_jsonrpc(
            send, donnees.get("id"), _CODE_ERREUR_AUTORISATION, raison
        )
        return True

    # --- filtrage de tools/list -----------------------------------------------------
    def _filtrer_json(self, corps: bytes, visibles: set[str]) -> bytes:
        """Ne garde que les outils annoncables dans une reponse JSON-RPC JSON."""
        try:
            donnees = json.loads(corps)
        except (ValueError, UnicodeDecodeError):
            return corps
        if not isinstance(donnees, dict):
            return corps
        resultat = donnees.get("result")
        if not isinstance(resultat, dict):
            return corps
        outils = resultat.get("tools")
        if not isinstance(outils, list):
            return corps
        conserves = [
            outil for outil in outils
            if isinstance(outil, dict) and outil.get("name") in visibles
        ]
        if len(conserves) == len(outils):
            return corps
        resultat["tools"] = conserves
        return json.dumps(donnees, ensure_ascii=False).encode()

    def _filtrer_sse(self, corps: bytes, visibles: set[str]) -> bytes:
        """Ne garde que les outils annoncables dans une enveloppe SSE (`data:`)."""
        lignes = corps.split(b"\n")
        modifiees = False
        for i, ligne in enumerate(lignes):
            if not ligne.startswith(b"data: "):
                continue
            payload = ligne[len(b"data: "):]
            try:
                donnees = json.loads(payload)
            except (ValueError, UnicodeDecodeError):
                continue
            resultat = donnees.get("result") if isinstance(donnees, dict) else None
            if not isinstance(resultat, dict) or not isinstance(resultat.get("tools"), list):
                continue
            conserves = [
                outil for outil in resultat["tools"]
                if isinstance(outil, dict) and outil.get("name") in visibles
            ]
            if len(conserves) == len(resultat["tools"]):
                continue
            resultat["tools"] = conserves
            lignes[i] = b"data: " + json.dumps(donnees, ensure_ascii=False).encode()
            modifiees = True
        return b"\n".join(lignes) if modifiees else corps

    def filtrer_liste(self, corps: bytes, content_type: str, visibles: set[str]) -> bytes:
        """Filtre une reponse tools/list (JSON nu ou enveloppe SSE)."""
        if "text/event-stream" in content_type.lower():
            return self._filtrer_sse(corps, visibles)
        if "application/json" in content_type.lower():
            return self._filtrer_json(corps, visibles)
        return corps

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            return
        methode = scope["method"]
        chemin = scope.get("path", "/mcp")
        query = scope.get("query_string", b"").decode("latin-1")
        url = f"{self._base_url}{chemin}" + (f"?{query}" if query else "")

        portees = self._portees(scope)

        corps = None
        if methode in ("POST", "PUT", "PATCH"):
            try:
                corps = await _lire_corps(receive)
            except ValueError:
                await _envoyer_reponse_json(
                    send, 413,
                    {"jsonrpc": "2.0", "error": {"code": -32000, "message": "Payload Too Large"}, "id": None},
                )
                return
            if corps:
                refuse_localement = await self._decider(send, corps, set(portees))
                if refuse_localement:
                    return

        if self._jeton_upstream is None:
            # Fail-closed : sans credential GitHub, aucun relais (l'upstream
            # repondrait 401 de toute facon). OAuth/discovery restent servies.
            await _envoyer_reponse_json(
                send, 200,
                {
                    "jsonrpc": "2.0",
                    "error": {"code": -32000, "message": "credential GitHub non configure cote passerelle (fail-closed)"},
                    "id": None,
                },
            )
            return

        debut = time.monotonic()
        try:
            headers_up = self._entetes_upstream(scope, corps)
            if _DEBUG_RELAY:
                # Methode JSON-RPC + version du corps initialize uniquement :
                # constantes du protocole, jamais de donnees utilisateur.
                methode_rpc = _methode_corps(corps)
                _journal.warning(
                    "debug-relay %s %s ct=%r accept=%r mcpv=%r sess=%r rpc=%r initv=%r",
                    methode,
                    url,
                    headers_up.get("content-type", ""),
                    headers_up.get("accept", ""),
                    headers_up.get("mcp-protocol-version", ""),
                    "oui" if headers_up.get("mcp-session-id") else "non",
                    methode_rpc,
                    _version_corps(corps),
                )
            requete = self._http().build_request(
                methode, url, headers=headers_up, content=corps
            )
            reponse = await self._http().send(requete, stream=True)
            if _DEBUG_RELAY:
                _journal.warning("debug-relay reponse %s -> HTTP %s", url, reponse.status_code)
        except httpx.HTTPError as exc:
            _journal.warning(
                "relais %s %s en echec apres %.0f ms: %s (reponse 502)",
                methode,
                url,
                (time.monotonic() - debut) * 1000,
                exc.__class__.__name__,
            )
            await _envoyer_reponse_json(
                send,
                502,
                {
                    "jsonrpc": "2.0",
                    "error": {"code": -32000, "message": f"upstream indisponible: {exc.__class__.__name__}"},
                    "id": None,
                },
            )
            return

        try:
            if methode == "GET":
                await _relayer_flux(send, reponse)
            else:
                corps_reponse = await reponse.aread()
                attente = time.monotonic() - debut
                if attente > _SEUIL_REPONSE_LENTE_S:
                    _journal.warning(
                        "relais %s %s : en-tetes upstream apres %.0f s (anormalement lent)",
                        methode,
                        url,
                        attente,
                    )
                if methode == "POST":
                    corps_reponse = self.filtrer_liste(
                        corps_reponse,
                        reponse.headers.get("content-type", "") or "",
                        self._politique.visibles(set(portees)),
                    )
                await _envoyer_corps(send, reponse.status_code, reponse.headers, corps_reponse)
        finally:
            await reponse.aclose()
