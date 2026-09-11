"""Page de consentement du flux OAuth de la passerelle GitHub.

Copie-adaptation de `vault_mcp/consentement.py` (adr/0015). La specification MCP et la
pratique des connecteurs sont explicites : chaque connexion d'un client externe exige un
consentement humain. Cette page authentifie l'humain par une phrase de passe, dont seule
l'empreinte PBKDF2 vit dans l'environnement (600).
"""

from __future__ import annotations

import os
import urllib.parse
from html import escape
from typing import Any

from starlette.requests import Request
from starlette.responses import HTMLResponse, RedirectResponse, Response
from starlette.routing import Route

from github_gateway.oauth import (
    PORTEE,
    PORTEE_ECRITURE,
    EtatOAuthCorrompu,
    FournisseurOAuth,
    verifier_phrase,
)

VARIABLE_EMPREINTE = "GITHUB_MCP_CONSENT_HASH"

_GABARIT = """<!doctype html>
<html lang="fr"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Autoriser l'acces au MCP GitHub</title>
<style>
 :root {{ color-scheme: light dark; }}
 body {{ font-family: system-ui, sans-serif; max-width: 26rem;
         margin: 12vh auto; padding: 0 1rem; }}
 h1 {{ font-size: 1.15rem; }}
 p {{ color: #666; font-size: .9rem; line-height: 1.5; }}
 input, button {{ font: inherit; width: 100%; padding: .6rem; margin-top: .5rem;
                  border: 1px solid #8886; border-radius: .4rem;
                  background: transparent; color: inherit; }}
 button {{ cursor: pointer; font-weight: 600; }}
 .err {{ color: #c0392b; font-size: .9rem; }}
 .droits {{ list-style: none; padding: 0; margin: .8rem 0; font-size: .9rem; }}
 .droits li {{ padding: .35rem .6rem; border-radius: .4rem; margin-bottom: .3rem;
               border: 1px solid #8886; }}
 .ecriture {{ border-color: #c0392b; color: #c0392b; font-weight: 600; }}
</style></head><body>
<h1>Autoriser l'acces a vos depots GitHub</h1>
<p>Le client <strong>{client}</strong> demande les acces suivants a vos depots
GitHub. Saisissez votre phrase de passe pour autoriser cette connexion.</p>
<ul class="droits">{droits}</ul>
{erreur}
<!-- Action relative : la page est servie sous /oauth/github/consentement (nginx
     ne route que ce prefixe) ; un action absolu /consentement tomberait sur le
     catch-all 444 et le POST n'atteindrait jamais la passerelle. -->
<form method="post" action="consentement">
  <input type="hidden" name="demande" value="{demande}">
  <input type="password" name="phrase" placeholder="Phrase de passe" autofocus
         autocomplete="current-password" required>
  <button type="submit">Autoriser</button>
</form>
</body></html>"""


# Libelles des portees. Une portee inconnue est affichee telle quelle plutot
# qu'ignoree : mieux vaut un libelle brut qu'un droit accorde en silence.
_LIBELLES = {
    PORTEE: ("Lire", "vos depots GitHub (code, issues, PR, Actions, releases)"),
    PORTEE_ECRITURE: ("Creer et modifier", "vos depots GitHub (fichiers, branches, issues, PR, releases)"),
}


def _rendre_droits(portees: list[str]) -> str:
    """Liste HTML des droits demandes. L'ecriture est visuellement distinguee."""
    if not portees:
        portees = [PORTEE]
    lignes = []
    for portee in portees:
        verbe, complement = _LIBELLES.get(portee, (portee, ""))
        classe = ' class="ecriture"' if portee == PORTEE_ECRITURE else ""
        lignes.append(f"<li{classe}>{escape(verbe)} {escape(complement)}</li>")
    return "".join(lignes)


def _page(
    demande: str, client: str, erreur: str = "", portees: list[str] | None = None
) -> HTMLResponse:
    bloc = f'<p class="err">{erreur}</p>' if erreur else ""
    # Le code de statut suit l'issue : un 200 sur un refus ferait croire au succes.
    return HTMLResponse(
        _GABARIT.format(
            demande=demande,
            client=client,
            erreur=bloc,
            droits=_rendre_droits(portees or [PORTEE]),
        ),
        status_code=401 if erreur else 200,
    )


def _empreinte_attendue() -> str:
    return os.environ.get(VARIABLE_EMPREINTE, "").strip()


def _rediriger(demande: dict[str, Any], code: str) -> RedirectResponse:
    parametres = {"code": code}
    if demande.get("state"):
        parametres["state"] = demande["state"]
    separateur = "&" if "?" in demande["redirect_uri"] else "?"
    cible = demande["redirect_uri"] + separateur + urllib.parse.urlencode(parametres)
    # 302 : le navigateur doit repartir en GET vers le client (ex. auth_callback ChatGPT).
    return RedirectResponse(cible, status_code=302)


def _indisponible() -> HTMLResponse:
    """Magasin OAuth illisible : 503 explicite, jamais un 500 brut."""
    return HTMLResponse(
        "<p>Magasin d'autorisation indisponible (etat corrompu). "
        "Prevenez l'administrateur : un redemarrage ne suffit pas, "
        "le fichier d'etat doit etre inspecte.</p>",
        status_code=503,
    )


def routes_consentement(fournisseur: FournisseurOAuth) -> list[Route]:
    """Routes GET/POST `/consentement`, branchees sur le magasin du fournisseur."""

    async def afficher(request: Request) -> Response:
        identifiant = request.query_params.get("demande", "")
        # On ne consomme pas la demande a l'affichage : seul le POST la retire, sinon un
        # rafraichissement de page rendrait le consentement impossible.
        try:
            demande = fournisseur.magasin._etat()["demandes"].get(identifiant)
        except EtatOAuthCorrompu:
            return _indisponible()
        if not demande:
            return HTMLResponse(
                "<p>Demande inconnue ou expiree. Relancez la connexion depuis le client.</p>",
                status_code=404,
            )
        return _page(
            identifiant,
            str(demande.get("client_id", "?")),
            portees=list(demande.get("scopes") or []),
        )

    async def valider(request: Request) -> Response:
        formulaire = await request.form()
        identifiant = str(formulaire.get("demande", ""))
        phrase = str(formulaire.get("phrase", ""))

        attendue = _empreinte_attendue()
        if not attendue:
            # Refuser plutot que d'ouvrir : une empreinte absente signifierait
            # « tout le monde passe ».
            return HTMLResponse(
                "<p>Consentement non configure sur ce serveur "
                f"({VARIABLE_EMPREINTE} absent). Acces refuse.</p>",
                status_code=503,
            )

        try:
            apercu = fournisseur.magasin._etat()["demandes"].get(identifiant)
        except EtatOAuthCorrompu:
            return _indisponible()
        if not apercu:
            return HTMLResponse(
                "<p>Demande inconnue ou expiree. Relancez la connexion depuis le client.</p>",
                status_code=404,
            )

        if not verifier_phrase(phrase, attendue):
            return _page(
                identifiant,
                str(apercu.get("client_id", "?")),
                "Phrase de passe refusee.",
                portees=list(apercu.get("scopes") or []),
            )

        # Consommee seulement maintenant : un consentement ne se rejoue pas.
        # Tout le bloc final est sous garde magasin (prise + emission du code).
        try:
            demande = fournisseur.magasin.prendre_demande(identifiant)
            if demande is None:
                return HTMLResponse("<p>Demande expiree pendant la saisie.</p>", status_code=404)
            return _rediriger(demande, fournisseur.creer_code(demande))
        except EtatOAuthCorrompu:
            return _indisponible()

    return [
        Route("/consentement", afficher, methods=["GET"]),
        Route("/consentement", valider, methods=["POST"]),
    ]
