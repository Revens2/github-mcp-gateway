"""Normalisation des reponses `get_file_contents` (anti-materialisation ChatGPT).

Cause racine (prouvee sur reponse brute upstream v1.12.0) : pour un fichier
texte, l'upstream officiel renvoie un resultat MCP a DEUX blocs ::

    {"type": "text", "text": "successfully downloaded text file (SHA: ...)"}
    {"type": "resource",
     "resource": {"uri": "repo://.../contents/<chemin>",
                  "mimeType": "text/plain; charset=utf-8",
                  "text": "<contenu du fichier>"}}

Le second bloc (EmbeddedResource) est materialise par ChatGPT Web en piece
jointe, d'ou la popup « Autoriser la materialisation des fichiers ? ». Meme
mecanisme pour les gros fichiers (``{"type": "resource_link", ...}``) et les
binaires (ressource avec ``blob`` au lieu de ``text``).

La passerelle convertit donc, STRICTEMENT pour les reponses a un
``tools/call`` de ``get_file_contents`` :
- ressource texte -> un unique bloc ``{"type": "text"}`` : message d'origine
  (SHA conserve) + chemin + MIME + contenu en clair, sans aucune ressource ;
- ressource binaire (``blob``, sans texte decodable) -> bloc texte explicite
  et borne, SANS reinjecter le blob, sans piece jointe ;
- lien de ressource (gros fichier) -> bloc texte explicite (message d'origine
  + nom/taille en texte), SANS le bloc ``resource_link`` ;
- repertoire (texte JSON), erreur upstream, autre outil : octets INCHANGES.

Seul le champ ``result.content`` des payloads JSON-RPC est touche ; ``id``,
``jsonrpc``, erreurs, ``structuredContent``, lignes SSE non-``data`` et
champs non concernes sont conserves. Pas de double serialisation du contenu :
simple concatenation de chaines.

Module pur (stdlib uniquement), testable sans la pile ASGI.
"""

from __future__ import annotations

import json
from typing import Any

# Seul outil reecrit : la lecture de fichier. Tout autre `tools/call`
# (lecture ou ecriture) est relaie a l'octet pres.
OUTIL_FICHIER = "get_file_contents"

# Blocs MCP qui declenchent une materialisation cote ChatGPT Web.
_TYPES_FICHIER = frozenset({"resource", "resource_link"})


def nom_outil_requete(corps: bytes | None) -> str | None:
    """Nom d'outil d'un corps JSON-RPC `tools/call`, ou None (autre methode)."""
    try:
        donnees = json.loads(corps or b"")
    except (ValueError, UnicodeDecodeError):
        return None
    if not isinstance(donnees, dict) or donnees.get("method") != "tools/call":
        return None
    params = donnees.get("params")
    nom = params.get("name") if isinstance(params, dict) else None
    return nom if isinstance(nom, str) and nom else None


def _chemin_depuis_uri(uri: Any) -> str:
    """Chemin du fichier extrait d'une URI `repo://.../contents/<chemin>`."""
    if not isinstance(uri, str) or not uri:
        return ""
    marqueur = "/contents/"
    idx = uri.find(marqueur)
    if idx == -1:
        return ""
    return uri[idx + len(marqueur):]


def _bloc_texte(texte: str) -> dict[str, Any]:
    return {"type": "text", "text": texte}


def _convertir_resource(message: str, resource: Any) -> dict[str, Any] | None:
    """Convertit une ressource integree en bloc texte. None si inattendue."""
    if not isinstance(resource, dict):
        return None
    texte = resource.get("text")
    chemin = _chemin_depuis_uri(resource.get("uri"))
    mime = resource.get("mimeType")
    mime_txt = mime if isinstance(mime, str) and mime else "type inconnu"
    if isinstance(texte, str):
        # Cas nominal : fichier texte (< 1 Mo cote upstream).
        entete = message
        if chemin:
            entete += ("" if not entete else "\n") + f"Fichier : {chemin} | MIME : {mime_txt}"
        return _bloc_texte(entete + ("\n\n" if entete else "") + texte)
    if isinstance(resource.get("blob"), str):
        # Fichier binaire : jamais de blob reinjecte, jamais de piece jointe.
        entete = message or "Fichier binaire recu."
        detail = f"Fichier binaire : {chemin or 'chemin inconnu'} | MIME : {mime_txt}"
        return _bloc_texte(
            entete + "\n" + detail + " — contenu non renvoye en ligne (aucune piece jointe)."
        )
    return None


def _convertir_lien(message: str, lien: Any) -> dict[str, Any]:
    """Convertit un `resource_link` (gros fichier) en bloc texte, sans lien."""
    if message:
        return _bloc_texte(message)
    # Repli : le message upstream existe toujours en pratique
    # (NewToolResultResourceLink) ; on reste textuel et borne sans URI.
    nom = lien.get("name") if isinstance(lien, dict) else None
    nom_txt = nom if isinstance(nom, str) and nom else "fichier"
    return _bloc_texte(
        f"Fichier {nom_txt} trop volumineux pour un affichage en ligne — "
        "aucune piece jointe renvoyee."
    )


def _transformer_payload(payload: Any) -> bool:
    """Reecrit `payload["result"]["content"]` en place, sans bloc fichier.

    Retourne True si une reecriture a eu lieu, False sinon (payload intact :
    erreur, repertoire en texte JSON, autre forme sans ressource).
    """
    if not isinstance(payload, dict):
        return False
    resultat = payload.get("result")
    if not isinstance(resultat, dict):
        return False
    contenu = resultat.get("content")
    if not isinstance(contenu, list) or not contenu:
        return False
    if not any(isinstance(b, dict) and b.get("type") in _TYPES_FICHIER for b in contenu):
        return False
    messages = [
        b.get("text", "")
        for b in contenu
        if isinstance(b, dict) and b.get("type") == "text" and isinstance(b.get("text"), str)
    ]
    message = "\n".join(m for m in messages if m)
    nouveaux: list[Any] = []
    for bloc in contenu:
        if not isinstance(bloc, dict):
            nouveaux.append(bloc)
            continue
        type_bloc = bloc.get("type")
        if type_bloc == "text":
            continue  # replie dans `message`, reemis avec le contenu fichier
        if type_bloc == "resource":
            converti = _convertir_resource(message, bloc.get("resource"))
            if converti is not None:
                nouveaux.append(converti)
            else:
                nouveaux.append(
                    _bloc_texte(
                        (message + "\n" if message else "")
                        + "Ressource de forme inattendue non renvoyee en ligne "
                        "(aucune piece jointe)."
                    )
                )
        elif type_bloc == "resource_link":
            nouveaux.append(_convertir_lien(message, bloc))
        else:
            nouveaux.append(bloc)
    resultat["content"] = nouveaux
    return True


def _normaliser_json(corps: bytes) -> bytes:
    try:
        donnees = json.loads(corps)
    except (ValueError, UnicodeDecodeError):
        return corps
    if not isinstance(donnees, dict):
        return corps
    if not _transformer_payload(donnees):
        return corps
    return json.dumps(donnees, ensure_ascii=False).encode()


def _normaliser_sse(corps: bytes) -> bytes:
    lignes = corps.split(b"\n")
    modifie = False
    for i, ligne in enumerate(lignes):
        if not ligne.startswith(b"data: "):
            continue
        brut = ligne[len(b"data: "):]
        if not brut.strip():
            continue
        try:
            donnees = json.loads(brut)
        except (ValueError, UnicodeDecodeError):
            continue
        if not isinstance(donnees, dict):
            continue
        if not _transformer_payload(donnees):
            continue
        lignes[i] = b"data: " + json.dumps(donnees, ensure_ascii=False).encode()
        modifie = True
    return b"\n".join(lignes) if modifie else corps


def normaliser_reponse_fichier(
    corps_requete: bytes | None, corps_reponse: bytes, content_type: str = ""
) -> bytes:
    """Normalise une reponse `tools/call get_file_contents` (JSON ou SSE).

    Retourne les octets d'origine INCHANGES (meme objet) pour tout autre outil,
    toute erreur, toute lecture de repertoire en texte, ou tout corps illisible.
    """
    if nom_outil_requete(corps_requete) != OUTIL_FICHIER:
        return corps_reponse
    if "text/event-stream" in (content_type or "").lower():
        return _normaliser_sse(corps_reponse)
    return _normaliser_json(corps_reponse)
