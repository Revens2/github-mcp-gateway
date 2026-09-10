#!/usr/bin/env python3
"""Insere les blocs nginx du MCP GitHub dans le vhost mymcps.duckdns.org.

Strategie : cloner les blocs `calendar` (style live identique) en remplacant
calendar->github et 8790->8799. L'insertion se fait APRES l'accolade fermante du
bloc calendar (jamais d'imbrication). Idempotent (ne fait rien si /github/mcp
present), fail-closed (ancre introuvable => aucune ecriture), backup horodate +
`nginx -t` avant tout reload. Dry-run par defaut ; `--appliquer` ecrit + reload.

Usage VPS : sudo python3 deploy/ajouter-blocs-nginx.py [--appliquer]
Rollback : supprimer les blocs marques `# github-mcp-gateway`,
  nginx -t && systemctl reload nginx (backup dans /srv/archives/).
"""

from __future__ import annotations

import subprocess
import sys
from datetime import datetime
from pathlib import Path

CONF = Path("/etc/nginx/sites-available/mymcps.duckdns.org.conf")
ARCHIVES = Path("/srv/archives")
MARQUEUR = "    # github-mcp-gateway"

# Ancres : 2 premieres lignes (uniques) de chaque bloc calendar a cloner.
BLOCS: list[str] = [
    """    location = /.well-known/oauth-protected-resource/calendar/mcp {
        proxy_pass http://127.0.0.1:8790/.well-known/oauth-protected-resource/calendar/mcp;""",
    """    location = /.well-known/oauth-authorization-server/oauth/calendar {
        proxy_pass http://127.0.0.1:8790/.well-known/oauth-authorization-server;""",
    """    location ~ ^/oauth/calendar/(authorize|token|register|revoke|consentement) {
        rewrite ^/oauth/calendar(/.*)$ $1 break;""",
    """    location = /calendar/mcp/ { return 404; }
    location ~ ^/calendar/mcp/ { return 404; }
    location = /calendar/mcp {
        rewrite ^/calendar(/.*)$ $1 break;""",
]

# Lignes uniques (bloc d'une ligne) a cloner.
LIGNES: list[str] = [
    "    location ~ ^/calendar/(authorize|token|register|revoke|consentement) { return 301 https://$host/oauth/calendar/$1$is_args$args; }",
    "    location ~ ^/calendar/\\.well-known/(.*)$ { return 301 https://$host/.well-known/$1; }",
    "    location = /astra/health { rewrite ^/astra(/.*)$ $1 break; proxy_pass http://127.0.0.1:8796; proxy_set_header Host $host; }",
]


def cloner(bloc_calendar: str) -> str:
    """Clone github Strictement borne au bloc (pas de remplacement global)."""
    assert "calendar" in bloc_calendar and "8790" in bloc_calendar
    return bloc_calendar.replace("calendar", "github").replace("8790", "8799")


def inserer_apres_bloc(texte: str, ancre: str) -> str:
    i = texte.find(ancre)
    if i < 0:
        raise LookupError(f"ancre introuvable : {ancre[:100]!r}")
    fin = texte.find("\n    }\n", i)
    if fin < 0:
        raise LookupError(f"fin de bloc introuvable apres : {ancre[:100]!r}")
    fin += len("\n    }\n")
    bloc_calendar = texte[i:fin]
    bloc_github = cloner(bloc_calendar)
    if "calendar" in bloc_github or "8790" in bloc_github:
        raise ValueError("remplacement incomplet (fail-closed)")
    return texte[:fin] + MARQUEUR + "\n" + bloc_github.rstrip("\n") + "\n" + texte[fin:]


def inserer_apres_ligne(texte: str, ligne: str) -> str:
    i = texte.find(ligne)
    if i < 0:
        raise LookupError(f"ligne introuvable : {ligne[:100]!r}")
    fin_ligne = texte.find("\n", i) + 1
    if ligne.startswith("    location = /astra/health"):
        ajout = "    location = /github/health { rewrite ^/github(/.*)$ $1 break; proxy_pass http://127.0.0.1:8799; proxy_set_header Host $host; }"
    else:
        ajout = ligne.replace("calendar", "github")
    return texte[:fin_ligne] + MARQUEUR + "\n" + ajout + "\n" + texte[fin_ligne:]


def main() -> None:
    appliquer = "--appliquer" in sys.argv
    texte = CONF.read_text(encoding="utf-8")
    if "/github/mcp" in texte or "/oauth/github/" in texte:
        print("Deja present : blocs github trouves, aucune modification.")
        return
    try:
        nouveau = texte
        for ancre in BLOCS:
            nouveau = inserer_apres_bloc(nouveau, ancre)
        for ligne in LIGNES:
            nouveau = inserer_apres_ligne(nouveau, ligne)
    except (LookupError, ValueError, AssertionError) as exc:
        print(f"ABORT fail-closed, aucune ecriture : {exc}")
        sys.exit(1)
    n = nouveau.count(MARQUEUR)
    if not appliquer:
        print(f"Dry-run : {n} insertion(s) pretes (relancez avec --appliquer).")
        return
    horodatage = datetime.now().strftime("%Y-%m-%d-%H%M%S")
    backup = ARCHIVES / f"mymcps.duckdns.org.conf.{horodatage}-pre-github-blocs"
    backup.write_text(texte, encoding="utf-8")
    CONF.write_text(nouveau, encoding="utf-8")
    test = subprocess.run(["nginx", "-t"], capture_output=True, text=True)
    print((test.stderr or test.stdout).strip().splitlines()[-1])
    if test.returncode != 0:
        CONF.write_text(texte, encoding="utf-8")
        print("nginx -t EN ECHEC : configuration restauree, abort.")
        sys.exit(1)
    reload = subprocess.run(["systemctl", "reload", "nginx"], capture_output=True, text=True)
    if reload.returncode != 0:
        print("reload nginx EN ECHEC (config valide, fichier en place).")
        sys.exit(1)
    print(f"OK : {n} blocs github inserees, backup {backup.name}, nginx recharge.")


if __name__ == "__main__":
    main()
