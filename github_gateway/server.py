"""Point d'entree de la passerelle GitHub (`python -m github_gateway.server`).

Ecoute sur la boucle locale uniquement : nginx (site `github-mcp`, 443 public) est le
seul point d'entree depuis l'exterieur. L'upstream (conteneur) n'est joint qu'en
127.0.0.1. Meme compromis d'isolation que `vault-mcp.service` : voir l'unite systemd.
"""

from __future__ import annotations

import os

import uvicorn

from github_gateway.app import PORT_PAR_DEFAUT, _config, construire_application


def main() -> None:
    _, _, port, _, _ = _config()
    uvicorn.run(construire_application(), host="127.0.0.1", port=port, log_level="info")


if __name__ == "__main__":
    main()
