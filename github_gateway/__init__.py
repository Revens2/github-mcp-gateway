"""Passerelle d'authentification du MCP GitHub.

Le serveur upstream `github/github-mcp-server` (image officielle non modifiee,
mode http) n'a aucune couche d'auth multi-client. Cette passerelle reprend le
pattern `vault-mcp` (adr/0015) : serveur d'autorisation OAuth 2.1 colocalise
(SDK python `mcp`), page de consentement, Bearer statique pour les CLI, et proxy
transparent vers l'upstream sur `/mcp`, avec injection du PAT GitHub interne
(fichier 0600 dedie, boucle locale uniquement).
"""

__version__ = "1.0.0"
