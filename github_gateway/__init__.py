"""Passerelle d'authentification du MCP Google GitHub.

Le serveur upstream `nspady/google-github-mcp` (conteneur non modifie) n'a aucune
couche d'auth. Cette passerelle reprend le pattern `vault-mcp` (adr/0015, adr/0016) :
serveur d'autorisation OAuth 2.1 colocalise (SDK python `mcp`), page de consentement,
Bearer statique pour les CLI, et proxy transparent vers l'upstream sur `/mcp`.
"""

__version__ = "1.0.0"
