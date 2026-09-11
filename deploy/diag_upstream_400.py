#!/usr/bin/env python3
"""Diagnostic 400 upstream : rejoue initialize avec des variantes d'en-tetes.

Usage VPS : sudo /srv/github/venv/bin/python deploy/diag_upstream_400.py
N'affiche que statuts + debuts de corps (jamais le PAT).

But : identifier quelle variante façon ChatGPT fait 400 cote
github-mcp-server officiel (go-sdk strict), pour calibrer le shim du proxy.
"""
from __future__ import annotations

import json
import sys

import httpx

UPSTREAM = "http://127.0.0.1:8800/mcp"
SECRETS = "/srv/github/secrets/github-pat"


def lire_pat() -> str:
    with open(SECRETS, encoding="utf-8") as f:
        return f.read().strip()


def init_corps(version: str = "2025-06-18") -> dict:
    return {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": version,
            "capabilities": {},
            "clientInfo": {"name": "diag-chatgpt", "version": "0"},
        },
    }


def main() -> None:
    pat = lire_pat()
    variantes = [
        ("baseline JSON+SSE + version 2025-06-18", {"Accept": "application/json, text/event-stream", "Mcp-Protocol-Version": "2025-06-18"}, "2025-06-18"),
        ("SSE seul + version", {"Accept": "text/event-stream", "Mcp-Protocol-Version": "2025-06-18"}, "2025-06-18"),
        ("JSON+SSE sans version", {"Accept": "application/json, text/event-stream"}, "2025-06-18"),
        ("SSE seul sans version", {"Accept": "text/event-stream"}, "2025-06-18"),
        ("JSON seul + version", {"Accept": "application/json", "Mcp-Protocol-Version": "2025-06-18"}, "2025-06-18"),
        ("body 2025-03-26 + header 2025-03-26", {"Accept": "application/json, text/event-stream", "Mcp-Protocol-Version": "2025-03-26"}, "2025-03-26"),
        ("body 2025-11-25 + header 2025-11-25", {"Accept": "application/json, text/event-stream", "Mcp-Protocol-Version": "2025-11-25"}, "2025-11-25"),
        ("body 2026-07-28 sans header", {"Accept": "application/json, text/event-stream"}, "2026-07-28"),
        ("body 2026-07-28 + header 2026-07-28", {"Accept": "application/json, text/event-stream", "Mcp-Protocol-Version": "2026-07-28"}, "2026-07-28"),
    ]
    with httpx.Client(timeout=60.0) as client:
        for nom, suppl, version in variantes:
            entetes = {"Content-Type": "application/json", "Authorization": f"Bearer {pat}", **suppl}
            r = client.post(UPSTREAM, json=init_corps(version), headers=entetes)
            print(f"{r.status_code}  {nom}  :: {r.text[:160].replace(chr(10), ' ')}")
        outils = [
            ("tools/list sans version", {"Accept": "application/json, text/event-stream"}),
            ("tools/list header 2025-06-18", {"Accept": "application/json, text/event-stream", "Mcp-Protocol-Version": "2025-06-18"}),
            ("tools/list header 2026-07-28", {"Accept": "application/json, text/event-stream", "Mcp-Protocol-Version": "2026-07-28"}),
            ("tools/list header 2025-03-26", {"Accept": "application/json, text/event-stream", "Mcp-Protocol-Version": "2025-03-26"}),
            ("tools/list header 2025-11-25", {"Accept": "application/json, text/event-stream", "Mcp-Protocol-Version": "2025-11-25"}),
        ]
        for nom, suppl in outils:
            entetes = {"Content-Type": "application/json", "Authorization": f"Bearer {pat}", **suppl}
            corps = {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}
            r = client.post(UPSTREAM, json=corps, headers=entetes)
            print(f"{r.status_code}  {nom}  :: {r.text[:160].replace(chr(10), ' ')}")


if __name__ == "__main__":
    sys.exit(main())
