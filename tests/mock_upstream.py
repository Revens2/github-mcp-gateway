"""Mock upstream github-mcp-server v1.12.0 pour smoke local github-gateway-rs.

- Exige `Authorization: Bearer <PAT>` sur /mcp (comme le Go : 401 sinon).
- Sert initialize (session `mcp-session-id`) / tools/list (sous-ensemble
  representatif : lecture + ecriture + 1 inconnu jamais classe) /
  tools/call get_me (reel, read-only) / resources + prompts.
- Usage: python mock_upstream.py <port> <pat>
"""
import json
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 18800
EXPECTED = sys.argv[2] if len(sys.argv) > 2 else "p" * 32

TOOLS = [
    {"name": "get_me", "description": "Utilisateur authentifie", "inputSchema": {"type": "object", "properties": {}}},
    {"name": "search_repositories", "description": "Recherche", "inputSchema": {"type": "object", "properties": {}}},
    {"name": "create_gist", "description": "Mutateur", "inputSchema": {"type": "object", "properties": {}}},
    {"name": "delete_repository", "description": "Mutateur MRTR", "inputSchema": {"type": "object", "properties": {}}},
]


class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, obj, code=200):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(body)))
        self.send_header("mcp-session-id", "mock-session-1")
        self.end_headers()
        self.wfile.write(body)

    def _auth_ok(self):
        return self.headers.get("Authorization") == f"Bearer {EXPECTED}"

    def do_POST(self):
        if self.path != "/mcp":
            self.send_response(404)
            self.end_headers()
            return
        if not self._auth_ok():
            self.send_response(401)
            self.end_headers()
            return
        ln = int(self.headers.get("Content-Length", 0))
        try:
            data = json.loads(self.rfile.read(ln) or b"{}")
        except ValueError:
            self._send({"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "parse"}})
            return
        rid = data.get("id")
        method = data.get("method")
        if method == "initialize":
            self._send({"jsonrpc": "2.0", "id": rid, "result": {
                "protocolVersion": "2025-11-25",
                "serverInfo": {"name": "github-mcp-server", "version": "v1.12.0-mock"},
                "capabilities": {"tools": {}}}})
        elif method == "tools/list":
            self._send({"jsonrpc": "2.0", "id": rid, "result": {"tools": TOOLS}})
        elif method == "tools/call" and (data.get("params") or {}).get("name") == "get_me":
            self._send({"jsonrpc": "2.0", "id": rid, "result": {
                "content": [{"type": "text", "text": "mock-user"}]}})
        elif method in ("resources/list",):
            self._send({"jsonrpc": "2.0", "id": rid, "result": {"resources": [
                {"uri": "repo://mock", "name": "mock"}]}})
        elif method in ("prompts/list",):
            self._send({"jsonrpc": "2.0", "id": rid, "result": {"prompts": [
                {"name": "mock-prompt"}]}})
        else:
            self._send({"jsonrpc": "2.0", "id": rid, "error": {"code": -32000, "message": "mock: non gere"}})


HTTPServer(("127.0.0.1", PORT), H).serve_forever()
