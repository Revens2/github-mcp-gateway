"""Diff contrat zero live : prod Python :8799 vs canary Rust :18999.

Secrets lus depuis leurs fichiers 600 sur le VPS uniquement (jamais affiches,
jamais journalises). Echec de parsing = message statique, exit 2.
Sessions MCP (`mcp-session-id`) gerees des deux cotes (upstream Go stateful).
Compare : initialize (protocolVersion/serverInfo), tools/list (86 noms +
descriptions + inputSchema), resources/list (4), prompts/list (2),
tools/call get_me (reel, read-only), refus local outil inconnu (-32000 des
deux cotes). Sortie : PASS/FAIL + diffs uniquement.
"""
import json
import re
import sys
import urllib.request

PROD_FILE = sys.argv[1] if len(sys.argv) > 1 else "/srv/github/secrets/github.env"
CANARY_FILE = sys.argv[2] if len(sys.argv) > 2 else "/opt/github-gateway-rs/.mcp_token"
PROD = "http://127.0.0.1:8799"
CANARY = "http://127.0.0.1:18999"

# Scripts operateur : loopback VPS uniquement.
BASES_AUTORISEES = (PROD, CANARY)


def lire_prod_env(path):
    try:
        with open(path, encoding="utf-8") as fh:
            content = fh.read()
    except OSError:
        print("ENV_PROD_ILLISIBLE")
        sys.exit(2)
    m = re.search(
        r"(?m)^\s*(?:export\s+)?GITHUB_MCP_TOKEN\s*=\s*['\"]?([^'\"\r\n]+)['\"]?\s*$",
        content,
    )
    if not m:
        print("ENV_PROD_SANS_JETON")
        sys.exit(2)
    tok = m.group(1).strip()
    if len(tok) < 32 or "\n" in tok:
        print("ENV_PROD_JETON_INVALIDE")
        sys.exit(2)
    return tok


def lire_token(path):
    try:
        with open(path, encoding="utf-8") as fh:
            tok = fh.read().strip()
    except OSError:
        print("JETON_CANARY_ILLISIBLE")
        sys.exit(2)
    if len(tok) < 32:
        print("JETON_CANARY_INVALIDE")
        sys.exit(2)
    return tok


TOKEN_PROD = lire_prod_env(PROD_FILE)
TOKEN_CANARY = lire_token(CANARY_FILE)


def sse_unwrap(raw):
    out = []
    for line in raw.decode("utf-8", "replace").splitlines():
        if line.startswith("data: "):
            try:
                out.append(json.loads(line[6:]))
            except ValueError:
                pass
    return out


def post(base, token, body, session=None):
    assert base in BASES_AUTORISEES, "loopback VPS uniquement"
    headers = {
        "content-type": "application/json",
        "accept": "application/json, text/event-stream",
        "authorization": "Bearer " + token,
        "mcp-protocol-version": "2025-11-25",
    }
    if session:
        headers["mcp-session-id"] = session
    req = urllib.request.Request(
        base + "/mcp", data=json.dumps(body).encode(), headers=headers, method="POST"
    )
    try:
        # base contrainte a BASES_AUTORISEES (loopback operateur, pas de file://)
        with urllib.request.urlopen(req, timeout=120) as res:  # nosemgrep: python.lang.security.audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected
            raw = res.read()
            sess = res.headers.get("mcp-session-id") or session
            status = res.status
    except Exception as exc:  # noqa: BLE001 - diagnostic smoke
        return -1, {"transport_error": str(exc)[:120]}, session
    try:
        return status, json.loads(raw), sess
    except ValueError:
        for m in sse_unwrap(raw):
            if m.get("id") == body.get("id"):
                return status, m, sess
        return status, {"sse_messages": len(sse_unwrap(raw))}, sess


def tools_map(resp):
    tools = ((resp.get("result") or {}).get("tools") or [])
    return {t.get("name"): t for t in tools if t.get("name")}


def norm_tool(t):
    return {
        "name": t.get("name"),
        "description": t.get("description"),
        "inputSchema": t.get("inputSchema"),
    }


diffs = []
sessions = {}

# 1. initialize (ouvre une session par cote)
for tag, base, token in (("prod", PROD, TOKEN_PROD), ("canary", CANARY, TOKEN_CANARY)):
    _, payload, sess = post(
        base, token,
        {"jsonrpc": "2.0", "id": 1, "method": "initialize",
         "params": {"protocolVersion": "2025-11-25", "capabilities": {},
                    "clientInfo": {"name": "diff", "version": "0"}}},
    )
    sessions[tag] = sess
    globals()[f"init_{tag}"] = payload

pi, ci = init_prod, init_canary
for key in ("protocolVersion",):
    if (pi.get("result") or {}).get(key) != (ci.get("result") or {}).get(key):
        diffs.append(f"initialize.{key}")
si_p = ((pi.get("result") or {}).get("serverInfo") or {})
si_c = ((ci.get("result") or {}).get("serverInfo") or {})
for key in ("name", "version"):
    if si_p.get(key) != si_c.get(key):
        diffs.append(f"initialize.serverInfo.{key}: prod={si_p.get(key)!r} canary={si_c.get(key)!r}")
print(f"initialize serverInfo: prod={si_p.get('name')} {si_p.get('version')} "
      f"canary={si_c.get('name')} {si_c.get('version')} "
      f"sessions: prod={bool(sessions['prod'])} canary={bool(sessions['canary'])}")

# 2. tools/list : noms + descriptions + schemas
_, pl, _ = post(PROD, TOKEN_PROD,
                {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
                sessions["prod"])
_, cl, _ = post(CANARY, TOKEN_CANARY,
                {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
                sessions["canary"])
pm, cm = tools_map(pl), tools_map(cl)
for name in sorted(set(pm) | set(cm)):
    if name not in pm:
        diffs.append(f"outil ajoute (canary seul) : {name}")
    elif name not in cm:
        diffs.append(f"outil perdu : {name}")
    elif norm_tool(pm[name]) != norm_tool(cm[name]):
        diffs.append(f"outil modifie : {name}")
print(f"prod tools: {len(pm)} canary tools: {len(cm)}")

# 3. resources/list + prompts/list
for method, attendu in (("resources/list", 4), ("prompts/list", 2)):
    _, pr, _ = post(PROD, TOKEN_PROD,
                    {"jsonrpc": "2.0", "id": 3, "method": method, "params": {}},
                    sessions["prod"])
    _, cr, _ = post(CANARY, TOKEN_CANARY,
                    {"jsonrpc": "2.0", "id": 3, "method": method, "params": {}},
                    sessions["canary"])
    cle = "resources" if method.startswith("resources") else "prompts"
    np = len(((pr.get("result") or {}).get(cle)) or [])
    nc = len(((cr.get("result") or {}).get(cle)) or [])
    print(f"{method}: prod={np} canary={nc}")
    if np != nc or np != attendu:
        diffs.append(f"{method}: prod={np} canary={nc} attendu={attendu}")

# 4. tools/call get_me : reel, read-only, des deux cotes
_, pg, _ = post(PROD, TOKEN_PROD,
                {"jsonrpc": "2.0", "id": 4, "method": "tools/call",
                 "params": {"name": "get_me", "arguments": {}}}, sessions["prod"])
_, cg, _ = post(CANARY, TOKEN_CANARY,
                {"jsonrpc": "2.0", "id": 4, "method": "tools/call",
                 "params": {"name": "get_me", "arguments": {}}}, sessions["canary"])
pe, ce = "error" in pg, "error" in cg
print(f"get_me: prod_erreur={pe} canary_erreur={ce}")
if pe != ce:
    diffs.append("get_me: erreur d'un seul cote")

# 5. refus local outil inconnu : -32000 des deux cotes, sans upstream
_, pu, _ = post(PROD, TOKEN_PROD,
                {"jsonrpc": "2.0", "id": 5, "method": "tools/call",
                 "params": {"name": "outil-inexistant-xyz", "arguments": {}}},
                sessions["prod"])
_, cu, _ = post(CANARY, TOKEN_CANARY,
                {"jsonrpc": "2.0", "id": 5, "method": "tools/call",
                 "params": {"name": "outil-inexistant-xyz", "arguments": {}}},
                sessions["canary"])
code_p = (pu.get("error") or {}).get("code")
code_c = (cu.get("error") or {}).get("code")
print(f"refus inconnu: prod={code_p} canary={code_c}")
if code_p != -32000 or code_c != -32000:
    diffs.append(f"refus inconnu: prod={code_p} canary={code_c} (attendu -32000)")

if diffs:
    print("DIFFS:")
    for d in diffs:
        print(f"  - {d}")
    print("RESULT: FAIL")
    sys.exit(1)
print("RESULT: PASS (diff contrat zero)")
