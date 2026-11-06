"""
Task 2: MCP Security Gateway Proxy (Tool Filtering and Auth)

Run downstream first, then:
    DOWNSTREAM_URL=http://127.0.0.1:9001/mcp uvicorn gateway:app --port 8002

Token to role mapping (documented, because the task does not define a
token format). Only exact, delimited forms grant admin. A token that
merely starts with the letters admin, for example adminfoo or
administrator, is a viewer token. That prefix flaw was present in an
earlier version and is a real privilege escalation bug:
    Bearer admin-token      -> admin
    Bearer admin            -> admin
    Bearer admin:<anything> -> admin
    Bearer viewer-token     -> viewer
    Bearer viewer           -> viewer
    Bearer <JWT>            -> role read from the payload claims
                               (role, roles, or scope) when present.
                               Demo only: a production gateway must
                               verify the JWT signature first.
    Any other Bearer token  -> viewer
    No token -> viewer (least privilege)

Rules:
- tools/list: forward transparently
- tools/call where params.name starts with admin_ : admin only.
  Non admin gets JSON-RPC error -32001 directly, downstream is NOT called.
- Everything else: forward transparently.
- Malformed payloads get JSON-RPC errors, never a bare HTTP 500:
  unparseable body -32700, a body that is not a JSON-RPC object
  -32600, a tools/call whose params or tool name has the wrong
  shape -32602.
"""
import base64
import json
import os

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response

DOWNSTREAM_URL = os.environ.get("DOWNSTREAM_URL", "http://127.0.0.1:9001/mcp")

app = FastAPI(title="mcp_security_gateway")

_ADMIN_TOKENS = {"admin-token", "admin"}
_VIEWER_TOKENS = {"viewer-token", "viewer"}


def _role_from_jwt(token: str) -> str | None:
    """Return a role from a JWT shaped token, or None if it is not one."""
    parts = token.split(".")
    if len(parts) != 3:
        return None
    try:
        padded = parts[1] + "=" * (-len(parts[1]) % 4)
        claims = json.loads(base64.urlsafe_b64decode(padded))
    except Exception:
        return None
    if not isinstance(claims, dict):
        return None
    role = claims.get("role")
    if isinstance(role, str):
        return "admin" if role.lower() == "admin" else "viewer"
    for key in ("roles", "scope", "permissions"):
        values = claims.get(key)
        if isinstance(values, str):
            values = values.split()
        if isinstance(values, list) and any(str(v).lower() == "admin" for v in values):
            return "admin"
    return "viewer"


def role_from_auth_header(auth: str | None) -> str:
    if not auth or not auth.lower().startswith("bearer "):
        return "viewer"
    token = auth[7:].strip()
    if token in _ADMIN_TOKENS or token.startswith("admin:"):
        return "admin"
    if token in _VIEWER_TOKENS or token.startswith("viewer:"):
        return "viewer"
    jwt_role = _role_from_jwt(token)
    if jwt_role is not None:
        return jwt_role
    return "viewer"


def _rpc_error(req_id, code: int, message: str, status_code: int = 200):
    return JSONResponse(
        {"jsonrpc": "2.0", "id": req_id, "error": {"code": code, "message": message}},
        status_code=status_code,
    )


def unauthorized_response(req_id):
    return _rpc_error(req_id, -32001, "Unauthorized Tool Call")


@app.get("/health")
async def health():
    return {"ok": True, "downstream": DOWNSTREAM_URL}


@app.post("/mcp")
async def proxy(request: Request):
    try:
        payload = await request.json()
    except Exception:
        return _rpc_error(None, -32700, "Parse error", status_code=400)

    if not isinstance(payload, dict):
        # JSON-RPC batches are not part of current MCP. A list, a
        # string, or any other non object body is an Invalid Request.
        return _rpc_error(None, -32600, "Invalid Request", status_code=400)

    method = payload.get("method")
    req_id = payload.get("id")
    role = role_from_auth_header(request.headers.get("authorization"))

    if method == "tools/call":
        params = payload.get("params")
        if params is not None and not isinstance(params, dict):
            return _rpc_error(req_id, -32602, "Invalid params", status_code=400)
        tool_name = (params or {}).get("name")
        if tool_name is not None and not isinstance(tool_name, str):
            return _rpc_error(req_id, -32602, "Invalid params", status_code=400)
        if isinstance(tool_name, str) and tool_name.startswith("admin_") and role != "admin":
            return unauthorized_response(req_id)

    # Forward transparently
    try:
        # trust_env=False: the downstream is an internal service, so proxy
        # settings from the environment must not be applied to it.
        async with httpx.AsyncClient(timeout=10.0, trust_env=False) as client:
            resp = await client.post(DOWNSTREAM_URL, json=payload)
    except Exception:
        # Sanitised gateway error, no downstream internals leaked
        return _rpc_error(req_id, -32000, "Downstream unavailable", status_code=502)

    try:
        return JSONResponse(resp.json(), status_code=resp.status_code)
    except Exception:
        # Downstream answered with a non JSON body. Pass the raw body
        # and status through instead of crashing into an HTTP 500.
        return Response(
            content=resp.content,
            status_code=resp.status_code,
            media_type=resp.headers.get("content-type"),
        )
