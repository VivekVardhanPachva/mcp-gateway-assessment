"""
Mock downstream MCP server for Task 2 testing.
It is a plain HTTP JSON-RPC endpoint. It records nothing, it just echoes
a tools/list result or a tools/call result, so tests can prove whether
the gateway forwarded a request or blocked it before forwarding.

Run:
    uvicorn mock_downstream:app --port 9001
"""
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

app = FastAPI(title="mock_downstream_mcp")


@app.get("/health")
async def health():
    return {"ok": True}


@app.post("/mcp")
async def mcp_endpoint(request: Request):
    payload = await request.json()
    method = payload.get("method")
    req_id = payload.get("id")
    if method == "tools/list":
        result = {"tools": [{"name": "get_customer_record"}, {"name": "admin_reset_key"}]}
    elif method == "tools/call":
        name = (payload.get("params") or {}).get("name")
        result = {"content": [{"type": "text", "text": f"called:{name}"}], "downstream_reached": True}
    else:
        result = {"echo_method": method}
    return JSONResponse({"jsonrpc": "2.0", "id": req_id, "result": result})
