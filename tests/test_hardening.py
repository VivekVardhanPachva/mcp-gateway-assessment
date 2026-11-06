"""Regression tests for the audit fixes.

Every test in this file corresponds to a bug that was actually found
by probing the first build: a published schema with no constraints,
an admin prefix privilege escalation, HTTP 500s on malformed gateway
payloads, an American Express card that was never redacted, a spaced
card that streamed through in slices when enough text followed it,
and a rate limiter that accepted negative token counts as free
budget.
"""
import base64
import json
import os
import sys
import tempfile
import threading
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "task1_mcp_server"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "task3_stream_guardrail"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "task4_router"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "task2_mcp_gateway"))

import pytest
from pydantic import ValidationError

# ---- Task 1: schema and validation hardening ----

from server import TriggerRefundInput, mcp as task1_server


@pytest.mark.asyncio
async def test_task1_published_schema_has_constraints():
    tools = {tool.name: tool for tool in await task1_server.list_tools()}
    customer = tools["get_customer_record"].inputSchema["properties"]["customer_id"]
    assert customer["pattern"] == r"^CUST-\d{5}$"
    refund = tools["trigger_refund"].inputSchema["properties"]
    assert refund["customer_id"]["pattern"] == r"^CUST-\d{5}$"
    assert refund["amount"]["exclusiveMinimum"] == 0
    assert refund["reason"]["minLength"] == 10


def test_task1_rejects_nan_and_infinite_amounts():
    for bad_amount in (float("nan"), float("inf"), float("-inf"), 0):
        with pytest.raises(ValidationError):
            TriggerRefundInput(
                customer_id="CUST-12345", amount=bad_amount, reason="a perfectly good reason"
            )


def test_task1_rejects_whitespace_only_reason():
    with pytest.raises(ValidationError):
        TriggerRefundInput(customer_id="CUST-12345", amount=10, reason="          ")


# ---- Task 2: auth and malformed payload hardening ----

from gateway import role_from_auth_header


def _jwt(claims) -> str:
    def enc(obj):
        raw = json.dumps(obj).encode()
        return base64.urlsafe_b64encode(raw).decode().rstrip("=")

    return f"{enc({'alg': 'none'})}.{enc(claims)}.signature"


def test_task2_prefix_tokens_are_not_admin():
    # The original bug: any token starting with the letters admin
    # was treated as an admin token.
    assert role_from_auth_header("Bearer adminfoo") == "viewer"
    assert role_from_auth_header("Bearer administrator") == "viewer"
    assert role_from_auth_header("Bearer admin-token-x") == "viewer"
    assert role_from_auth_header("Bearer ADMIN-TOKEN") == "viewer"


def test_task2_exact_and_delimited_tokens():
    assert role_from_auth_header("Bearer admin") == "admin"
    assert role_from_auth_header("Bearer admin:scoped-service") == "admin"
    assert role_from_auth_header("Bearer viewer") == "viewer"
    assert role_from_auth_header("bearer admin-token") == "admin"


def test_task2_jwt_role_claims():
    assert role_from_auth_header(f"Bearer {_jwt({'role': 'admin'})}") == "admin"
    assert role_from_auth_header(f"Bearer {_jwt({'role': 'viewer'})}") == "viewer"
    assert role_from_auth_header(f"Bearer {_jwt({'roles': ['viewer', 'admin']})}") == "admin"
    assert role_from_auth_header(f"Bearer {_jwt({'sub': 'someone'})}") == "viewer"
    assert role_from_auth_header("Bearer not.a.jwt") == "viewer"


def _gateway_client():
    from fastapi.testclient import TestClient

    import gateway

    return TestClient(gateway.app, raise_server_exceptions=False)


@pytest.mark.parametrize(
    "payload,code",
    [
        ({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": "oops"}, -32602),
        ({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": [1, 2]}, -32602),
        ({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": 123}}, -32602),
        ([{"jsonrpc": "2.0", "id": 1, "method": "tools/list"}], -32600),
        ("just a string", -32600),
        (42, -32600),
    ],
)
def test_task2_malformed_payloads_get_rpc_errors_not_500(payload, code):
    resp = _gateway_client().post("/mcp", json=payload)
    assert resp.status_code != 500
    body = resp.json()
    assert body["error"]["code"] == code


def test_task2_unparseable_body_gets_parse_error():
    resp = _gateway_client().post(
        "/mcp", content="{not json", headers={"content-type": "application/json"}
    )
    assert resp.status_code == 400
    assert resp.json()["error"]["code"] == -32700


def test_task2_block_and_forward_against_live_downstream():
    import uvicorn
    from fastapi.testclient import TestClient

    import gateway
    import mock_downstream

    config = uvicorn.Config(mock_downstream.app, host="127.0.0.1", port=9871, log_level="error")
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    try:
        for _ in range(100):
            if server.started:
                break
            time.sleep(0.05)
        assert server.started
        original = gateway.DOWNSTREAM_URL
        gateway.DOWNSTREAM_URL = "http://127.0.0.1:9871/mcp"
        try:
            client = TestClient(gateway.app, raise_server_exceptions=False)
            listed = client.post(
                "/mcp",
                json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
                headers={"authorization": "Bearer viewer-token"},
            )
            assert listed.status_code == 200 and "tools" in listed.json()["result"]

            blocked = client.post(
                "/mcp",
                json={
                    "jsonrpc": "2.0",
                    "id": 2,
                    "method": "tools/call",
                    "params": {"name": "admin_reset_key"},
                },
                headers={"authorization": "Bearer viewer-token"},
            )
            assert blocked.json()["error"]["code"] == -32001
            assert "result" not in blocked.json()

            # A prefix token must not unlock the admin tool either.
            sneaky = client.post(
                "/mcp",
                json={
                    "jsonrpc": "2.0",
                    "id": 3,
                    "method": "tools/call",
                    "params": {"name": "admin_reset_key"},
                },
                headers={"authorization": "Bearer administrator"},
            )
            assert sneaky.json()["error"]["code"] == -32001

            allowed = client.post(
                "/mcp",
                json={
                    "jsonrpc": "2.0",
                    "id": 4,
                    "method": "tools/call",
                    "params": {"name": "admin_reset_key"},
                },
                headers={"authorization": "Bearer admin-token"},
            )
            assert allowed.json()["result"]["downstream_reached"] is True
        finally:
            gateway.DOWNSTREAM_URL = original
    finally:
        server.should_exit = True
        thread.join(timeout=5)


# ---- Task 3: streaming redaction hardening ----

from guardrail import StreamingRedactor, redact_text


def _stream(text: str, chunk_size: int) -> str:
    redactor = StreamingRedactor()
    pieces = [
        redactor.feed(text[i : i + chunk_size]) for i in range(0, len(text), chunk_size)
    ]
    pieces.append(redactor.flush())
    return "".join(pieces)


def test_task3_amex_card_redacted():
    assert "3782" not in redact_text("card 3782 822463 10005 end")
    assert "[REDACTED]" in redact_text("card 3782-822463-10005 end")


@pytest.mark.parametrize("chunk_size", [1, 2, 3, 4, 5, 7])
def test_task3_spaced_card_never_leaks_at_any_alignment(chunk_size):
    # Regression test for the audit finding: with enough trailing
    # text, a spaced card used to be released one group at a time
    # and arrived at the client intact.
    for prefix_len in range(0, 30):
        text = "x" * prefix_len + " pay 4111 1111 1111 1111 end " + "y" * 50
        out = _stream(text, chunk_size)
        assert "4111" not in out, (prefix_len, chunk_size, out)
        assert "[REDACTED]" in out


@pytest.mark.parametrize("chunk_size", [1, 3, 5])
def test_task3_dashed_and_plain_cards_and_ssn_at_any_alignment(chunk_size):
    for prefix_len in range(0, 20):
        for secret in ("4111-1111-1111-1111", "4111111111111111", "123-45-6789"):
            text = "x" * prefix_len + f" value {secret} tail " + "y" * 50
            out = _stream(text, chunk_size)
            assert secret not in out, (prefix_len, chunk_size, secret, out)
            assert secret[:4] not in out, (prefix_len, chunk_size, secret, out)


def test_task3_long_email_split_one_char_at_a_time():
    text = "contact alexandra.peterson.longname@some-company-domain.example.com please" + " y" * 30
    out = _stream(text, 1)
    assert "alexandra" not in out
    assert "[REDACTED]" in out


def test_task3_ordinary_numbers_are_not_redacted():
    text = "order 12345 total 99 dollars, year 2026, phone 555 1234 done"
    assert _stream(text, 3) == text
    assert redact_text(text) == text


# ---- Task 4: limiter hardening ----

from router import ModelRouter, TokenRateLimiter, estimate_tokens


def _make_limiter(limit=1000):
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    os.unlink(path)
    return TokenRateLimiter(db_path=path, limit=limit, window=60)


def test_task4_negative_and_zero_tokens_raise():
    limiter = _make_limiter()
    for bad in (0, -1, -5000):
        with pytest.raises(ValueError):
            limiter.check_and_record("tenant", bad, now=1000.0)
    assert limiter.used_in_window("tenant", now=1000.0) == 0


@pytest.mark.asyncio
async def test_task4_route_rejects_non_positive_tokens():
    async def primary(payload):
        return {"text": "should not run"}

    async def secondary(payload):
        return {"text": "should not run"}

    router = ModelRouter(primary, secondary, _make_limiter())
    status, body = await router.route("tenant", -5000, {})
    assert status == 400
    assert body["error"]["code"] == "invalid_request"


def test_task4_estimate_tokens_scales_with_text():
    assert estimate_tokens("") == 1
    assert estimate_tokens("abcd") == 1
    assert estimate_tokens("a" * 400) == 100


def test_task4_limiter_db_parent_folder_is_created(tmp_path):
    path = tmp_path / "missing" / "folder" / "usage.db"
    limiter = TokenRateLimiter(db_path=str(path), limit=10, window=60)
    assert limiter.check_and_record("tenant", 10, now=1000.0)


def test_task4_concurrent_checks_never_exceed_limit():
    limiter = _make_limiter(limit=1000)
    results = []

    def attempt():
        try:
            results.append(limiter.check_and_record("shared", 100, now=1000.0))
        except Exception:
            results.append(False)

    threads = [threading.Thread(target=attempt) for _ in range(30)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert sum(1 for ok in results if ok) == 10
    assert limiter.used_in_window("shared", now=1000.0) == 1000


def test_task4_api_rejects_negative_tokens_and_estimates_when_missing():
    from fastapi.testclient import TestClient

    import router as router_module

    original = router_module.limiter
    router_module.limiter = _make_limiter(limit=1000)
    router_module.router_service.limiter = router_module.limiter
    try:
        client = TestClient(router_module.app, raise_server_exceptions=False)
        bad = client.post(
            "/complete",
            json={"prompt": "hi", "estimated_tokens": -5000},
            headers={"x-api-key": "api-neg"},
        )
        assert bad.status_code == 422
        ok = client.post(
            "/complete",
            json={"prompt": "a" * 400},
            headers={"x-api-key": "api-est"},
        )
        assert ok.status_code == 200
        assert router_module.limiter.used_in_window("api-est") == 100
    finally:
        router_module.router_service.limiter = original
        router_module.limiter = original
