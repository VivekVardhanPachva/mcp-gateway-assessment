import asyncio
import os
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "task1_mcp_server"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "task3_stream_guardrail"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "task4_router"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "task2_mcp_gateway"))

import pytest
from pydantic import ValidationError

# Task 1 validation
from server import GetCustomerRecordInput, TriggerRefundInput

def test_task1_valid():
    assert GetCustomerRecordInput(customer_id="CUST-12345").customer_id == "CUST-12345"
    assert TriggerRefundInput(customer_id="CUST-12345", amount=10.5, reason="damaged product").amount == 10.5

@pytest.mark.parametrize("bad", ["12345", "CUST-123", "CUST-ABCDE", "cust-12345"])
def test_task1_bad_customer_id(bad):
    with pytest.raises(ValidationError):
        GetCustomerRecordInput(customer_id=bad)

def test_task1_bad_refund():
    with pytest.raises(ValidationError):
        TriggerRefundInput(customer_id="CUST-12345", amount=-1, reason="valid reason here")
    with pytest.raises(ValidationError):
        TriggerRefundInput(customer_id="CUST-12345", amount=10, reason="short")

# Task 2 auth logic
from gateway import role_from_auth_header

def test_task2_roles():
    assert role_from_auth_header("Bearer admin-token") == "admin"
    assert role_from_auth_header("Bearer viewer-token") == "viewer"
    assert role_from_auth_header(None) == "viewer"

# Task 3 redaction, including split chunks
from guardrail import StreamingRedactor, redact_text

def test_task3_redact_text():
    out = redact_text("mail a@b.com ssn 123-45-6789 card 4111 1111 1111 1111 end")
    assert "a@b.com" not in out and "123-45-6789" not in out and "4111" not in out
    assert out.count("[REDACTED]") == 3

def test_task3_split_chunks():
    text = "SSN is 123-45-6789 and email john.doe@example.com done"
    r = StreamingRedactor()
    pieces = [r.feed(text[i:i+3]) for i in range(0, len(text), 3)]
    pieces.append(r.flush())
    out = "".join(pieces)
    assert "123-45-6789" not in out
    assert "john.doe@example.com" not in out
    assert "[REDACTED]" in out

# Task 4 limiter and fallback
from router import ModelRouter, TokenRateLimiter, UpstreamError

def make_limiter():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    os.unlink(path)
    return TokenRateLimiter(db_path=path, limit=1000, window=60)

def test_task4_limiter():
    lim = make_limiter()
    assert lim.check_and_record("t1", 600, now=1000.0)
    assert lim.check_and_record("t1", 400, now=1001.0)
    assert not lim.check_and_record("t1", 1, now=1002.0)
    # other tenant unaffected
    assert lim.check_and_record("t2", 1000, now=1002.0)
    # window slides: old entries expire
    assert lim.check_and_record("t1", 1000, now=1062.0)

@pytest.mark.asyncio
async def test_task4_fallback_on_429():
    async def primary(payload):
        raise UpstreamError(429, "secret internal")
    async def secondary(payload):
        return {"text": "backup"}
    router = ModelRouter(primary, secondary, make_limiter())
    status, body = await router.route("tenant", 10, {})
    assert status == 200 and body["provider"] == "secondary"

@pytest.mark.asyncio
async def test_task4_fallback_on_timeout():
    async def primary(payload):
        await asyncio.sleep(2)
        return {"text": "late"}
    async def secondary(payload):
        return {"text": "backup"}
    router = ModelRouter(primary, secondary, make_limiter(), timeout=0.2)
    status, body = await router.route("tenant", 10, {})
    assert status == 200 and body["provider"] == "secondary"

@pytest.mark.asyncio
async def test_task4_both_fail_sanitised():
    async def primary(payload):
        raise UpstreamError(429, "secret internal primary trace")
    async def secondary(payload):
        raise UpstreamError(500, "secret internal secondary trace")
    router = ModelRouter(primary, secondary, make_limiter())
    status, body = await router.route("tenant", 10, {})
    assert status == 502
    assert "secret" not in str(body) and "trace" not in str(body)
    assert body["error"]["code"] == "gateway_upstream_error"
