# AI Field Developer / Solutions Engineer Assessment: Reference Build

Four tasks, all in Python, in one repo. This is a study and run reference, built to the scoring criteria in the assessment brief.

## Setup

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
```

Note: `requirements.txt` pins `mcp>=1.0,<2`. In mcp 2.x, FastMCP was renamed, so the v1 pin keeps the official SDK import used in Task 1 working.

## Run the tests

```bash
.venv/bin/python -m pytest tests/ -v
```

Verified result after a full audit pass: 45 passed, no warnings, in both the project venv and a fresh venv installed from requirements.txt alone. The tests cover validation, the published tool schema, role parsing including JWT claims, malformed gateway payloads, split chunk redaction swept across prefixes and chunk sizes, the sliding window limiter under concurrency, fallback on 429, fallback on timeout, and sanitised errors when both providers fail. A 600 case fuzz run over streamed secrets at random positions and chunk sizes also passed with no leaks.

## Audit fixes (second pass)

A probing pass over the first build found real bugs, all fixed and covered by regression tests in tests/test_hardening.py:

- Task 1 published a tools/list schema with no constraints at all. The signatures now carry the validation rules, so the schema shows the pattern, the exclusive minimum, and the minimum length, and NaN or infinite refund amounts and whitespace only reasons are rejected.
- Task 2 treated any token starting with the letters admin, including administrator, as an admin token. Only exact or delimited token forms grant admin now, and JWT role claims are read when present. Malformed payloads used to return a bare HTTP 500 and now return proper JSON-RPC errors.
- Task 3 never redacted American Express format cards, and a card written with spaces followed by enough trailing text streamed through group by group and arrived intact. The redactor now uses lookahead across digit sequences, and one card pattern covers plain, grouped, dashed, and Amex formats.
- Task 4 recorded negative token counts as negative usage, which handed a tenant free budget and disabled the limiter. Non positive counts are now rejected at every layer, and a missing count is estimated from the prompt instead of charged a flat default.

## Task 1: MCP Server (`task1_mcp_server/server.py`)

Run it:

```bash
.venv/bin/python task1_mcp_server/server.py
```

It speaks JSON-RPC over stdio. Send `initialize`, then `notifications/initialized`, then `tools/list` or `tools/call`, one JSON object per line.

What to study:
- No `print` anywhere. Logs use the logging module pointed at stderr, so stdout stays pure JSON-RPC. Verified live with the official MCP client: initialize, tools/list, and valid and invalid calls all behave at protocol level, with logs only on stderr.
- The tool signatures carry the constraints, so tools/list publishes `pattern` for customer_id, `exclusiveMinimum` for amount, and `minLength` for reason. Pydantic models then re-validate inside the tool as defence in depth: `CUST-\d{5}`, amount greater than 0 and finite, reason at least 10 characters and not whitespace only. A call with customer_id BAD returns an error instead of running the tool.

## Task 2: MCP Security Gateway (`task2_mcp_gateway/`)

```bash
.venv/bin/python -m uvicorn --app-dir task2_mcp_gateway mock_downstream:app --port 9001
DOWNSTREAM_URL=http://127.0.0.1:9001/mcp .venv/bin/python -m uvicorn --app-dir task2_mcp_gateway gateway:app --port 8002
```

Tokens: `Bearer admin-token` is admin, `Bearer viewer-token` is viewer, no token is viewer. Only exact or delimited forms grant admin, a token like `administrator` is a viewer, and a JWT shaped token has its role read from its claims. Malformed bodies return JSON-RPC errors (-32700, -32600, -32602), never a bare HTTP 500.

Verified live, all cases:
- viewer + tools/list: forwarded, tool list returned
- viewer + tools/call get_customer_record: forwarded, downstream reached
- viewer + tools/call admin_reset_key: blocked, error code -32001, downstream not called
- prefix token `administrator` + admin tool: also blocked with -32001
- admin + tools/call admin_reset_key: forwarded, downstream reached
- tools/call with params as a string: error code -32602, HTTP 400, no crash

Note in the code: the downstream HTTP client uses `trust_env=False`, because an internal downstream must not be routed through environment proxy settings.

## Task 3: Streaming PII Guardrail (`task3_stream_guardrail/guardrail.py`)

```bash
.venv/bin/python -m uvicorn --app-dir task3_stream_guardrail guardrail:app --port 8003
curl -N -X POST localhost:8003/generate -H 'content-type: application/json' -d '{"mock_text":"ssn 123-45-6789 email a@b.com"}'
```

What to study, and the bugs earlier versions actually hit:
- The redactor holds back the last 40 characters and releases only safe text, chunk by chunk, so Time To First Token stays low and the full response is never buffered.
- Hold back alone is not enough. If a cut lands inside a token, the released half of an SSN no longer matches the pattern and leaks. The cut therefore moves back to the start of anything that crosses it: a full pattern match, a token, or a digit sequence, since a card is a digit sequence with spaces or dashes between groups, not a single token. That last case was a real leak in the audit: a spaced card followed by enough trailing text used to arrive intact, released one group at a time.
- Patterns: emails, SSNs in the form 123-45-6789, and cards of 13 to 19 digits in plain, grouped, dashed, and American Express formats, from one digit sequence pattern. All become `[REDACTED]`. Tests sweep prefixes 0 to 29 and chunk sizes 1 to 7 to prove no alignment leaks, and ordinary numbers such as order ids and years pass through unchanged.

## Task 4: Rate Limiting and Fallback Router (`task4_router/router.py`)

```bash
.venv/bin/python -m uvicorn --app-dir task4_router router:app --port 8004
curl -X POST localhost:8004/complete -H 'content-type: application/json' -H 'x-api-key: tenant1' -d '{"prompt":"hi","estimated_tokens":10}'
curl -X POST localhost:8004/complete -H 'content-type: application/json' -H 'x-api-key: tenant2' -d '{"prompt":"hi","estimated_tokens":10,"simulate_primary":"429"}'
curl -X POST localhost:8004/complete -H 'content-type: application/json' -H 'x-api-key: tenant3' -d '{"prompt":"hi","estimated_tokens":10,"simulate_primary":"timeout"}'
```

What to study:
- Usage is stored in an on disk SQLite file (`rate_limit.db` next to router.py, path overridable with the `RATE_LIMIT_DB` environment variable, parent folder created if missing), in a table of tenant, timestamp, and tokens.
- Each request, inside a lock and a transaction: delete rows older than 60 seconds, sum the rest for that tenant, reject with a standardised rate limit error if the sum plus the new estimate would pass 50000, otherwise insert and proceed. A concurrency test proves 30 parallel checks against a 1000 token budget admit exactly 10.
- Token counts must be positive. Zero or negative counts are rejected with 422 at the API and an error from the router and limiter, closing an audit found bypass where a negative count was recorded as negative usage and refunded budget. When the caller omits a count, it is estimated from the prompt at about four characters per token.
- The primary call races a 3000 ms timeout using `asyncio.wait_for`. A timeout or an upstream 429 triggers the secondary provider. Any other primary error returns the standardised gateway error immediately.
- If the secondary also fails, the client gets only `gateway_upstream_error` and a generic message. The real upstream detail is logged server side only. A test asserts the words from the fake internal traces never appear in the client payload
