"""
Task 4: Rate Limiting and Model Fallback Router, with SQLite on disk

- Sliding window: 50,000 tokens per minute per tenant API key.
  State lives in an on disk SQLite file, not just in memory.
- Primary timeout: 3000 ms.
- Fallback triggers: primary returns 429, or primary times out.
- Errors returned to clients are standardised. Raw upstream traces,
  provider payloads, and stack traces are logged server side only.

Run:
    uvicorn router:app --port 8004
"""
import asyncio
import logging
import math
import os
import sqlite3
import threading
import time
from collections.abc import Awaitable, Callable

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

log = logging.getLogger("task4_router")
logging.basicConfig(level=logging.INFO)

DB_PATH = os.environ.get("RATE_LIMIT_DB", os.path.join(os.path.dirname(__file__), "rate_limit.db"))
LIMIT_TOKENS = 50_000
WINDOW_SECONDS = 60
PRIMARY_TIMEOUT_SECONDS = 3.0


class UpstreamError(Exception):
    def __init__(self, status: int, detail: str = ""):
        super().__init__(detail)
        self.status = status
        self.detail = detail


def gateway_error(code: str = "gateway_upstream_error", message: str = "Upstream model unavailable"):
    return {"error": {"code": code, "message": message}}


def estimate_tokens(text: str) -> int:
    """Rough token estimate, about four characters per token.

    Used when a caller does not declare a token count, so a request
    is never charged a flat made up number and never charged zero.
    """
    if not text:
        return 1
    return max(1, math.ceil(len(text) / 4))


class TokenRateLimiter:
    """SQLite backed sliding window limiter. Thread safe via a lock."""

    def __init__(self, db_path: str = DB_PATH, limit: int = LIMIT_TOKENS, window: int = WINDOW_SECONDS):
        self.db_path = db_path
        self.limit = limit
        self.window = window
        self._lock = threading.Lock()
        self._init_db()

    def _connect(self):
        return sqlite3.connect(self.db_path)

    def _init_db(self):
        # The configured path may point into a folder that does not
        # exist yet. Create it instead of crashing at import time.
        parent = os.path.dirname(os.path.abspath(self.db_path))
        os.makedirs(parent, exist_ok=True)
        with self._connect() as conn:
            conn.execute(
                "CREATE TABLE IF NOT EXISTS usage_events "
                "(tenant TEXT NOT NULL, ts REAL NOT NULL, tokens INTEGER NOT NULL)"
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_usage_tenant_ts ON usage_events(tenant, ts)")

    def check_and_record(self, tenant: str, tokens: int, now: float | None = None) -> bool:
        """
        Return True and record the usage if allowed.
        Return False and record nothing if this request would exceed the limit.
        Raise ValueError for a non positive token count. A negative
        count used to be recorded as negative usage, which handed the
        tenant free budget and silently disabled the limiter.
        """
        if tokens <= 0:
            raise ValueError("tokens must be positive")
        now = time.time() if now is None else now
        cutoff = now - self.window
        with self._lock:
            with self._connect() as conn:
                conn.execute("DELETE FROM usage_events WHERE ts <= ?", (cutoff,))
                row = conn.execute(
                    "SELECT COALESCE(SUM(tokens),0) FROM usage_events WHERE tenant=? AND ts>?", (tenant, cutoff)
                ).fetchone()
                used = int(row[0] or 0)
                if used + tokens > self.limit:
                    return False
                conn.execute("INSERT INTO usage_events(tenant, ts, tokens) VALUES (?,?,?)", (tenant, now, tokens))
                return True

    def used_in_window(self, tenant: str, now: float | None = None) -> int:
        now = time.time() if now is None else now
        cutoff = now - self.window
        with self._connect() as conn:
            row = conn.execute(
                "SELECT COALESCE(SUM(tokens),0) FROM usage_events WHERE tenant=? AND ts>?", (tenant, cutoff)
            ).fetchone()
            return int(row[0] or 0)


# Type for a model provider call
Provider = Callable[[dict], Awaitable[dict]]


class ModelRouter:
    def __init__(self, primary: Provider, secondary: Provider, limiter: TokenRateLimiter, timeout: float = PRIMARY_TIMEOUT_SECONDS):
        self.primary = primary
        self.secondary = secondary
        self.limiter = limiter
        self.timeout = timeout

    async def route(self, tenant: str, estimated_tokens: int, payload: dict) -> tuple[int, dict]:
        if estimated_tokens <= 0:
            return 400, gateway_error("invalid_request", "estimated_tokens must be positive")
        if not self.limiter.check_and_record(tenant, estimated_tokens):
            return 429, gateway_error("rate_limit_exceeded", "Rate limit exceeded for this tenant")

        # Primary, with timeout race
        try:
            result = await asyncio.wait_for(self.primary(payload), timeout=self.timeout)
            return 200, {"provider": "primary", "result": result}
        except asyncio.TimeoutError:
            log.warning("primary timed out, failing over")
        except UpstreamError as exc:
            if exc.status != 429:
                log.warning("primary failed with %s, not a fallback trigger", exc.status)
                return 502, gateway_error()
            log.warning("primary returned 429, failing over")
        except Exception as exc:  # do not leak this to the client
            log.exception("primary unexpected error: %s", exc)
            return 502, gateway_error()

        # Secondary
        try:
            result = await asyncio.wait_for(self.secondary(payload), timeout=self.timeout)
            return 200, {"provider": "secondary", "result": result}
        except Exception as exc:
            log.exception("secondary failed: %s", exc)
            return 502, gateway_error()


# ---- Demo providers and FastAPI app ----

async def primary_provider(payload: dict) -> dict:
    mode = payload.get("simulate_primary", "ok")
    if mode == "429":
        raise UpstreamError(429, "primary rate limited, internal detail must not leak")
    if mode == "timeout":
        await asyncio.sleep(5)
    return {"text": f"primary answer to: {payload.get('prompt','')}"}


async def secondary_provider(payload: dict) -> dict:
    if payload.get("simulate_secondary_fail"):
        raise UpstreamError(500, "secondary internal trace must not leak")
    return {"text": f"secondary answer to: {payload.get('prompt','')}"}


limiter = TokenRateLimiter()
router_service = ModelRouter(primary_provider, secondary_provider, limiter)

app = FastAPI(title="llm_router")


class CompletionRequest(BaseModel):
    prompt: str = ""
    # Optional on purpose. When a caller declares a count it is used
    # and must be positive (zero and negative values are rejected by
    # validation). When it is omitted, the count is estimated from
    # the prompt instead of charging a flat made up default.
    estimated_tokens: int | None = Field(default=None, gt=0)
    simulate_primary: str = "ok"
    simulate_secondary_fail: bool = False


@app.get("/health")
async def health():
    return {"ok": True, "db": DB_PATH, "limit": LIMIT_TOKENS}


@app.post("/complete")
async def complete(req: CompletionRequest, request: Request):
    tenant = request.headers.get("x-api-key") or "anonymous"
    tokens = req.estimated_tokens if req.estimated_tokens is not None else estimate_tokens(req.prompt)
    payload = req.model_dump()
    payload["estimated_tokens"] = tokens
    status, body = await router_service.route(tenant, tokens, payload)
    return JSONResponse(body, status_code=status)
