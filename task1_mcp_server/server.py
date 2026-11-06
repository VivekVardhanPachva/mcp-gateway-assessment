"""
Task 1: Custom MCP Server with Strict Validation and Transport Handling

Run:
    python server.py

Rules honoured:
- stdio transport only
- stdout is reserved for JSON-RPC. No print() anywhere in this file.
- All logs go to stderr via the logging module configured to sys.stderr.
- Inputs are validated twice, on purpose:
  1. The tool signatures carry the constraints as Annotated Field
     metadata, so tools/list publishes the real schema (pattern,
     exclusiveMinimum, minLength) and the SDK validates arguments
     against it before the tool body runs, returning a protocol
     level error for bad input. The underlying JSON-RPC code for
     invalid params is -32602.
  2. The tool bodies re-validate with the same Pydantic models, as
     defence in depth, so the logic never runs on unchecked input
     even if the server is embedded differently.
"""
import logging
import sys
from typing import Annotated, Any

from pydantic import BaseModel, Field, ValidationError, field_validator

from mcp.server.fastmcp import FastMCP

# Logs to stderr only. Never to stdout.
logging.basicConfig(stream=sys.stderr, level=logging.INFO)
log = logging.getLogger("task1_mcp_server")

mcp = FastMCP("customer_mcp_server")

# Fake data store. No real database is needed for this assessment.
CUSTOMERS: dict[str, dict[str, Any]] = {
    "CUST-12345": {"customer_id": "CUST-12345", "name": "Test Customer", "tier": "standard", "status": "active"},
    "CUST-00001": {"customer_id": "CUST-00001", "name": "Demo Customer", "tier": "premium", "status": "active"},
}

CUSTOMER_ID_PATTERN = r"^CUST-\d{5}$"


class GetCustomerRecordInput(BaseModel):
    customer_id: str = Field(pattern=CUSTOMER_ID_PATTERN)


class TriggerRefundInput(BaseModel):
    customer_id: str = Field(pattern=CUSTOMER_ID_PATTERN)
    # allow_inf_nan=False: NaN and infinity are not refund amounts,
    # and Pydantic accepts them for a plain float field otherwise.
    amount: float = Field(gt=0, allow_inf_nan=False)
    reason: str = Field(min_length=10)

    @field_validator("reason")
    @classmethod
    def reason_must_have_content(cls, value: str) -> str:
        # Ten spaces satisfy min_length but are not a reason.
        if not value.strip():
            raise ValueError("reason must contain non-whitespace text")
        return value


# Annotated constraints on the signatures are what FastMCP turns into
# the published JSON schema. Without them tools/list would advertise
# bare string and number types with no validation rules at all.
CustomerId = Annotated[str, Field(pattern=CUSTOMER_ID_PATTERN)]
RefundAmount = Annotated[float, Field(gt=0, allow_inf_nan=False)]
RefundReason = Annotated[str, Field(min_length=10)]


@mcp.tool()
def get_customer_record(customer_id: CustomerId) -> dict[str, Any]:
    """Get a customer record by id, formatted as CUST-XXXXX."""
    try:
        data = GetCustomerRecordInput(customer_id=customer_id)
    except ValidationError as exc:
        log.warning("validation failed for get_customer_record: %s", exc)
        # FastMCP turns a raised error into an MCP tool error response.
        # The validation detail is safe to return, it contains no secrets.
        raise ValueError(f"Invalid params: {exc.errors()}") from exc

    record = CUSTOMERS.get(data.customer_id)
    if record is None:
        return {"customer_id": data.customer_id, "found": False}
    return {"found": True, **record}


@mcp.tool()
def trigger_refund(customer_id: CustomerId, amount: RefundAmount, reason: RefundReason) -> dict[str, Any]:
    """Trigger a refund. amount must be positive, reason at least 10 chars."""
    try:
        data = TriggerRefundInput(customer_id=customer_id, amount=amount, reason=reason)
    except ValidationError as exc:
        log.warning("validation failed for trigger_refund: %s", exc)
        raise ValueError(f"Invalid params: {exc.errors()}") from exc

    log.info("refund triggered for %s amount=%s", data.customer_id, data.amount)
    return {
        "status": "refund_initiated",
        "customer_id": data.customer_id,
        "amount": data.amount,
        "reason": data.reason,
        "refund_id": f"REF-{data.customer_id[-5:]}-001",
    }


if __name__ == "__main__":
    log.info("starting MCP server on stdio")
    mcp.run(transport="stdio")
