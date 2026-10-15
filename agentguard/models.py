"""Data schema for the Pre-Signing Risk Engine.

Everything the engine needs arrives in one EvaluationRequest. The engine never
fetches data itself: what is not in the request does not exist for the decision.
"""
from __future__ import annotations

from decimal import Decimal
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field, model_validator

from .mandate import SignedMandate


class SourceType(str, Enum):
    """Label for something the agent read.

    Labels are descriptive only. Trust is NOT derived from them: an agent (or an
    attacker steering it) could label an invoice "vendor_registry". Trusted
    facts enter the engine only through UserIntent and AuthorizationPolicy,
    which the integrator fills from systems the agent cannot write to.
    """
    INVOICE = "invoice"
    EMAIL = "email"
    WEB_PAGE = "web_page"
    API_RESPONSE = "api_response"
    AGENT_MEMORY = "agent_memory"
    VENDOR_REGISTRY = "vendor_registry"
    UNKNOWN = "unknown"


class Decision(str, Enum):
    APPROVE = "APPROVE"
    REVIEW = "REVIEW"
    BLOCK = "BLOCK"


# ---------------------------------------------------------------- inputs


class UserIntent(BaseModel):
    """What the user actually asked for, captured from a trusted channel."""
    user_id: str
    instruction: str = Field(description="Original free-text instruction, kept for audit")
    payee_name: str
    amount: Decimal = Field(gt=0, description="Amount the user asked to pay")
    token: str
    chain: str
    # Destination(s) the user explicitly approved. Empty = user did not pin one.
    approved_destinations: list[str] = Field(default_factory=list)


class VendorRecord(BaseModel):
    name: str
    addresses: list[str]
    chain: str


class AuthorizationPolicy(BaseModel):
    """Organisation-level limits that apply to this agent."""
    agent_id: str
    max_amount_per_tx: Decimal = Field(gt=0)
    allowed_tokens: list[str]
    allowed_chains: list[str]
    # Tolerance above the user's stated amount before we treat it as a mismatch.
    # Default 0: pay exactly what the user said.
    amount_tolerance: Decimal = Decimal("0")
    vendor_registry: list[VendorRecord] = Field(default_factory=list)
    denylist: list[str] = Field(default_factory=list)

    # --- Phase 2: mandates
    # When true, authority comes ONLY from a valid signed mandate; request.intent is ignored.
    require_signed_mandate: bool = False
    principal_keys: list["PrincipalKey"] = Field(default_factory=list)

    # --- Phase 2: behavioral thresholds
    split_window_hours: float = 24
    # A payment counts toward a split pattern only if it is at least this share of the per-tx limit.
    # Keeps many tiny pay-per-use payments from looking like structuring.
    split_near_limit_ratio: Decimal = Decimal("0.5")
    velocity_window_minutes: float = 60
    velocity_max_tx: int = 10


class PrincipalKey(BaseModel):
    key_id: str
    principal: str
    public_key_hex: str


class ContextItem(BaseModel):
    """A piece of external information the agent read before acting."""
    id: str
    source_type: SourceType
    content: str = ""
    # Payment address the agent (or a parser) extracted from this item, if any.
    extracted_address: Optional[str] = None


class AgentAction(BaseModel):
    agent_id: str
    stated_purpose: str
    payee_name: str
    # Which context item the agent says it took the destination address from.
    destination_source_id: Optional[str] = None


class TransactionRequest(BaseModel):
    to: str
    amount: Decimal = Field(gt=0)
    token: str
    chain: str


class EvaluationRequest(BaseModel):
    request_id: str
    intent: Optional[UserIntent] = None
    mandate: Optional[SignedMandate] = None
    policy: AuthorizationPolicy
    action: AgentAction
    transaction: TransactionRequest
    context: list[ContextItem] = Field(default_factory=list)

    @model_validator(mode="after")
    def _needs_authority(self):
        if self.intent is None and self.mandate is None:
            raise ValueError("request needs an intent or a signed mandate")
        return self


# ---------------------------------------------------------------- outputs


class Severity(str, Enum):
    INFO = "info"      # recorded, does not change the decision
    REVIEW = "review"  # forces at least REVIEW
    BLOCK = "block"    # forces BLOCK


class Finding(BaseModel):
    code: str
    severity: Severity
    message: str
    evidence: dict = Field(default_factory=dict)


class EvaluationResult(BaseModel):
    request_id: str
    decision: Decision
    risk_score: int = Field(ge=0, le=100, description="Experimental; not calibrated")
    reason_codes: list[str]
    findings: list[Finding]
    engine_version: str
    latency_ms: float
