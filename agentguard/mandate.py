"""Signed spending mandates (Phase 2).

A mandate is the principal's authorization, signed with the principal's
Ed25519 key. The agent carries it but cannot change it: any edit breaks the
signature. This closes the Phase 1 gap where "approved destinations" were
just fields in a request that whoever built the request could fill in.

Trust root = AuthorizationPolicy.principal_keys (org config, not agent-writable).
"""
from __future__ import annotations

import json
from datetime import datetime
from decimal import Decimal
from typing import Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from pydantic import BaseModel, Field


class MandateBody(BaseModel):
    mandate_id: str
    principal: str                 # user/company that grants authority
    agent_id: str                  # the only agent allowed to use it
    purpose: str
    payee_name: str
    destinations: list[str]        # allowed recipient addresses
    token: str
    chain: str
    max_amount_per_tx: Decimal = Field(gt=0)
    max_total: Optional[Decimal] = Field(default=None, gt=0)   # cumulative ceiling over the mandate's life
    max_tx_count: Optional[int] = Field(default=None, gt=0)
    valid_from: datetime
    expires_at: datetime


class SignedMandate(BaseModel):
    body: MandateBody
    key_id: str
    signature: str                 # hex Ed25519 signature over canonical(body)


def canonical(body: MandateBody) -> bytes:
    return json.dumps(body.model_dump(mode="json"), sort_keys=True, separators=(",", ":")).encode()


def sign(body: MandateBody, key: Ed25519PrivateKey, key_id: str) -> SignedMandate:
    return SignedMandate(body=body, key_id=key_id, signature=key.sign(canonical(body)).hex())


def verify(m: SignedMandate, public_key_hex: str) -> bool:
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_key_hex)).verify(
            bytes.fromhex(m.signature), canonical(m.body))
        return True
    except (InvalidSignature, ValueError):
        return False


def public_hex(key: Ed25519PrivateKey) -> str:
    from cryptography.hazmat.primitives import serialization
    return key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()


def fixture_key(seed: str) -> Ed25519PrivateKey:
    """Deterministic key for fixtures/demos ONLY. Never use for real funds."""
    import hashlib
    return Ed25519PrivateKey.from_private_bytes(hashlib.sha256(seed.encode()).digest())
