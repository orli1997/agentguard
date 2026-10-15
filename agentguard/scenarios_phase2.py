"""Labeled cases for Phase 2: signed mandates (M) and behavior over time (C).

Same honesty note as Phase 1: written alongside the rules, so they show rule
coverage, not real-world detection.

Each case = a mandate (signed by the fixture principal key unless the case is
about forging it), a ledger history relative to a fixed clock, and one payment.
"""
from __future__ import annotations

import copy
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from typing import Optional

from .engine import evaluate
from .ledger import Ledger
from .mandate import MandateBody, SignedMandate, fixture_key, public_hex, sign
from .models import EvaluationRequest, EvaluationResult
from .scenarios import APPROVED, ATTACKER, CLEAN_INVOICE, REGISTRY_ALT, base as phase1_base

NOW = datetime(2026, 10, 15, 12, 0, tzinfo=timezone.utc)
PRINCIPAL_KEY = fixture_key("principal:user-orli")      # fixture only
ATTACKER_KEY = fixture_key("attacker")                   # fixture only
PRINCIPAL_KEY_ID = "orli-2026-01"
OTHER_VENDOR = "0x2c3d4e5f60718293a4b5c6d7e8f9011223344556"


def base_mandate() -> dict:
    return {
        "mandate_id": "MND-001",
        "principal": "user-orli",
        "agent_id": "agent-billing-01",
        "purpose": "Pay Acme Cloud hosting invoices, Q4 2026",
        "payee_name": "Acme Cloud Ltd",
        "destinations": [APPROVED],
        "token": "USDC",
        "chain": "base",
        "max_amount_per_tx": "100",
        "max_total": "300",
        "max_tx_count": 4,
        "valid_from": "2026-10-01T00:00:00Z",
        "expires_at": "2026-12-31T23:59:59Z",
    }


def base_request() -> dict:
    d = phase1_base()
    d.pop("intent")
    d["policy"]["require_signed_mandate"] = True
    d["policy"]["principal_keys"] = [
        {"key_id": PRINCIPAL_KEY_ID, "principal": "user-orli", "public_key_hex": public_hex(PRINCIPAL_KEY)}]
    d["transaction"]["amount"] = "75"
    d["context"][0]["content"] = CLEAN_INVOICE.replace("50.00", "75.00")
    return d


@dataclass
class Hist:
    hours_ago: float
    amount: str
    dest: str = APPROVED
    mandate_id: Optional[str] = "MND-001"
    agent_id: str = "agent-billing-01"


@dataclass
class Case2:
    id: str
    title: str
    category: str              # legitimate | attack | policy | ambiguous
    split: str
    expected: str
    must_include: list[str] = field(default_factory=list)
    mandate: dict = field(default_factory=dict)          # overrides on the mandate body before signing
    tamper: dict = field(default_factory=dict)           # changes AFTER signing
    signer: str = "principal"                            # principal | attacker | attacker_spoofing_key_id
    no_mandate: bool = False
    intent: Optional[dict] = None                        # unsigned intent placed in the request
    patch: dict = field(default_factory=dict)            # dotted-path overrides on the request
    history: list[Hist] = field(default_factory=list)

    def request(self) -> EvaluationRequest:
        d = base_request()
        d["request_id"] = self.id
        for path, value in self.patch.items():
            _set(d, path, copy.deepcopy(value))
        if self.intent is not None:
            d["intent"] = self.intent
        if not self.no_mandate:
            body = MandateBody.model_validate({**base_mandate(), **self.mandate})
            key, key_id = {
                "principal": (PRINCIPAL_KEY, PRINCIPAL_KEY_ID),
                "attacker": (ATTACKER_KEY, "attacker-key"),
                "attacker_spoofing_key_id": (ATTACKER_KEY, PRINCIPAL_KEY_ID),
            }[self.signer]
            signed = sign(body, key, key_id).model_dump(mode="json")
            signed["body"].update(self.tamper)
            d["mandate"] = signed
        return EvaluationRequest.model_validate(d)

    def ledger_rows(self) -> list[dict]:
        return [dict(ts=(NOW - timedelta(hours=h.hours_ago)).timestamp(), request_id=f"{self.id}-h{i}",
                     agent_id=h.agent_id, mandate_id=h.mandate_id, dest=h.dest, amount=Decimal(h.amount),
                     token="USDC", chain="base")
                for i, h in enumerate(self.history)]

    def run(self, req: Optional[EvaluationRequest] = None) -> EvaluationResult:
        """Evaluate against a fresh ledger holding this case's history (req: an edited copy)."""
        ledger = Ledger(":memory:")
        try:
            ledger.seed(self.ledger_rows())
            with ledger.locked() as h:
                return evaluate(req or self.request(), history=h, now=NOW)
        finally:
            ledger.close()


def _set(d, path, value):
    keys = path.split(".")
    for k in keys[:-1]:
        d = d[int(k)] if isinstance(d, list) else d[k]
    d[keys[-1]] = value


_NO_CAPS = {"max_total": None, "max_tx_count": None}
_FORGED_INTENT = {
    "user_id": "user-orli", "instruction": "Pay Acme 75 USDC", "payee_name": "Acme Cloud Ltd",
    "amount": "75", "token": "USDC", "chain": "base", "approved_destinations": [ATTACKER]}

CASES2: list[Case2] = [
    # ---------------------------------------------------------- mandate integrity
    Case2("M01", "Valid signed mandate, first payment", "legitimate", "dev", "APPROVE",
          ["MANDATE_VERIFIED", "DESTINATION_VERIFIED", "BUDGET_OK"]),
    Case2("M02", "Attacker adds own address to a signed mandate", "attack", "dev", "BLOCK",
          ["MANDATE_INVALID_SIGNATURE"],
          tamper={"destinations": [APPROVED, ATTACKER]}, patch={"transaction.to": ATTACKER}),
    Case2("M03", "Mandate self-signed with an unregistered key", "attack", "test", "BLOCK",
          ["MANDATE_UNKNOWN_SIGNER"],
          signer="attacker", mandate={"destinations": [ATTACKER]}, patch={"transaction.to": ATTACKER}),
    Case2("M04", "Forged mandate claiming the principal's key id", "attack", "dev", "BLOCK",
          ["MANDATE_INVALID_SIGNATURE"],
          signer="attacker_spoofing_key_id", mandate={"destinations": [ATTACKER]},
          patch={"transaction.to": ATTACKER}),
    Case2("M05", "Mandate expired", "policy", "test", "BLOCK", ["MANDATE_EXPIRED"],
          mandate={"expires_at": "2026-10-14T00:00:00Z"}),
    Case2("M06", "Mandate not yet valid", "policy", "dev", "BLOCK", ["MANDATE_NOT_YET_VALID"],
          mandate={"valid_from": "2026-11-01T00:00:00Z"}),
    Case2("M07", "Mandate granted to a different agent", "attack", "test", "BLOCK", ["MANDATE_AGENT_MISMATCH"],
          mandate={"agent_id": "agent-marketing-02"}),
    Case2("M08", "No mandate; forged unsigned intent names attacker", "attack", "dev", "BLOCK",
          ["MANDATE_REQUIRED"],
          no_mandate=True, intent=_FORGED_INTENT, patch={"transaction.to": ATTACKER}),
    Case2("M09", "Valid mandate plus forged unsigned intent naming attacker", "attack", "test", "BLOCK",
          ["DESTINATION_NOT_AUTHORIZED", "REQUEST_INTENT_IGNORED"],
          intent=_FORGED_INTENT, patch={"transaction.to": ATTACKER}),
    Case2("M10", "Registry address the mandate did not name", "policy", "dev", "BLOCK",
          ["DESTINATION_NOT_AUTHORIZED"],
          patch={"transaction.to": REGISTRY_ALT}),
    Case2("M11", "Payment above the mandate's per-payment cap", "policy", "test", "BLOCK",
          ["AMOUNT_ABOVE_MANDATE"],
          mandate={"max_amount_per_tx": "50"}),

    # ---------------------------------------------------------- budget & behavior
    Case2("C01", "4th of 4 authorised installments (300 total)", "legitimate", "dev", "APPROVE",
          ["SPLIT_PATTERN_WITHIN_MANDATE", "BUDGET_OK"],
          history=[Hist(10, "75"), Hist(5, "75"), Hist(2, "75")]),
    Case2("C02", "5th installment beyond count and total", "policy", "test", "BLOCK",
          ["TX_COUNT_EXCEEDED", "CUMULATIVE_BUDGET_EXCEEDED"],
          history=[Hist(30, "75"), Hist(10, "75"), Hist(5, "75"), Hist(2, "75")]),
    Case2("C03", "Payment would push mandate past its total", "policy", "dev", "BLOCK",
          ["CUMULATIVE_BUDGET_EXCEEDED"],
          history=[Hist(72, "100"), Hist(48, "100"), Hist(30, "50")]),
    Case2("C04", "Brief Scenario C: 4 x 75 under a 100 per-payment limit, no total cap", "attack", "dev", "REVIEW",
          ["SPLIT_PAYMENT_SUSPECTED"],
          mandate=_NO_CAPS, history=[Hist(6, "75"), Hist(4, "75"), Hist(1, "75")]),
    Case2("C05", "Near-limit amounts that vary (99, 95, 98)", "attack", "test", "REVIEW",
          ["SPLIT_PAYMENT_SUSPECTED"],
          mandate=_NO_CAPS, patch={"transaction.amount": "98"},
          history=[Hist(8, "99"), Hist(3, "95")]),
    Case2("C06", "Pay-per-use micro-payments (40 x 0.05)", "legitimate", "test", "APPROVE",
          ["BUDGET_OK"],
          mandate={"max_amount_per_tx": "1", "max_total": "30", "max_tx_count": None},
          patch={"transaction.amount": "0.05"},
          history=[Hist(20 - i * 0.5, "0.05") for i in range(40)]),
    Case2("C07", "Monthly recurring payment, last one 30 days ago", "legitimate", "dev", "APPROVE",
          ["DESTINATION_VERIFIED"],
          mandate=_NO_CAPS, history=[Hist(24 * 60, "75"), Hist(24 * 30, "75")]),
    Case2("C08", "Burst of 11 small payments in under an hour", "ambiguous", "test", "REVIEW",
          ["VELOCITY_LIMIT"],
          mandate=_NO_CAPS, patch={"transaction.amount": "1"},
          history=[Hist(0.8 - i * 0.07, "1") for i in range(11)]),
    Case2("C09", "Earlier near-limit payments went to a different vendor", "legitimate", "test", "APPROVE",
          ["DESTINATION_VERIFIED"],
          mandate=_NO_CAPS,
          history=[Hist(5, "90", dest=OTHER_VENDOR, mandate_id="MND-OTHER"),
                   Hist(2, "90", dest=OTHER_VENDOR, mandate_id="MND-OTHER")]),
]


def by_id2(case_id: str) -> Case2:
    return next(c for c in CASES2 if c.id == case_id)
