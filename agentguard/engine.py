"""Deterministic pre-signing policy engine (Phase 1: Scenario A).

Design rules:
  * Trusted facts come only from UserIntent and AuthorizationPolicy.
    Context items (invoices, emails, ...) are always untrusted, whatever their label.
  * Every check emits Findings; the decision is a pure function of the
    worst severity. No score threshold decides anything.
  * Fail closed: missing information -> REVIEW, engine error -> REVIEW.
"""
from __future__ import annotations

import time

from . import address as addr
from . import injection
from .models import (
    Decision,
    EvaluationRequest,
    EvaluationResult,
    Finding,
    Severity,
    VendorRecord,
)

ENGINE_VERSION = "0.1.0-phaseA"

# Experimental score weights. Displayed only; never used to decide.
_WEIGHTS = {Severity.BLOCK: 60, Severity.REVIEW: 25, Severity.INFO: 5}


def _norm_name(s: str) -> str:
    return " ".join((s or "").lower().split())


def _registry_matches(req: EvaluationRequest) -> list[VendorRecord]:
    payee = _norm_name(req.intent.payee_name)
    return [
        v for v in req.policy.vendor_registry
        if _norm_name(v.name) == payee and v.chain.lower() == req.transaction.chain.lower()
    ]


def trusted_destinations(req: EvaluationRequest) -> dict[str, str]:
    """address(normalized) -> where the trust comes from."""
    out: dict[str, str] = {}
    for a in req.intent.approved_destinations:
        out[addr.normalize(a)] = "user_intent"
    for v in _registry_matches(req):
        for a in v.addresses:
            out.setdefault(addr.normalize(a), f"vendor_registry:{v.name}")
    return out


# ------------------------------------------------------------------ checks
# Each check takes the request and returns a list of findings.


def check_format(req: EvaluationRequest) -> list[Finding]:
    if not addr.is_valid_evm(req.transaction.to):
        return [Finding(code="INVALID_ADDRESS_FORMAT", severity=Severity.BLOCK,
                        message="Destination is not a valid EVM address.",
                        evidence={"to": req.transaction.to})]
    return []


def check_denylist(req: EvaluationRequest) -> list[Finding]:
    deny = {addr.normalize(a) for a in req.policy.denylist}
    if addr.normalize(req.transaction.to) in deny:
        return [Finding(code="DENYLISTED_DESTINATION", severity=Severity.BLOCK,
                        message="Destination is on the organisation denylist.",
                        evidence={"to": req.transaction.to})]
    return []


def check_asset(req: EvaluationRequest) -> list[Finding]:
    tx, pol, it = req.transaction, req.policy, req.intent
    f: list[Finding] = []
    if tx.token.upper() not in {t.upper() for t in pol.allowed_tokens}:
        f.append(Finding(code="TOKEN_NOT_ALLOWED", severity=Severity.BLOCK,
                         message=f"Token {tx.token} is not allowed by policy.",
                         evidence={"token": tx.token, "allowed": pol.allowed_tokens}))
    if tx.token.upper() != it.token.upper():
        f.append(Finding(code="TOKEN_MISMATCH_INTENT", severity=Severity.BLOCK,
                         message=f"User asked for {it.token}, agent is sending {tx.token}.",
                         evidence={"intent": it.token, "tx": tx.token}))
    if tx.chain.lower() not in {c.lower() for c in pol.allowed_chains}:
        f.append(Finding(code="CHAIN_NOT_ALLOWED", severity=Severity.BLOCK,
                         message=f"Chain {tx.chain} is not allowed by policy.",
                         evidence={"chain": tx.chain, "allowed": pol.allowed_chains}))
    if tx.chain.lower() != it.chain.lower():
        f.append(Finding(code="CHAIN_MISMATCH_INTENT", severity=Severity.BLOCK,
                         message=f"User asked for {it.chain}, agent is using {tx.chain}.",
                         evidence={"intent": it.chain, "tx": tx.chain}))
    return f


def check_amount(req: EvaluationRequest) -> list[Finding]:
    tx, pol, it = req.transaction, req.policy, req.intent
    f: list[Finding] = []
    if tx.amount > pol.max_amount_per_tx:
        f.append(Finding(code="AMOUNT_EXCEEDS_POLICY_LIMIT", severity=Severity.BLOCK,
                         message=f"{tx.amount} exceeds per-transaction limit {pol.max_amount_per_tx}.",
                         evidence={"amount": str(tx.amount), "limit": str(pol.max_amount_per_tx)}))
    if tx.amount > it.amount + pol.amount_tolerance:
        f.append(Finding(code="AMOUNT_ABOVE_INTENT", severity=Severity.BLOCK,
                         message=f"User authorised {it.amount}, agent requests {tx.amount}.",
                         evidence={"intent": str(it.amount), "tx": str(tx.amount),
                                   "tolerance": str(pol.amount_tolerance)}))
    elif tx.amount < it.amount:
        # Paying less is not theft, but it is not what was asked either.
        f.append(Finding(code="AMOUNT_BELOW_INTENT", severity=Severity.REVIEW,
                         message=f"User authorised {it.amount}, agent requests only {tx.amount}.",
                         evidence={"intent": str(it.amount), "tx": str(tx.amount)}))
    return f


def check_payee(req: EvaluationRequest) -> list[Finding]:
    if _norm_name(req.action.payee_name) != _norm_name(req.intent.payee_name):
        return [Finding(code="PAYEE_MISMATCH", severity=Severity.REVIEW,
                        message="Agent's payee differs from the payee the user named.",
                        evidence={"intent": req.intent.payee_name, "action": req.action.payee_name})]
    return []


def check_agent(req: EvaluationRequest) -> list[Finding]:
    if req.action.agent_id != req.policy.agent_id:
        return [Finding(code="AGENT_NOT_AUTHORIZED", severity=Severity.BLOCK,
                        message="Policy was issued for a different agent.",
                        evidence={"policy_agent": req.policy.agent_id, "action_agent": req.action.agent_id})]
    return []


def check_destination(req: EvaluationRequest) -> list[Finding]:
    """Core Scenario A check: is the destination one the user/org approved?"""
    to = req.transaction.to
    trusted = trusted_destinations(req)
    f: list[Finding] = []

    # Conflict between the two trusted sources is itself worth a human look.
    intent_set = {addr.normalize(a) for a in req.intent.approved_destinations}
    reg_set = {addr.normalize(a) for v in _registry_matches(req) for a in v.addresses}
    if intent_set and reg_set and not (intent_set & reg_set):
        f.append(Finding(code="TRUSTED_SOURCES_CONFLICT", severity=Severity.REVIEW,
                         message="User-approved address and vendor registry disagree.",
                         evidence={"intent": sorted(intent_set), "registry": sorted(reg_set)}))

    if addr.normalize(to) in trusted:
        f.append(Finding(code="DESTINATION_VERIFIED", severity=Severity.INFO,
                         message=f"Destination matches a trusted record ({trusted[addr.normalize(to)]}).",
                         evidence={"to": to, "trust_source": trusted[addr.normalize(to)]}))
        return f

    if not trusted:
        f.append(Finding(code="UNVERIFIED_DESTINATION", severity=Severity.REVIEW,
                         message="No trusted address on record for this payee; cannot verify destination.",
                         evidence={"to": to, "payee": req.intent.payee_name}))
        return f

    f.append(Finding(code="DESTINATION_NOT_AUTHORIZED", severity=Severity.BLOCK,
                     message=f"Destination {addr.short(to)} is not an approved address for {req.intent.payee_name}.",
                     evidence={"to": to, "approved": sorted(trusted)}))
    for t in trusted:
        if addr.is_lookalike(to, t):
            f.append(Finding(code="LOOKALIKE_ADDRESS", severity=Severity.BLOCK,
                             message=f"Destination mimics approved address {addr.short(t)} (same prefix/suffix).",
                             evidence={"to": to, "mimics": t}))
    return f


def check_provenance(req: EvaluationRequest) -> list[Finding]:
    """Where did the agent get the destination from, and does that hold up?"""
    to = req.transaction.to
    verified = addr.normalize(to) in trusted_destinations(req)
    # When the destination is already verified, provenance problems are noted, not escalated.
    sev = Severity.INFO if verified else Severity.REVIEW
    by_id = {c.id: c for c in req.context}
    f: list[Finding] = []

    src_id = req.action.destination_source_id
    if src_id:
        src = by_id.get(src_id)
        if src is None:
            f.append(Finding(code="PROVENANCE_MISSING", severity=sev,
                             message=f"Agent cites source '{src_id}' which was not supplied.",
                             evidence={"source_id": src_id}))
        else:
            if src.extracted_address and not addr.same_address(src.extracted_address, to):
                f.append(Finding(code="PROVENANCE_MISMATCH", severity=sev,
                                 message="Address in the cited source differs from the transaction destination.",
                                 evidence={"source_id": src_id, "source_address": src.extracted_address, "to": to}))
            if not verified:
                f.append(Finding(code="DESTINATION_FROM_UNTRUSTED_SOURCE", severity=Severity.INFO,
                                 message=f"Destination was taken from untrusted {src.source_type.value} '{src_id}'.",
                                 evidence={"source_id": src_id, "source_type": src.source_type.value}))

    # Addresses in context that are neither the destination nor trusted:
    # e.g. an invoice offering an "updated" wallet the agent did not use.
    trusted = trusted_destinations(req)
    for c in req.context:
        if c.extracted_address and addr.normalize(c.extracted_address) not in trusted \
                and not addr.same_address(c.extracted_address, to):
            f.append(Finding(code="UNTRUSTED_ADDRESS_IN_CONTEXT", severity=Severity.INFO,
                             message=f"{c.source_type.value} '{c.id}' contains an unapproved address the agent did not use.",
                             evidence={"source_id": c.id, "address": c.extracted_address}))
    return f


def check_injection(req: EvaluationRequest) -> list[Finding]:
    f: list[Finding] = []
    for c in req.context:
        hits = injection.scan(c.content)
        if hits:
            f.append(Finding(code="INSTRUCTION_IN_UNTRUSTED_CONTENT", severity=Severity.INFO,
                             message=f"{c.source_type.value} '{c.id}' contains instruction-like text "
                                     f"({', '.join(h['pattern'] for h in hits)}).",
                             evidence={"source_id": c.id, "hits": hits}))
    return f


CHECKS = [
    check_agent,
    check_format,
    check_denylist,
    check_asset,
    check_amount,
    check_payee,
    check_destination,
    check_provenance,
    check_injection,
]


# ------------------------------------------------------------------ decision


def decide(findings: list[Finding]) -> Decision:
    sev = {f.severity for f in findings}
    if Severity.BLOCK in sev:
        return Decision.BLOCK
    if Severity.REVIEW in sev:
        return Decision.REVIEW
    return Decision.APPROVE


def risk_score(findings: list[Finding]) -> int:
    return min(100, sum(_WEIGHTS[f.severity] for f in findings if f.code != "DESTINATION_VERIFIED"))


def evaluate(req: EvaluationRequest) -> EvaluationResult:
    t0 = time.perf_counter()
    findings: list[Finding] = []
    try:
        for check in CHECKS:
            findings.extend(check(req))
    except Exception as e:  # fail closed
        findings.append(Finding(code="ENGINE_ERROR", severity=Severity.REVIEW,
                                message="Engine error during evaluation; human review required.",
                                evidence={"error": f"{type(e).__name__}: {e}", "check": check.__name__}))
    order = {Severity.BLOCK: 0, Severity.REVIEW: 1, Severity.INFO: 2}
    findings.sort(key=lambda x: order[x.severity])
    return EvaluationResult(
        request_id=req.request_id,
        decision=decide(findings),
        risk_score=risk_score(findings),
        reason_codes=[f.code for f in findings],
        findings=findings,
        engine_version=ENGINE_VERSION,
        latency_ms=round((time.perf_counter() - t0) * 1000, 3),
    )
