"""Deterministic pre-signing policy engine.

Phase 1: payment address injection (single transaction).
Phase 2: signed mandates + behavior over time (budget, splitting, velocity).

Design rules:
  * Authority comes from exactly one place: a verified signed mandate, or
    (legacy mode) the request's UserIntent. Context items are never trusted.
  * History comes from the engine's own ledger, never from the request.
  * Every check emits Findings; the decision is the worst severity present.
    The risk score is displayed, never used to decide.
  * Fail closed: missing information -> REVIEW, engine error -> REVIEW.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from typing import Optional

from . import address as addr
from . import injection
from . import mandate as mandate_mod
from .ledger import HistoryView
from .mandate import MandateBody
from .models import (
    Decision,
    EvaluationRequest,
    EvaluationResult,
    Finding,
    Severity,
    VendorRecord,
)

ENGINE_VERSION = "0.2.0-phase2"

_WEIGHTS = {Severity.BLOCK: 60, Severity.REVIEW: 25, Severity.INFO: 5}
_NEUTRAL = {"DESTINATION_VERIFIED", "MANDATE_VERIFIED", "BUDGET_OK"}  # info codes that are good news


@dataclass
class Authority:
    source: str                          # "intent" | "mandate"
    payee_name: str
    token: str
    chain: str
    pinned_destinations: list[str]
    max_amount: Decimal                  # ceiling for this single payment
    exact_amount: Optional[Decimal] = None   # intent mode: the amount the user named
    mandate: Optional[MandateBody] = None


@dataclass
class Ctx:
    req: EvaluationRequest
    now: datetime
    history: Optional[HistoryView]
    auth: Optional[Authority] = None
    findings: list[Finding] = field(default_factory=list)


def _f(code: str, sev: Severity, msg: str, **evidence) -> Finding:
    return Finding(code=code, severity=sev, message=msg, evidence=evidence)


def _norm_name(s: str) -> str:
    return " ".join((s or "").lower().split())


def _aware(dt: datetime) -> datetime:
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


# ------------------------------------------------------------------ authority


def resolve_authority(ctx: Ctx) -> list[Finding]:
    req, f = ctx.req, []
    if req.mandate is None:
        if req.policy.require_signed_mandate:
            return [_f("MANDATE_REQUIRED", Severity.BLOCK,
                       "Policy requires a signed mandate; none was supplied.",
                       unsigned_intent_supplied=req.intent is not None)]
        it = req.intent
        ctx.auth = Authority(
            source="intent", payee_name=it.payee_name, token=it.token, chain=it.chain,
            pinned_destinations=list(it.approved_destinations),
            max_amount=it.amount + req.policy.amount_tolerance, exact_amount=it.amount)
        return []

    m = req.mandate
    key = next((k for k in req.policy.principal_keys if k.key_id == m.key_id), None)
    if key is None or key.principal != m.body.principal:
        return [_f("MANDATE_UNKNOWN_SIGNER", Severity.BLOCK,
                   "Mandate is signed with a key that is not registered for this principal.",
                   key_id=m.key_id, principal=m.body.principal)]
    if not mandate_mod.verify(m, key.public_key_hex):
        return [_f("MANDATE_INVALID_SIGNATURE", Severity.BLOCK,
                   "Mandate signature does not match its content (altered or forged).",
                   mandate_id=m.body.mandate_id, key_id=m.key_id)]

    b = m.body
    if ctx.now < _aware(b.valid_from):
        f.append(_f("MANDATE_NOT_YET_VALID", Severity.BLOCK, f"Mandate is valid from {b.valid_from}.",
                    valid_from=b.valid_from.isoformat(), now=ctx.now.isoformat()))
    if ctx.now > _aware(b.expires_at):
        f.append(_f("MANDATE_EXPIRED", Severity.BLOCK, f"Mandate expired at {b.expires_at}.",
                    expires_at=b.expires_at.isoformat(), now=ctx.now.isoformat()))
    if b.agent_id != req.action.agent_id:
        f.append(_f("MANDATE_AGENT_MISMATCH", Severity.BLOCK,
                    "Mandate was granted to a different agent.",
                    mandate_agent=b.agent_id, action_agent=req.action.agent_id))
    if req.intent is not None:
        f.append(_f("REQUEST_INTENT_IGNORED", Severity.INFO,
                    "Signed mandate is the authority; the unsigned intent in the request was ignored.",
                    ignored_destinations=req.intent.approved_destinations))
    f.append(_f("MANDATE_VERIFIED", Severity.INFO, f"Mandate {b.mandate_id} signed by {b.principal} verified.",
                mandate_id=b.mandate_id, principal=b.principal, key_id=m.key_id))
    ctx.auth = Authority(
        source="mandate", payee_name=b.payee_name, token=b.token, chain=b.chain,
        pinned_destinations=list(b.destinations), max_amount=b.max_amount_per_tx, mandate=b)
    return f


def _registry_matches(ctx: Ctx) -> list[VendorRecord]:
    payee = _norm_name(ctx.auth.payee_name)
    chain = ctx.req.transaction.chain.lower()
    return [v for v in ctx.req.policy.vendor_registry
            if _norm_name(v.name) == payee and v.chain.lower() == chain]


def trusted_destinations(ctx: Ctx) -> dict[str, str]:
    """address(normalized) -> where the trust comes from."""
    a = ctx.auth
    label = "user_intent" if a.source == "intent" else f"signed_mandate:{a.mandate.mandate_id}"
    out = {addr.normalize(x): label for x in a.pinned_destinations}
    # A mandate that names destinations is exhaustive: the registry cannot widen it.
    if a.source == "mandate" and out:
        return out
    for v in _registry_matches(ctx):
        for x in v.addresses:
            out.setdefault(addr.normalize(x), f"vendor_registry:{v.name}")
    return out


# ------------------------------------------------------------------ static checks (need no authority)


def check_format(ctx: Ctx) -> list[Finding]:
    to = ctx.req.transaction.to
    if not addr.is_valid_evm(to):
        return [_f("INVALID_ADDRESS_FORMAT", Severity.BLOCK, "Destination is not a valid EVM address.", to=to)]
    return []


def check_denylist(ctx: Ctx) -> list[Finding]:
    deny = {addr.normalize(a) for a in ctx.req.policy.denylist}
    if addr.normalize(ctx.req.transaction.to) in deny:
        return [_f("DENYLISTED_DESTINATION", Severity.BLOCK, "Destination is on the organisation denylist.",
                   to=ctx.req.transaction.to)]
    return []


def check_policy_asset(ctx: Ctx) -> list[Finding]:
    tx, pol, f = ctx.req.transaction, ctx.req.policy, []
    if tx.token.upper() not in {t.upper() for t in pol.allowed_tokens}:
        f.append(_f("TOKEN_NOT_ALLOWED", Severity.BLOCK, f"Token {tx.token} is not allowed by policy.",
                    token=tx.token, allowed=pol.allowed_tokens))
    if tx.chain.lower() not in {c.lower() for c in pol.allowed_chains}:
        f.append(_f("CHAIN_NOT_ALLOWED", Severity.BLOCK, f"Chain {tx.chain} is not allowed by policy.",
                    chain=tx.chain, allowed=pol.allowed_chains))
    if tx.amount > pol.max_amount_per_tx:
        f.append(_f("AMOUNT_EXCEEDS_POLICY_LIMIT", Severity.BLOCK,
                    f"{tx.amount} exceeds per-transaction limit {pol.max_amount_per_tx}.",
                    amount=str(tx.amount), limit=str(pol.max_amount_per_tx)))
    return f


def check_agent(ctx: Ctx) -> list[Finding]:
    if ctx.req.action.agent_id != ctx.req.policy.agent_id:
        return [_f("AGENT_NOT_AUTHORIZED", Severity.BLOCK, "Policy was issued for a different agent.",
                   policy_agent=ctx.req.policy.agent_id, action_agent=ctx.req.action.agent_id)]
    return []


def check_injection(ctx: Ctx) -> list[Finding]:
    f = []
    for c in ctx.req.context:
        hits = injection.scan(c.content)
        if hits:
            f.append(_f("INSTRUCTION_IN_UNTRUSTED_CONTENT", Severity.INFO,
                        f"{c.source_type.value} '{c.id}' contains instruction-like text "
                        f"({', '.join(h['pattern'] for h in hits)}).", source_id=c.id, hits=hits))
    return f


# ------------------------------------------------------------------ authority checks


def check_asset_vs_authority(ctx: Ctx) -> list[Finding]:
    tx, a, f = ctx.req.transaction, ctx.auth, []
    who = "User asked for" if a.source == "intent" else "Mandate allows"
    if tx.token.upper() != a.token.upper():
        f.append(_f("TOKEN_MISMATCH_INTENT", Severity.BLOCK, f"{who} {a.token}, agent is sending {tx.token}.",
                    authorized=a.token, tx=tx.token))
    if tx.chain.lower() != a.chain.lower():
        f.append(_f("CHAIN_MISMATCH_INTENT", Severity.BLOCK, f"{who} {a.chain}, agent is using {tx.chain}.",
                    authorized=a.chain, tx=tx.chain))
    return f


def check_amount_vs_authority(ctx: Ctx) -> list[Finding]:
    tx, a = ctx.req.transaction, ctx.auth
    if a.source == "mandate":
        if tx.amount > a.max_amount:
            return [_f("AMOUNT_ABOVE_MANDATE", Severity.BLOCK,
                       f"Mandate allows up to {a.max_amount} per payment; agent requests {tx.amount}.",
                       max_per_tx=str(a.max_amount), tx=str(tx.amount))]
        return []
    if tx.amount > a.max_amount:
        return [_f("AMOUNT_ABOVE_INTENT", Severity.BLOCK,
                   f"User authorised {a.exact_amount}, agent requests {tx.amount}.",
                   intent=str(a.exact_amount), tx=str(tx.amount),
                   tolerance=str(ctx.req.policy.amount_tolerance))]
    if tx.amount < a.exact_amount:
        return [_f("AMOUNT_BELOW_INTENT", Severity.REVIEW,
                   f"User authorised {a.exact_amount}, agent requests only {tx.amount}.",
                   intent=str(a.exact_amount), tx=str(tx.amount))]
    return []


def check_payee(ctx: Ctx) -> list[Finding]:
    if _norm_name(ctx.req.action.payee_name) != _norm_name(ctx.auth.payee_name):
        return [_f("PAYEE_MISMATCH", Severity.REVIEW, "Agent's payee differs from the authorised payee.",
                   authorized=ctx.auth.payee_name, action=ctx.req.action.payee_name)]
    return []


def check_destination(ctx: Ctx) -> list[Finding]:
    to, f = ctx.req.transaction.to, []
    trusted = trusted_destinations(ctx)

    pinned = {addr.normalize(a) for a in ctx.auth.pinned_destinations}
    reg = {addr.normalize(a) for v in _registry_matches(ctx) for a in v.addresses}
    if pinned and reg and not (pinned & reg):
        f.append(_f("TRUSTED_SOURCES_CONFLICT", Severity.REVIEW,
                    "Authorised address and vendor registry disagree.",
                    authorized=sorted(pinned), registry=sorted(reg)))

    if addr.normalize(to) in trusted:
        f.append(_f("DESTINATION_VERIFIED", Severity.INFO,
                    f"Destination matches a trusted record ({trusted[addr.normalize(to)]}).",
                    to=to, trust_source=trusted[addr.normalize(to)]))
        return f
    if not trusted:
        f.append(_f("UNVERIFIED_DESTINATION", Severity.REVIEW,
                    "No trusted address on record for this payee; cannot verify destination.",
                    to=to, payee=ctx.auth.payee_name))
        return f
    f.append(_f("DESTINATION_NOT_AUTHORIZED", Severity.BLOCK,
                f"Destination {addr.short(to)} is not an approved address for {ctx.auth.payee_name}.",
                to=to, approved=sorted(trusted)))
    for t in trusted:
        if addr.is_lookalike(to, t):
            f.append(_f("LOOKALIKE_ADDRESS", Severity.BLOCK,
                        f"Destination mimics approved address {addr.short(t)} (same prefix/suffix).",
                        to=to, mimics=t))
    return f


def check_provenance(ctx: Ctx) -> list[Finding]:
    req, to = ctx.req, ctx.req.transaction.to
    trusted = trusted_destinations(ctx)
    verified = addr.normalize(to) in trusted
    sev = Severity.INFO if verified else Severity.REVIEW
    by_id = {c.id: c for c in req.context}
    f = []
    src_id = req.action.destination_source_id
    if src_id:
        src = by_id.get(src_id)
        if src is None:
            f.append(_f("PROVENANCE_MISSING", sev, f"Agent cites source '{src_id}' which was not supplied.",
                        source_id=src_id))
        else:
            if src.extracted_address and not addr.same_address(src.extracted_address, to):
                f.append(_f("PROVENANCE_MISMATCH", sev,
                            "Address in the cited source differs from the transaction destination.",
                            source_id=src_id, source_address=src.extracted_address, to=to))
            if not verified:
                f.append(_f("DESTINATION_FROM_UNTRUSTED_SOURCE", Severity.INFO,
                            f"Destination was taken from untrusted {src.source_type.value} '{src_id}'.",
                            source_id=src_id, source_type=src.source_type.value))
    for c in req.context:
        if c.extracted_address and addr.normalize(c.extracted_address) not in trusted \
                and not addr.same_address(c.extracted_address, to):
            f.append(_f("UNTRUSTED_ADDRESS_IN_CONTEXT", Severity.INFO,
                        f"{c.source_type.value} '{c.id}' contains an unapproved address the agent did not use.",
                        source_id=c.id, address=c.extracted_address))
    return f


# ------------------------------------------------------------------ behavioral checks (Phase 2)


def check_history_available(ctx: Ctx) -> list[Finding]:
    if ctx.history is not None:
        return []
    m = ctx.auth.mandate if ctx.auth else None
    if m and (m.max_total or m.max_tx_count):
        return [_f("HISTORY_UNAVAILABLE", Severity.REVIEW,
                   "Mandate has cumulative limits but no ledger is connected; cannot enforce them.",
                   unenforced=["max_total", "max_tx_count", "splitting", "velocity"])]
    return [_f("HISTORY_UNAVAILABLE", Severity.INFO,
               "No ledger connected; behavioral checks (splitting, velocity) skipped.",
               skipped=["splitting", "velocity"])]


def check_mandate_budget(ctx: Ctx) -> list[Finding]:
    m = ctx.auth.mandate
    if ctx.history is None or m is None or not (m.max_total or m.max_tx_count):
        return []
    spent, count = ctx.history.mandate_usage(m.mandate_id)
    amt, f = ctx.req.transaction.amount, []
    if m.max_total is not None and spent + amt > m.max_total:
        f.append(_f("CUMULATIVE_BUDGET_EXCEEDED", Severity.BLOCK,
                    f"Mandate total {m.max_total}: already spent {spent}, this payment {amt} would exceed it.",
                    max_total=str(m.max_total), spent=str(spent), amount=str(amt),
                    remaining=str(m.max_total - spent)))
    if m.max_tx_count is not None and count + 1 > m.max_tx_count:
        f.append(_f("TX_COUNT_EXCEEDED", Severity.BLOCK,
                    f"Mandate allows {m.max_tx_count} payments; {count} already made.",
                    max_tx_count=m.max_tx_count, used=count))
    if not f:
        f.append(_f("BUDGET_OK", Severity.INFO, f"Within mandate budget (spent {spent} of "
                    f"{m.max_total if m.max_total is not None else 'no cap'}, {count} payments).",
                    spent=str(spent), count=count))
    return f


def check_splitting(ctx: Ctx) -> list[Finding]:
    """Several near-limit payments to one destination that together exceed the single-payment limit."""
    if ctx.history is None:
        return []
    req, pol = ctx.req, ctx.req.policy
    tx, now = req.transaction, ctx.now
    limit = ctx.auth.max_amount if ctx.auth.source == "mandate" else pol.max_amount_per_tx
    near = (pol.split_near_limit_ratio * limit).quantize(Decimal("0.000001"))
    since = (now - timedelta(hours=pol.split_window_hours)).timestamp()
    dest = addr.normalize(tx.to)
    past = [p for p in ctx.history.agent_since(req.action.agent_id, since) if p.dest == dest]
    cluster = [p.amount for p in past if p.amount >= near]
    if tx.amount >= near:
        cluster.append(tx.amount)
    total = sum(cluster, Decimal(0))
    if len(cluster) < 2 or total <= limit:
        return []
    ev = dict(payments=len(cluster), total=str(total), single_limit=str(limit),
              near_limit_threshold=str(near), window_hours=pol.split_window_hours,
              amounts=[str(a) for a in cluster], destination=tx.to)
    m = ctx.auth.mandate
    if m is not None and m.max_total is not None:
        spent, _ = ctx.history.mandate_usage(m.mandate_id)
        if spent + tx.amount <= m.max_total:
            return [_f("SPLIT_PATTERN_WITHIN_MANDATE", Severity.INFO,
                       f"{len(cluster)} payments totalling {total} exceed the single limit {limit}, "
                       f"but the signed mandate explicitly authorises up to {m.max_total} in total.", **ev)]
    return [_f("SPLIT_PAYMENT_SUSPECTED", Severity.REVIEW,
               f"{len(cluster)} near-limit payments to {addr.short(tx.to)} within "
               f"{pol.split_window_hours:g}h total {total}, above the single-payment limit {limit}.", **ev)]


def check_velocity(ctx: Ctx) -> list[Finding]:
    if ctx.history is None:
        return []
    pol = ctx.req.policy
    since = (ctx.now - timedelta(minutes=pol.velocity_window_minutes)).timestamp()
    n = len(ctx.history.agent_since(ctx.req.action.agent_id, since)) + 1
    if n > pol.velocity_max_tx:
        return [_f("VELOCITY_LIMIT", Severity.REVIEW,
                   f"{n} payments by this agent in {pol.velocity_window_minutes:g} min "
                   f"(limit {pol.velocity_max_tx}).", count=n, limit=pol.velocity_max_tx,
                   window_minutes=pol.velocity_window_minutes)]
    return []


STATIC_CHECKS = [check_agent, check_format, check_denylist, check_policy_asset, check_injection]
AUTHORITY_CHECKS = [check_asset_vs_authority, check_amount_vs_authority, check_payee,
                    check_destination, check_provenance]
BEHAVIOR_CHECKS = [check_history_available, check_mandate_budget, check_splitting, check_velocity]


# ------------------------------------------------------------------ decision


def decide(findings: list[Finding]) -> Decision:
    sev = {f.severity for f in findings}
    if Severity.BLOCK in sev:
        return Decision.BLOCK
    if Severity.REVIEW in sev:
        return Decision.REVIEW
    return Decision.APPROVE


def risk_score(findings: list[Finding]) -> int:
    return min(100, sum(_WEIGHTS[f.severity] for f in findings if f.code not in _NEUTRAL))


def evaluate(req: EvaluationRequest, history: Optional[HistoryView] = None,
             now: Optional[datetime] = None) -> EvaluationResult:
    t0 = time.perf_counter()
    ctx = Ctx(req=req, now=_aware(now or datetime.now(timezone.utc)), history=history)
    step = "resolve_authority"
    try:
        ctx.findings.extend(resolve_authority(ctx))
        checks = STATIC_CHECKS + (AUTHORITY_CHECKS + BEHAVIOR_CHECKS if ctx.auth else [])
        for check in checks:
            step = check.__name__
            ctx.findings.extend(check(ctx))
    except Exception as e:  # fail closed
        ctx.findings.append(_f("ENGINE_ERROR", Severity.REVIEW,
                               "Engine error during evaluation; human review required.",
                               error=f"{type(e).__name__}: {e}", check=step))
    order = {Severity.BLOCK: 0, Severity.REVIEW: 1, Severity.INFO: 2}
    findings = sorted(ctx.findings, key=lambda x: order[x.severity])
    return EvaluationResult(
        request_id=req.request_id,
        decision=decide(findings),
        risk_score=risk_score(findings),
        reason_codes=[f.code for f in findings],
        findings=findings,
        engine_version=ENGINE_VERSION,
        latency_ms=round((time.perf_counter() - t0) * 1000, 3),
    )
