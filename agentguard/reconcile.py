"""Phase 3: Reconcile what was approved with what actually happened on-chain.

    Approve -> (Submit) -> Observe -> Reconcile -> Explain

The chain alone does not know what was approved, and an approval alone does
not know what was executed. Reconciliation needs both:

  PaymentApproved   from AgentGuard's own decision log (APPROVE decisions)
  PaymentSubmitted  optional: the executor reports which tx_hash it broadcast
                    for which request. Without it we can only match by
                    wallet + destination + amount + time, and we say so.
  PaymentObserved   ERC-20 Transfer events (and receipts) read from the chain

Every approval ends in exactly one status, and every outgoing transfer from an
agent wallet is either claimed by an approval or reported as UNAPPROVED_OUTFLOW.
Deterministic: same inputs, same output. No LLM.
"""
from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timedelta
from decimal import Decimal
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field

from . import address as addr

# ------------------------------------------------------------------ data contract


class PaymentApproved(BaseModel):
    request_id: str                    # also the idempotency key
    approved_at: datetime
    agent_id: str
    mandate_id: Optional[str] = None
    from_wallet: str                   # the agent's wallet
    to_address: str
    amount: Decimal
    token: str
    chain: str
    decision_hash: Optional[str] = None   # link to the audit-log record of the APPROVE


class PaymentSubmitted(BaseModel):
    request_id: str
    tx_hash: str
    submitted_at: datetime
    attempt: int = 1                   # retries of the same request share request_id


class PaymentObserved(BaseModel):
    chain: str
    tx_hash: str
    log_index: int = 0
    block_number: int
    block_time: datetime
    token: str
    from_address: str
    to_address: str
    amount: Decimal
    status: str = "success"            # success | reverted (from the receipt)

    @property
    def key(self) -> tuple:
        return (self.chain.lower(), self.tx_hash.lower(), self.log_index)


class ReconConfig(BaseModel):
    required_confirmations: int = 12
    grace_minutes: float = 30          # how long an approval may stay unseen before it is MISSING
    match_window_hours: float = 24     # heuristic matching: transfer must land this soon after approval
    duplicate_window_minutes: float = 60
    # Engine clock and block timestamps come from different machines. Allow a transfer to look
    # slightly earlier than its approval before calling it unrelated.
    clock_skew_seconds: float = 120


class Status(str, Enum):
    CONFIRMED = "CONFIRMED"
    PENDING = "PENDING"
    MISSING = "MISSING"
    FAILED = "FAILED"
    DUPLICATE = "DUPLICATE"
    AMOUNT_MISMATCH = "AMOUNT_MISMATCH"
    DESTINATION_MISMATCH = "DESTINATION_MISMATCH"
    UNAPPROVED_OUTFLOW = "UNAPPROVED_OUTFLOW"


SEVERITY = {
    Status.CONFIRMED: "none", Status.PENDING: "low", Status.FAILED: "medium", Status.MISSING: "high",
    Status.DUPLICATE: "high", Status.AMOUNT_MISMATCH: "high", Status.DESTINATION_MISMATCH: "critical",
    Status.UNAPPROVED_OUTFLOW: "critical",
}


class ReconItem(BaseModel):
    subject: str                       # "approval" or "transfer"
    request_id: Optional[str] = None
    tx_hashes: list[str] = Field(default_factory=list)
    status: Status
    severity: str
    match_method: str                  # tx_hash | heuristic | none
    explanation: str
    action: str
    evidence: dict = Field(default_factory=dict)
    handling: str = "OPEN"             # OPEN | CLOSED

    @classmethod
    def make(cls, status: Status, **kw) -> "ReconItem":
        return cls(status=status, severity=SEVERITY[status],
                   handling="CLOSED" if status == Status.CONFIRMED else "OPEN", **kw)


# ------------------------------------------------------------------ helpers


def _short(a: str) -> str:
    return addr.short(a)


def _fmt(d: Decimal) -> str:
    return f"{d.normalize():f}"


def _decimals_hint(approved: Decimal, sent: Decimal) -> str:
    if sent == 0 or approved == 0:
        return ""
    ratio = sent / approved
    for k in range(1, 19):
        if ratio == Decimal(10) ** k or ratio == Decimal(10) ** -k:
            return f" The ratio is exactly 10^{k if ratio > 1 else -k}: likely a token-decimals bug in the executor."
    return ""


def _confirmations(o: PaymentObserved, heads: dict[str, int]) -> int:
    normalized_heads = {chain.lower(): height for chain, height in heads.items()}
    return max(0, normalized_heads.get(o.chain.lower(), o.block_number) - o.block_number + 1)


def _same_route(a: PaymentApproved, o: PaymentObserved) -> bool:
    return (o.chain.lower() == a.chain.lower() and o.token.upper() == a.token.upper()
            and addr.same_address(o.from_address, a.from_wallet))


# ------------------------------------------------------------------ reconcile


def reconcile(approved: list[PaymentApproved], observed: list[PaymentObserved],
              submitted: list[PaymentSubmitted], *, as_of: datetime, heads: dict[str, int],
              agent_wallets: set[str], cfg: ReconConfig = ReconConfig()) -> list[ReconItem]:
    """heads: latest block number per chain at as_of. agent_wallets: wallets whose outflows must be explained."""
    wallets = {addr.normalize(w) for w in agent_wallets}
    # Event identity, rather than ingestion count, determines how many payments happened.
    unique = {}
    for o in observed:
        previous = unique.get(o.key)
        if previous is not None:
            left, right = previous.model_dump(), o.model_dump()
            for data in (left, right):
                for field in ('chain', 'tx_hash', 'from_address', 'to_address', 'token'):
                    data[field] = data[field].lower()
            if left != right:
                raise ValueError(f'Conflicting observations for event {o.key}')
        else:
            unique[o.key] = o
    outflows = [o for o in unique.values() if addr.normalize(o.from_address) in wallets]
    by_hash: dict[str, list[PaymentObserved]] = defaultdict(list)
    for o in outflows:
        by_hash[o.tx_hash.lower()].append(o)
    subs_by_req: dict[str, list[PaymentSubmitted]] = defaultdict(list)
    for s in submitted:
        subs_by_req[s.request_id].append(s)

    claimed: set[tuple] = set()
    items: list[ReconItem] = []

    # Pass 1: approvals the executor linked to tx hashes. Strongest evidence, so they claim first.
    linked, unlinked = [], []
    for a in sorted(approved, key=lambda x: (x.approved_at, x.request_id)):
        (linked if subs_by_req.get(a.request_id) else unlinked).append(a)

    claimed_by: dict[tuple, str] = {}
    for a in linked:
        subs = sorted(subs_by_req[a.request_id], key=lambda s: s.attempt)
        found = list({o.key: o for s in subs for o in by_hash.get(s.tx_hash.lower(), [])
                      if _same_route(a, o)}.values())
        # A transfer pays for one approval only. If the executor reported the same hash twice,
        # the earlier approval keeps it and this one has no transfer of its own.
        taken = [o for o in found if o.key in claimed]
        hits = [o for o in found if o.key not in claimed]
        for o in hits:
            claimed.add(o.key)
            claimed_by[o.key] = a.request_id
        if taken and not hits:
            items.append(ReconItem.make(
                Status.MISSING, subject="approval", request_id=a.request_id, tx_hashes=[o.tx_hash for o in taken],
                match_method="none",
                explanation=(f"The executor reported tx {taken[0].tx_hash[:12]}… for this request, but that transfer "
                             f"already pays for {claimed_by[taken[0].key]}. This approval has no transfer of its own."),
                action="Ask the executor which request the tx belongs to; one of the two approvals was not paid.",
                evidence={"approval": a.model_dump(mode="json"), "submitted_tx_hashes": [s.tx_hash for s in subs],
                          "already_claimed_by": claimed_by[taken[0].key]}))
            continue
        items.append(_judge(a, hits, "tx_hash", [s.tx_hash for s in subs], as_of, heads, cfg))

    # Pass 2: unlinked approvals, matched by route + destination + exact amount inside the window.
    pool = sorted((o for o in outflows if o.key not in claimed), key=lambda o: (o.block_time, o.tx_hash))
    for a in unlinked:
        start = a.approved_at - timedelta(seconds=cfg.clock_skew_seconds)
        end = a.approved_at + timedelta(hours=cfg.match_window_hours)
        hit = next((o for o in pool if o.key not in claimed and _same_route(a, o)
                    and addr.same_address(o.to_address, a.to_address) and o.amount == a.amount
                    and start <= o.block_time <= end), None)
        if hit:
            claimed.add(hit.key)
        items.append(_judge(a, [hit] if hit else [], "heuristic" if hit else "none", [], as_of, heads, cfg))

    # Pass 3: anything else that left an agent wallet.
    approvals_by_route = defaultdict(list)
    for it, a in zip(items, linked + unlinked):
        approvals_by_route[(addr.normalize(a.to_address), a.amount)].append((it, a))
    for o in pool:
        if o.key in claimed or o.status != "success":
            continue
        twin = next(((it, a) for it, a in approvals_by_route.get((addr.normalize(o.to_address), o.amount), [])
                     if _same_route(a, o)
                     and it.status in (Status.CONFIRMED, Status.PENDING, Status.DUPLICATE) and it.evidence.get("block_time")
                     and abs((o.block_time - datetime.fromisoformat(it.evidence["block_time"])).total_seconds())
                     <= cfg.duplicate_window_minutes * 60), None)
        if twin:
            # Same payee, same amount, minutes after an already-settled approval and nothing else claims it:
            # treat it as a second execution of that approval rather than an unrelated outflow.
            it, a = twin
            claimed.add(o.key)
            _mark_duplicate(it, a, o, heuristic=True)
            continue
        items.append(ReconItem.make(
            Status.UNAPPROVED_OUTFLOW, subject="transfer", tx_hashes=[o.tx_hash], match_method="none",
            explanation=(f"{_fmt(o.amount)} {o.token} left agent wallet {_short(o.from_address)} for "
                         f"{_short(o.to_address)} in tx {o.tx_hash[:12]}… (block {o.block_number}), and no "
                         f"AgentGuard approval matches it. The agent's wallet was used without passing the guard."),
            action=("Treat as a possible bypass or key compromise: pause the agent's signing key, trace the "
                    "destination, and check whether an approval record was lost."),
            evidence={"transfer": o.model_dump(mode="json")}))
    return items


def _judge(a: PaymentApproved, hits: list[PaymentObserved], method: str, sub_hashes: list[str],
           as_of: datetime, heads: dict[str, int], cfg: ReconConfig) -> ReconItem:
    ev = {"approval": a.model_dump(mode="json"), "submitted_tx_hashes": sub_hashes,
          "observed": [h.model_dump(mode="json") for h in hits]}
    base = dict(subject="approval", request_id=a.request_id, tx_hashes=[h.tx_hash for h in hits] or sub_hashes,
                match_method=method if hits else "none", evidence=ev)
    ok = [h for h in hits if h.status == "success"]
    age_min = (as_of - a.approved_at).total_seconds() / 60

    if not hits:
        if sub_hashes and age_min > cfg.grace_minutes:
            return ReconItem.make(Status.MISSING, **base,
                explanation=(f"Executor reported tx {', '.join(h[:12] + '…' for h in sub_hashes)} but nothing from "
                             f"{_short(a.from_wallet)} with that hash is on {a.chain} after {age_min:.0f} min "
                             f"(dropped, replaced, or sent from another wallet)."),
                action="Check the executor's broadcast log and mempool. Do not re-send until the tx is known to be dead.")
        if age_min <= cfg.grace_minutes:
            return ReconItem.make(Status.PENDING, **base,
                explanation=f"Approved {age_min:.0f} min ago; not on-chain yet (grace period {cfg.grace_minutes:g} min).",
                action="Wait and re-check.")
        return ReconItem.make(Status.MISSING, **base,
            explanation=(f"Approved {_fmt(a.amount)} {a.token} to {_short(a.to_address)} at {a.approved_at:%Y-%m-%d %H:%M} "
                         f"UTC; no matching transfer from {_short(a.from_wallet)} after {age_min / 60:.1f} h, and the "
                         f"executor reported no tx hash."),
            action=("Ask the executor whether it ran. Re-send only with the same request_id, so a late original "
                    "cannot settle as a second payment."))

    if not ok:
        return ReconItem.make(Status.FAILED, **base,
            explanation=f"Tx {hits[0].tx_hash[:12]}… was mined in block {hits[0].block_number} but reverted; no funds moved.",
            action="Safe to retry with the same request_id.")

    first = ok[0]
    ev["block_time"] = first.block_time.isoformat()
    if not addr.same_address(first.to_address, a.to_address):
        return ReconItem.make(Status.DESTINATION_MISMATCH, **base,
            explanation=(f"Approved destination {_short(a.to_address)}, but tx {first.tx_hash[:12]}… paid "
                         f"{_fmt(first.amount)} {first.token} to {_short(first.to_address)}. The transaction changed "
                         f"after approval."),
            action=("Critical: pause the agent and executor keys, report the destination, and investigate how the "
                    "signed transaction differed from the approved one."))
    if first.amount != a.amount:
        diff = first.amount - a.amount
        return ReconItem.make(Status.AMOUNT_MISMATCH, **base,
            explanation=(f"Approved {_fmt(a.amount)} {a.token}; tx {first.tx_hash[:12]}… sent {_fmt(first.amount)} "
                         f"({'+' if diff > 0 else ''}{_fmt(diff)}).{_decimals_hint(a.amount, first.amount)}"),
            action=("Recover the overpayment from the payee." if diff > 0 else "Pay the shortfall under a new approval.")
                   + " Fix the executor before further payments.")
    if len(ok) > 1:
        item = _judge(a, [first], method, sub_hashes, as_of, heads, cfg)
        for extra in ok[1:]:
            _mark_duplicate(item, a, extra, heuristic=False)
        item.evidence["observed"] = [h.model_dump(mode="json") for h in hits]
        return item

    conf = _confirmations(first, heads)
    how = "linked by tx hash" if method == "tx_hash" else "matched by wallet, destination, amount and time (no tx hash reported)"
    if conf < cfg.required_confirmations:
        return ReconItem.make(Status.PENDING, **base,
            explanation=(f"Seen in tx {first.tx_hash[:12]}… (block {first.block_number}) with {conf}/"
                         f"{cfg.required_confirmations} confirmations; {how}."),
            action="Wait for finality before marking the invoice paid.")
    return ReconItem.make(Status.CONFIRMED, **base,
        explanation=(f"Paid once: {_fmt(first.amount)} {first.token} to {_short(first.to_address)} in tx "
                     f"{first.tx_hash[:12]}… (block {first.block_number}, {conf} confirmations); {how}."),
        action="None.")


def _mark_duplicate(item: ReconItem, a: PaymentApproved, extra: PaymentObserved, heuristic: bool) -> None:
    hashes = list(dict.fromkeys(item.tx_hashes + [extra.tx_hash]))
    total = a.amount * len(hashes)
    item.status, item.severity, item.handling = Status.DUPLICATE, SEVERITY[Status.DUPLICATE], "OPEN"
    item.tx_hashes = hashes
    item.evidence.setdefault("duplicates", []).append(extra.model_dump(mode="json"))
    basis = ("an identical transfer minutes later that no other approval explains" if heuristic
             else "more than one reported tx settled")
    item.explanation = (f"Paid {len(hashes)} times for one approval ({basis}): "
                        f"{', '.join(h[:12] + '…' for h in hashes)}. Approved {_fmt(a.amount)} {a.token}, "
                        f"sent {_fmt(total)} in total.")
    item.action = (f"Ask {_short(a.to_address)} to refund {_fmt(total - a.amount)} {a.token}. Make the executor "
                   f"idempotent: a retry must check whether the first tx already settled.")
