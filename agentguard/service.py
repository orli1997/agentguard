"""The enforcing payment service (v2).

    agent --(API key, payment request)--> service --(APPROVE only)--> signer --> chain

What the agent controls: the payment it asks for and the context it read.
What it cannot control: who it is (the API key decides), its policy and the
trusted keys (server-side Store), the signing key (inside the signer), and how
many times one request_id is paid (idempotency record).

Run:  uvicorn agentguard.service:default_app --factory     (expects data/agentguard.db; see README)
"""
from __future__ import annotations

import os
from datetime import datetime, timezone
from decimal import Decimal
from pathlib import Path
from typing import Callable, Optional

from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel, ConfigDict, Field

from .audit import AuditLog
from .engine import ENGINE_VERSION
from .guard import Guard
from .ledger import Ledger
from .mandate import SignedMandate
from .models import AgentAction, ContextItem, Decision, EvaluationRequest, TransactionRequest
from .reconcile import PaymentApproved, PaymentSubmitted, ReconConfig, reconcile
from .signer import Signer, SimChainSigner
from .store import Store


class PaymentIn(BaseModel):
    """What an agent may send. Anything else (a policy, keys, an agent_id) is rejected with 422."""
    model_config = ConfigDict(extra="forbid")
    request_id: str = Field(min_length=1, max_length=128)
    mandate: Optional[SignedMandate] = None
    payee_name: str
    purpose: str = ""
    transaction: TransactionRequest
    context: list[ContextItem] = Field(default_factory=list)
    destination_source_id: Optional[str] = None


class PaymentOut(BaseModel):
    request_id: str
    agent_id: str
    decision: str
    reason_codes: list[str]
    tx_hash: Optional[str] = None
    replayed: bool = False
    error: Optional[str] = None


def build_app(store: Store, guard: Guard, signer: Signer,
              clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
              observer=None) -> FastAPI:
    app = FastAPI(title="AgentGuard payment service", version=ENGINE_VERSION)

    def authenticate(key: Optional[str]) -> str:
        agent = store.agent_for_key(key)
        if agent is None:
            raise HTTPException(status_code=401, detail="unknown or missing X-Agent-Key")
        return agent

    @app.post("/v2/payments", response_model=PaymentOut)
    def pay(body: PaymentIn, x_agent_key: Optional[str] = Header(default=None)) -> PaymentOut:
        agent = authenticate(x_agent_key)
        now = clock()
        state, previous = store.claim_request(agent, body.request_id, now)
        if state == "done":
            return PaymentOut(**{**previous, "replayed": True})
        if state == "in_progress":
            raise HTTPException(status_code=409, detail="this request_id is already being processed")

        req = EvaluationRequest(
            request_id=body.request_id, mandate=body.mandate, policy=store.policies[agent],
            action=AgentAction(agent_id=agent, stated_purpose=body.purpose, payee_name=body.payee_name,
                               destination_source_id=body.destination_source_id),
            transaction=body.transaction, context=body.context)
        res = guard.check(req)
        out = PaymentOut(request_id=body.request_id, agent_id=agent, decision=res.decision.value,
                         reason_codes=res.reason_codes)
        if res.decision == Decision.APPROVE:
            tx = body.transaction
            try:
                out.tx_hash = signer.transfer(chain=tx.chain, token=tx.token, from_wallet=store.wallets[agent],
                                              to=tx.to, amount=tx.amount, now=now)
                store.record_submission(body.request_id, out.tx_hash, now)
            except Exception as e:   # approved and reserved, but not sent: Reconcile will report it MISSING
                out.error = f"signer failed: {type(e).__name__}: {e}"
        store.finish_request(agent, body.request_id, out.model_dump())
        return out

    @app.get("/v2/reconcile")
    def recon() -> list[dict]:
        """Approved payments (ledger) vs. what the chain shows (observer), with explanations."""
        if observer is None:
            raise HTTPException(status_code=501, detail="no chain observer configured")
        approved = [PaymentApproved(request_id=r["request_id"], approved_at=datetime.fromtimestamp(r["ts"], timezone.utc),
                                    agent_id=r["agent_id"], mandate_id=r["mandate_id"],
                                    from_wallet=store.wallets[r["agent_id"]], to_address=r["dest"],
                                    amount=Decimal(r["amount"]), token=r["token"], chain=r["chain"])
                    for r in guard.ledger.all()]
        submitted = [PaymentSubmitted(request_id=s["request_id"], tx_hash=s["tx_hash"],
                                      submitted_at=datetime.fromisoformat(s["submitted_at"]), attempt=s["attempt"])
                     for s in store.submissions()]
        items = reconcile(approved, observer.observed(), submitted, as_of=clock(), heads=observer.heads(),
                          agent_wallets=set(store.wallets.values()), cfg=ReconConfig())
        return [i.model_dump(mode="json", exclude={"evidence"}) for i in items]

    @app.get("/health")
    def health() -> dict:
        return {"status": "ok", "engine_version": ENGINE_VERSION}

    return app


def default_app() -> FastAPI:
    root = Path(__file__).resolve().parents[1] / "data"
    state = Path(os.environ.get("AGENTGUARD_STATE_DB", root / "service.db"))
    store = Store(os.environ.get("AGENTGUARD_CONFIG_DB", root / "agentguard.db"), state)
    chain = SimChainSigner(state)
    guard = Guard(Ledger(str(state)), audit=AuditLog(state))
    return build_app(store, guard, chain, observer=chain)

