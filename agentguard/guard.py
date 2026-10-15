"""Guard = engine + ledger + audit, as one atomic pre-signing step.

    decision = guard.check(request)
    if decision.decision == "APPROVE": signer.sign(...)

APPROVE reserves the payment in the ledger inside the same lock that read the
history, so concurrent requests cannot jointly overspend a budget.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Callable, Optional

from .audit import AuditLog
from .engine import evaluate
from .ledger import Ledger
from .models import Decision, EvaluationRequest, EvaluationResult


class Guard:
    def __init__(self, ledger: Ledger, audit: Optional[AuditLog] = None,
                 clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc)):
        self.ledger, self.audit, self.clock = ledger, audit, clock

    def check(self, req: EvaluationRequest) -> EvaluationResult:
        now = self.clock()
        with self.ledger.locked() as history:
            res = evaluate(req, history=history, now=now)
            if res.decision == Decision.APPROVE:
                self._record(history, req, now, "approved")
        if self.audit:
            self.audit.record(req, res)
        return res

    def record_manual_approval(self, req: EvaluationRequest) -> None:
        """A human approved a REVIEW decision and the payment went out: it must count toward limits."""
        with self.ledger.locked() as history:
            self._record(history, req, self.clock(), "manual_approved")

    @staticmethod
    def _record(history, req: EvaluationRequest, now: datetime, status: str) -> None:
        tx = req.transaction
        history.record(ts=now.timestamp(), request_id=req.request_id, agent_id=req.action.agent_id,
                       mandate_id=req.mandate.body.mandate_id if req.mandate else None,
                       dest=tx.to, amount=tx.amount, token=tx.token, chain=tx.chain, status=status)
