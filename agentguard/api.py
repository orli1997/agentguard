"""HTTP interface. Run: uvicorn agentguard.api:app --reload

In a real deployment the signer, not the agent, must call this endpoint and
refuse to sign unless the decision is APPROVE. An agent that can reach the
signer directly can simply skip the check.
"""
from __future__ import annotations

import os

from fastapi import FastAPI

from .audit import AuditLog
from .engine import ENGINE_VERSION, evaluate
from .models import EvaluationRequest, EvaluationResult

app = FastAPI(title="AgentGuard Pre-Signing Risk Engine", version=ENGINE_VERSION)
audit = AuditLog(os.environ.get("AGENTGUARD_AUDIT_DB", "agentguard_audit.db"))


@app.post("/v1/evaluate", response_model=EvaluationResult)
def evaluate_payment(req: EvaluationRequest) -> EvaluationResult:
    res = evaluate(req)
    audit.record(req, res)
    return res


@app.get("/v1/audit/verify")
def verify_audit() -> dict:
    ok, bad = audit.verify_chain()
    return {"ok": ok, "first_bad_seq": bad}


@app.get("/health")
def health() -> dict:
    return {"status": "ok", "engine_version": ENGINE_VERSION}
