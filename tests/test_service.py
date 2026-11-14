"""The enforcing service: identity from the API key, server-owned policy, signer only on APPROVE,
one request_id = at most one payment, and Reconcile over what the signer actually sent."""
import subprocess
import sys
import threading
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from agentguard.audit import AuditLog
from agentguard.guard import Guard
from agentguard.ledger import Ledger
from agentguard.mandate import MandateBody, fixture_key, sign
from agentguard.service import build_app
from agentguard.signer import SimChainSigner
from agentguard.store import Store, load_mandates

ROOT = Path(__file__).resolve().parents[1]
NOW = datetime(2026, 11, 14, 12, 0, tzinfo=timezone.utc)
ATTACKER = "0x" + "d" * 40


@pytest.fixture(scope="module")
def config_db(tmp_path_factory):
    db = tmp_path_factory.mktemp("cfg") / "config.db"
    subprocess.run([sys.executable, str(ROOT / "scripts" / "load_excel.py"),
                    str(ROOT / "data" / "agentguard_test_data.xlsx"), str(db)], check=True, capture_output=True)
    return db


@pytest.fixture
def svc(config_db, tmp_path):
    import sqlite3
    state = tmp_path / "state.db"
    store = Store(config_db, state)
    chain = SimChainSigner(state)
    clock = {"t": NOW}
    guard = Guard(Ledger(str(state)), audit=AuditLog(state), clock=lambda: clock["t"])
    app = build_app(store, guard, chain, clock=lambda: clock["t"], observer=chain)
    con = sqlite3.connect(config_db)
    mandates = load_mandates(con)
    con.close()

    class S:
        pass
    s = S()
    s.client, s.store, s.chain, s.clock, s.guard = TestClient(app), store, chain, clock, guard
    s.mandates = {k: v.model_dump(mode="json") for k, v in mandates.items()}
    s.billing_key = store.issue_agent_key("agent-billing-01", NOW)
    s.procure_key = store.issue_agent_key("agent-procure-02", NOW)
    s.acme = mandates["MND-101"].body.destinations[0]
    return s


def pay(s, key, request_id="P-1", to=None, amount="75", mandate="MND-101", **extra):
    body = {"request_id": request_id, "mandate": s.mandates[mandate] if mandate else None,
            "payee_name": "Acme Cloud Ltd", "purpose": "October hosting",
            "transaction": {"to": to or s.acme, "amount": amount, "token": "USDC", "chain": "base"}, **extra}
    return s.client.post("/v2/payments", json=body, headers={"X-Agent-Key": key} if key else {})


# ------------------------------------------------------------------ identity and trust


def test_no_or_wrong_key_is_rejected(svc):
    assert pay(svc, None).status_code == 401
    assert pay(svc, "agk_not-a-real-key").status_code == 401
    assert svc.chain.observed() == []


def test_agent_cannot_send_its_own_policy_or_identity(svc):
    assert pay(svc, svc.billing_key, policy={"max_amount_per_tx": "1000000"}).status_code == 422
    assert pay(svc, svc.billing_key, agent_id="agent-procure-02").status_code == 422


def test_identity_comes_from_the_key_not_the_mandate(svc):
    """The procurement agent presents the billing agent's mandate: blocked, nothing sent."""
    r = pay(svc, svc.procure_key).json()
    assert r["agent_id"] == "agent-procure-02" and r["decision"] == "BLOCK"
    assert "MANDATE_AGENT_MISMATCH" in r["reason_codes"] and r["tx_hash"] is None
    assert svc.chain.observed() == []


def test_agent_cannot_self_sign_a_mandate(svc):
    """Trusted principal keys live on the server; a mandate signed with any other key is refused."""
    body = MandateBody.model_validate({**svc.mandates["MND-101"]["body"], "destinations": [ATTACKER]})
    forged = sign(body, fixture_key("agent's own key"), "org-finance-2026").model_dump(mode="json")
    svc.mandates["FORGED"] = forged
    r = pay(svc, svc.billing_key, to=ATTACKER, mandate="FORGED").json()
    assert r["decision"] == "BLOCK" and "MANDATE_INVALID_SIGNATURE" in r["reason_codes"]
    assert svc.chain.observed() == []


# ------------------------------------------------------------------ the money path


def test_approved_payment_is_signed_once_by_the_service(svc):
    r = pay(svc, svc.billing_key).json()
    assert r["decision"] == "APPROVE" and r["tx_hash"].startswith("0x")
    [t] = svc.chain.observed()
    assert t.tx_hash == r["tx_hash"] and t.amount == Decimal("75") and t.to_address == svc.acme.lower()
    assert t.from_address == svc.store.wallets["agent-billing-01"].lower()
    assert [s["tx_hash"] for s in svc.store.submissions()] == [r["tx_hash"]]


def test_blocked_payment_never_reaches_the_signer(svc):
    r = pay(svc, svc.billing_key, to=ATTACKER).json()
    assert r["decision"] == "BLOCK" and r["tx_hash"] is None
    assert svc.chain.observed() == [] and svc.store.submissions() == []


def test_retry_with_same_request_id_pays_once(svc):
    """The x402 #452 situation: the agent times out and retries. The second call is answered from the record."""
    first = pay(svc, svc.billing_key, request_id="RETRY-1").json()
    second = pay(svc, svc.billing_key, request_id="RETRY-1").json()
    assert second["replayed"] is True and second["tx_hash"] == first["tx_hash"]
    assert len(svc.chain.observed()) == 1


def test_parallel_retries_pay_once(svc):
    results, barrier = [], threading.Barrier(6)

    def go():
        barrier.wait()
        results.append(pay(svc, svc.billing_key, request_id="RACE-1"))

    threads = [threading.Thread(target=go) for _ in range(6)]
    [t.start() for t in threads]
    [t.join() for t in threads]
    codes = sorted(r.status_code for r in results)
    assert codes.count(200) >= 1 and set(codes) <= {200, 409}
    assert len(svc.chain.observed()) == 1


def test_same_request_id_for_two_agents_is_independent(svc):
    a = pay(svc, svc.billing_key, request_id="SHARED").json()
    b = pay(svc, svc.procure_key, request_id="SHARED").json()
    assert a["decision"] == "APPROVE" and b["decision"] == "BLOCK" and b["replayed"] is False


def test_budget_is_enforced_across_calls(svc):
    """MND-101: 6 payments / 400 total. Five 75s fit (375); the sixth would make 450."""
    out = []
    for i in range(6):
        svc.clock["t"] = NOW + timedelta(days=2 * i)     # spread out: this test is about budget, not splitting
        out.append(pay(svc, svc.billing_key, request_id=f"B-{i}").json()["decision"])
    assert out == ["APPROVE"] * 5 + ["BLOCK"]
    assert len(svc.chain.observed()) == 5


# ------------------------------------------------------------------ reconcile over the real path


def test_reconcile_confirms_service_payments_and_flags_outside_outflow(svc):
    r = pay(svc, svc.billing_key).json()
    # Someone with the wallet key (not the service) moves money directly.
    svc.chain.transfer(chain="base", token="USDC", from_wallet=svc.store.wallets["agent-billing-01"], to=ATTACKER,
                       amount=Decimal("240"), now=NOW + timedelta(minutes=5))
    svc.chain.mine("base", 20)
    svc.clock["t"] = NOW + timedelta(hours=1)
    items = {(i["request_id"], i["status"]) for i in svc.client.get("/v2/reconcile").json()}
    assert ("P-1", "CONFIRMED") in items and (None, "UNAPPROVED_OUTFLOW") in items
    assert r["tx_hash"]


def test_signer_failure_is_reported_and_reconciled_as_missing(svc, monkeypatch):
    def broken(**kw):
        raise ConnectionError("node unreachable")
    monkeypatch.setattr(svc.chain, "transfer", broken)
    r = pay(svc, svc.billing_key, request_id="FAIL-1").json()
    assert r["decision"] == "APPROVE" and r["tx_hash"] is None and "node unreachable" in r["error"]
    svc.clock["t"] = NOW + timedelta(hours=2)
    items = {(i["request_id"], i["status"]) for i in svc.client.get("/v2/reconcile").json()}
    assert ("FAIL-1", "MISSING") in items
