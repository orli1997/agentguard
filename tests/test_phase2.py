"""Phase 2: signed mandates, ledger-backed budget, splitting, velocity."""
import threading
from datetime import timedelta

import pytest

from agentguard import mandate as mandate_mod
from agentguard.engine import evaluate
from agentguard.guard import Guard
from agentguard.ledger import Ledger
from agentguard.models import Decision
from agentguard.scenarios_phase2 import (
    ATTACKER_KEY, CASES2, NOW, PRINCIPAL_KEY, PRINCIPAL_KEY_ID, by_id2,
)


@pytest.mark.parametrize("case", CASES2, ids=[c.id for c in CASES2])
def test_case(case):
    res = case.run()
    assert res.decision.value == case.expected, (case.title, res.reason_codes)
    for code in case.must_include:
        assert code in res.reason_codes, (case.title, code, res.reason_codes)


# ---------------------------------------------------------------- signatures


def test_signature_roundtrip_and_tamper():
    signed = by_id2("M01").request().mandate
    pub = mandate_mod.public_hex(PRINCIPAL_KEY)
    assert mandate_mod.verify(signed, pub)
    tampered = signed.model_copy(deep=True)
    tampered.body.max_total = tampered.body.max_total * 10
    assert not mandate_mod.verify(tampered, pub)
    assert not mandate_mod.verify(signed, mandate_mod.public_hex(ATTACKER_KEY))


def test_mandate_survives_json_roundtrip():
    """The API receives the mandate as JSON; re-parsing must not change the signed bytes."""
    req = by_id2("M01").request()
    from agentguard.models import EvaluationRequest
    again = EvaluationRequest.model_validate_json(req.model_dump_json())
    assert mandate_mod.verify(again.mandate, mandate_mod.public_hex(PRINCIPAL_KEY))


def test_garbage_signature_does_not_crash():
    req = by_id2("M01").request()
    req.mandate.signature = "zz-not-hex"
    res = evaluate(req, now=NOW)
    assert res.decision == Decision.BLOCK
    assert "MANDATE_INVALID_SIGNATURE" in res.reason_codes


def test_mandate_with_caps_but_no_ledger_fails_closed():
    res = evaluate(by_id2("M01").request(), history=None, now=NOW)
    assert res.decision == Decision.REVIEW
    assert "HISTORY_UNAVAILABLE" in res.reason_codes


# ---------------------------------------------------------------- guard + ledger


def _guard(tmp_path, start=NOW):
    clock = {"t": start}
    g = Guard(Ledger(str(tmp_path / "ledger.db")), clock=lambda: clock["t"])
    return g, clock


def test_guard_enforces_budget_across_calls(tmp_path):
    """Four 75 payments fit a 300 / 4-payment mandate; the fifth is blocked."""
    g, clock = _guard(tmp_path)
    base = by_id2("M01")
    decisions = []
    for i in range(5):
        req = base.request()
        req.request_id = f"pay-{i}"
        decisions.append(g.check(req).decision)
        clock["t"] += timedelta(days=2)  # spread out: this test is about budget, not splitting
    assert decisions == [Decision.APPROVE] * 4 + [Decision.BLOCK]
    assert len(g.ledger.all()) == 4


def test_blocked_and_reviewed_payments_are_not_recorded(tmp_path):
    g, _ = _guard(tmp_path)
    req = by_id2("M11").request()   # above per-payment cap -> BLOCK
    assert g.check(req).decision == Decision.BLOCK
    assert g.ledger.all() == []


def test_manual_approval_counts_toward_budget(tmp_path):
    g, clock = _guard(tmp_path)
    req = by_id2("M01").request()
    for _ in range(4):
        g.record_manual_approval(req)
        clock["t"] += timedelta(days=2)
    assert g.check(req).decision == Decision.BLOCK


def test_concurrent_requests_cannot_overspend(tmp_path):
    """Race: 8 threads each try to spend 75 from a 300 budget at the same instant -> exactly 4 succeed."""
    db = tmp_path / "race.db"
    results, start = [], threading.Barrier(8)

    def worker(i):
        g = Guard(Ledger(str(db)), clock=lambda: NOW)   # separate connection per thread
        req = by_id2("M01").request()
        req.request_id = f"race-{i}"
        start.wait()
        results.append(g.check(req).decision)
        g.ledger.close()

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert results.count(Decision.APPROVE) == 4, results
    check = Ledger(str(db))
    assert len(check.all()) == 4
    check.close()
