"""Red-team regressions: cases the rules were not originally written for.
Four of these failed on first run (2026-11-02) and were fixed; the rest document behaviour that held."""
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from pathlib import Path

from agentguard import scenarios as s1
from agentguard import scenarios_phase2 as s2
from agentguard.engine import evaluate
from agentguard.guard import Guard
from agentguard.ledger import Ledger
from agentguard.mandate import MandateBody, sign
from agentguard.models import Decision, EvaluationRequest
from agentguard.reconcile import PaymentApproved, PaymentObserved, PaymentSubmitted, Status, reconcile


def p1(**patch):
    d = s1.base()
    for k, v in patch.items():
        sec, f = k.split("__")
        d[sec][f] = v
    return EvaluationRequest.model_validate(d)


def signed_mandate(**overrides):
    body = MandateBody.model_validate({**s2.base_mandate(), **overrides})
    return sign(body, s2.PRINCIPAL_KEY, s2.PRINCIPAL_KEY_ID).model_dump(mode="json")


# ------------------------------------------------------------------ engine


def test_address_tricks_never_approve_a_different_address():
    assert evaluate(p1(transaction__to="0X" + s1.ATTACKER[2:])).decision == Decision.BLOCK
    # Whitespace around the approved address is rejected as malformed: safe, though strict.
    assert evaluate(p1(transaction__to=" " + s1.APPROVED + " ")).decision == Decision.BLOCK


def test_sub_cent_overpayment_is_not_approved():
    assert evaluate(p1(transaction__amount="50.000001")).decision == Decision.BLOCK


def test_token_and_chain_casing_is_normalised():
    assert evaluate(p1(transaction__token="usdc", transaction__chain="BASE")).decision == Decision.APPROVE


def test_split_across_one_payees_two_wallets_is_flagged_from_the_second_payment():
    """Found 2026-11-02: split detection grouped by address, so alternating wallets delayed the flag."""
    g = Guard(Ledger(":memory:"), clock=lambda: s2.NOW)
    m = signed_mandate(destinations=[s1.APPROVED, s1.REGISTRY_ALT], max_total=None, max_tx_count=None)
    decisions = []
    for i, to in enumerate([s1.APPROVED, s1.REGISTRY_ALT, s1.APPROVED, s1.REGISTRY_ALT]):
        d = s2.base_request()
        d.update(mandate=m, request_id=f"SPLIT-{i}")
        d["transaction"].update(to=to, amount="75")
        decisions.append(g.check(EvaluationRequest.model_validate(d)).decision)
    assert decisions == [Decision.APPROVE, Decision.REVIEW, Decision.REVIEW, Decision.REVIEW]


def test_mandate_cannot_be_replayed_on_another_chain():
    d = s2.base_request()
    d.update(mandate=signed_mandate(), request_id="X")
    d["transaction"]["chain"] = "ethereum"
    d["policy"]["allowed_chains"] = ["base", "ethereum"]
    with Ledger(":memory:").locked() as h:
        r = evaluate(EvaluationRequest.model_validate(d), history=h, now=s2.NOW)
    assert r.decision == Decision.BLOCK and "CHAIN_MISMATCH_INTENT" in r.reason_codes


def test_key_registered_to_another_principal_is_rejected():
    d = s2.base_request()
    d.update(mandate=signed_mandate(), request_id="X")
    d["policy"]["principal_keys"][0]["principal"] = "someone-else"
    assert evaluate(EvaluationRequest.model_validate(d), now=s2.NOW).reason_codes[0] == "MANDATE_UNKNOWN_SIGNER"


def test_naive_datetimes_in_mandate_are_treated_as_utc():
    d = s2.base_request()
    d.update(mandate=signed_mandate(valid_from="2026-10-01T00:00:00", expires_at="2026-10-14T00:00:00"),
             request_id="X")
    with Ledger(":memory:").locked() as h:
        r = evaluate(EvaluationRequest.model_validate(d), history=h, now=s2.NOW)
    assert "MANDATE_EXPIRED" in r.reason_codes and "MANDATE_VERIFIED" in r.reason_codes


# ------------------------------------------------------------------ reconcile

T = datetime(2026, 10, 10, 12, tzinfo=timezone.utc)
W, V = "0x" + "a" * 40, "0x" + "b" * 40


def ap(rid="R", amount="75", at=T):
    return PaymentApproved(request_id=rid, approved_at=at, agent_id="a", from_wallet=W, to_address=V,
                           amount=Decimal(amount), token="USDC", chain="base")


def ob(h, amount="75", at=T + timedelta(seconds=20), to=V):
    return PaymentObserved(chain="base", tx_hash=h, block_number=1000, block_time=at, token="USDC",
                           from_address=W, to_address=to, amount=Decimal(amount))


def statuses(a, o, s=()):
    return sorted(i.status.value for i in reconcile(a, o, list(s), as_of=T + timedelta(days=1),
                                                    heads={"base": 100_000}, agent_wallets={W}))


def test_six_decimal_amounts_reconcile_exactly():
    assert statuses([ap(amount="0.123456")], [ob("0x1", amount="0.123456")]) == ["CONFIRMED"]


def test_small_clock_skew_still_matches():
    """Found 2026-11-02: a block 5 s 'before' the engine's approval time raised MISSING + UNAPPROVED_OUTFLOW."""
    assert statuses([ap()], [ob("0x1", at=T - timedelta(seconds=5))]) == ["CONFIRMED"]
    # ...but a transfer well before the approval is not attributed to it.
    assert statuses([ap()], [ob("0x1", at=T - timedelta(hours=1))]) == ["MISSING", "UNAPPROVED_OUTFLOW"]


def test_one_transfer_cannot_pay_two_approvals():
    """Found 2026-11-02: the same tx hash reported for two requests confirmed both."""
    subs = [PaymentSubmitted(request_id="R1", tx_hash="0x1", submitted_at=T),
            PaymentSubmitted(request_id="R2", tx_hash="0x1", submitted_at=T)]
    items = reconcile([ap("R1"), ap("R2", at=T + timedelta(minutes=1))], [ob("0x1")], subs,
                      as_of=T + timedelta(days=1), heads={"base": 100_000}, agent_wallets={W})
    assert sorted(i.status.value for i in items) == ["CONFIRMED", "MISSING"]
    missing = next(i for i in items if i.status == Status.MISSING)
    assert missing.request_id == "R2" and "already pays for R1" in missing.explanation


def test_address_and_hash_case_do_not_matter():
    assert statuses([ap()], [ob("0x1", to="0x" + "B" * 40)]) == ["CONFIRMED"]
    assert statuses([ap()], [ob("0xABC")], [PaymentSubmitted(request_id="R", tx_hash="0xabc", submitted_at=T)]) \
        == ["CONFIRMED"]


def test_two_identical_approvals_one_transfer():
    assert statuses([ap("R1"), ap("R2", at=T + timedelta(seconds=30))],
                    [ob("0x1", at=T + timedelta(seconds=40))]) == ["CONFIRMED", "MISSING"]


def test_batch_loader_keeps_full_precision():
    """Found 2026-11-02: reconcile_batch rounded approved amounts to cents (USDC has 6 decimals)."""
    src = (Path(__file__).resolve().parents[1] / "scripts" / "reconcile_batch.py").read_text(encoding="utf-8")
    assert 'quantize(Decimal("0.01"))' not in src
