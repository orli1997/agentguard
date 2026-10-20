"""Phase 3 reconcile: matching rules and edge cases, independent of the simulator."""
from datetime import datetime, timedelta, timezone
from decimal import Decimal

from agentguard.reconcile import (
    PaymentApproved, PaymentObserved, PaymentSubmitted, ReconConfig, Status, reconcile,
)

T = datetime(2026, 10, 10, 12, 0, tzinfo=timezone.utc)
WALLET = "0x" + "a" * 40
VENDOR = "0x" + "b" * 40
OTHER = "0x" + "c" * 40
B0 = 1_000_000


def appr(rid="R1", amount="75", to=VENDOR, at=T):
    return PaymentApproved(request_id=rid, approved_at=at, agent_id="ag", from_wallet=WALLET, to_address=to,
                           amount=Decimal(amount), token="USDC", chain="base")


def obs(h, amount="75", to=VENDOR, at=T + timedelta(seconds=20), frm=WALLET, status="success"):
    return PaymentObserved(chain="base", tx_hash=h, block_number=B0 + int((at - T).total_seconds() // 2),
                           block_time=at, token="USDC", from_address=frm, to_address=to,
                           amount=Decimal(amount), status=status)


def sub(rid, h, attempt=1):
    return PaymentSubmitted(request_id=rid, tx_hash=h, submitted_at=T, attempt=attempt)


def run(approved, observed, submitted=(), as_of=T + timedelta(days=1), head=None):
    head = head if head is not None else B0 + int((as_of - T).total_seconds() // 2)   # chain head at as_of
    return reconcile(approved, observed, list(submitted), as_of=as_of, heads={"base": head},
                     agent_wallets={WALLET}, cfg=ReconConfig())


def one(items, subject="approval"):
    xs = [i for i in items if i.subject == subject]
    assert len(xs) == 1, items
    return xs[0]


def test_confirmed_by_hash_and_by_heuristic():
    linked = one(run([appr()], [obs("0x1")], [sub("R1", "0x1")]))
    assert linked.status == Status.CONFIRMED and linked.match_method == "tx_hash" and linked.handling == "CLOSED"
    loose = one(run([appr()], [obs("0x1")]))
    assert loose.status == Status.CONFIRMED and loose.match_method == "heuristic"
    assert "no tx hash reported" in loose.explanation


def test_two_identical_weekly_payments_are_not_a_duplicate():
    """Same vendor, same amount, a week apart: two approvals, two transfers, one-to-one."""
    week = timedelta(days=7)
    items = run([appr("R1"), appr("R2", at=T + week)],
                [obs("0x1"), obs("0x2", at=T + week + timedelta(seconds=20))], as_of=T + week * 2)
    assert [i.status for i in items] == [Status.CONFIRMED, Status.CONFIRMED]
    assert {i.tx_hashes[0] for i in items} == {"0x1", "0x2"}


def test_duplicate_linked_retry():
    items = run([appr()], [obs("0x1"), obs("0x2", at=T + timedelta(minutes=3))],
                [sub("R1", "0x1"), sub("R1", "0x2", attempt=2)])
    it = one(items)
    assert it.status == Status.DUPLICATE and set(it.tx_hashes) == {"0x1", "0x2"}
    assert "refund 75" in it.action


def test_duplicate_unlinked_within_window_but_not_outside():
    near = run([appr()], [obs("0x1"), obs("0x2", at=T + timedelta(minutes=3))])
    assert one(near).status == Status.DUPLICATE and len(near) == 1
    far = run([appr()], [obs("0x1"), obs("0x2", at=T + timedelta(hours=5))])
    assert one(far).status == Status.CONFIRMED
    assert one(far, "transfer").status == Status.UNAPPROVED_OUTFLOW


def test_amount_mismatch_with_decimals_hint():
    it = one(run([appr()], [obs("0x1", amount="750")], [sub("R1", "0x1")]))
    assert it.status == Status.AMOUNT_MISMATCH and "10^1" in it.explanation and "Recover" in it.action


def test_destination_changed_after_approval_is_critical():
    it = one(run([appr()], [obs("0x1", to=OTHER)], [sub("R1", "0x1")]))
    assert it.status == Status.DESTINATION_MISMATCH and it.severity == "critical"


def test_reverted_is_failed_and_safe_to_retry():
    it = one(run([appr()], [obs("0x1", status="reverted")], [sub("R1", "0x1")]))
    assert it.status == Status.FAILED and "Safe to retry" in it.action


def test_pending_by_grace_period_and_by_confirmations():
    fresh = one(run([appr()], [], as_of=T + timedelta(minutes=10)))
    assert fresh.status == Status.PENDING
    o = obs("0x1")
    shallow = one(run([appr()], [o], [sub("R1", "0x1")], head=o.block_number + 3))
    assert shallow.status == Status.PENDING and "4/12" in shallow.explanation


def test_missing_with_and_without_reported_hash():
    dropped = one(run([appr()], [], [sub("R1", "0xdead")]))
    assert dropped.status == Status.MISSING and "0xdead" in dropped.explanation
    never = one(run([appr()], []))
    assert never.status == Status.MISSING and "Re-send only with the same request_id" in never.action


def test_inbound_transfers_are_ignored():
    topup = obs("0xin", amount="1000", frm=OTHER, to=WALLET)
    assert run([], [topup]) == []


def test_unapproved_outflow():
    it = one(run([], [obs("0xbad", to=OTHER, amount="240")]), "transfer")
    assert it.status == Status.UNAPPROVED_OUTFLOW and it.severity == "critical"


def test_known_limit_unlinked_wrong_amount():
    """Without a reported tx hash, a wrong-amount payment cannot be tied to its approval.
    It surfaces as MISSING + UNAPPROVED_OUTFLOW (both flagged), not as AMOUNT_MISMATCH.
    This is why the executor should report tx hashes."""
    items = run([appr()], [obs("0x1", amount="7.5")])
    assert sorted(i.status.value for i in items) == ["MISSING", "UNAPPROVED_OUTFLOW"]


def test_deterministic():
    args = ([appr("R1"), appr("R2", amount="10")], [obs("0x1"), obs("0x2", amount="10"), obs("0x3", to=OTHER)])
    assert [i.model_dump() for i in run(*args)] == [i.model_dump() for i in run(*args)]
