"""Independent adversarial checks of reconciliation identity and route matching."""
from datetime import datetime, timedelta, timezone
from decimal import Decimal

import pytest

from agentguard.reconcile import PaymentApproved, PaymentObserved, PaymentSubmitted, reconcile

T = datetime(2026, 10, 10, tzinfo=timezone.utc)
W, V = '0x' + 'a' * 40, '0x' + 'b' * 40


def run(observations, submissions=None):
    approval = PaymentApproved(request_id='R', approved_at=T, agent_id='a', from_wallet=W,
                               to_address=V, amount=Decimal('75'), token='USDC', chain='base')
    if submissions is None:
        submissions = [PaymentSubmitted(request_id='R', tx_hash='0x1', submitted_at=T)]
    return reconcile([approval], observations, submissions, as_of=T + timedelta(days=1),
                     heads={'base': 10000, 'ethereum': 10000}, agent_wallets={W})


def observed(**patch):
    return PaymentObserved(**dict(chain='base', tx_hash='0x1', log_index=0, block_number=100,
                                  block_time=T + timedelta(seconds=10), token='USDC',
                                  from_address=W, to_address=V, amount=Decimal('75')) | patch)


@pytest.mark.parametrize('patch', [{'chain': 'ethereum'}, {'token': 'DAI'},
                                   {'from_address': '0x' + 'c' * 40}])
def test_reported_hash_cannot_confirm_wrong_route(patch):
    items = run([observed(**patch)])
    expected = ['MISSING'] if 'from_address' in patch else ['MISSING', 'UNAPPROVED_OUTFLOW']
    assert sorted(i.status.value for i in items) == expected


def test_repeated_submission_is_not_a_second_payment():
    submission = PaymentSubmitted(request_id='R', tx_hash='0x1', submitted_at=T)
    assert [i.status.value for i in run([observed()], [submission, submission])] == ['CONFIRMED']


def test_repeated_observation_is_not_a_second_payment():
    transfer = observed()
    assert [i.status.value for i in run([transfer, transfer])] == ['CONFIRMED']


def test_other_route_outflow_is_not_folded_into_duplicate():
    items = run([observed(), observed(tx_hash='0x2', token='DAI')], [])
    assert sorted(i.status.value for i in items) == ['CONFIRMED', 'UNAPPROVED_OUTFLOW']


def test_casing_does_not_change_event_identity():
    assert observed(chain='BASE').key == observed().key


def test_conflicting_event_payloads_fail_explicitly():
    with pytest.raises(ValueError, match='Conflicting observations'):
        run([observed(), observed(amount=Decimal('76'))])


def test_case_variants_of_one_event_count_once():
    assert [i.status.value for i in run([observed(), observed(chain='BASE', token='usdc')])] == ['CONFIRMED']


def test_genuinely_distinct_transfers_still_raise_duplicate():
    submissions = [PaymentSubmitted(request_id='R', tx_hash=h, submitted_at=T) for h in ['0x1', '0x2']]
    assert [i.status.value for i in run([observed(), observed(tx_hash='0x2')], submissions)] == ['DUPLICATE']
