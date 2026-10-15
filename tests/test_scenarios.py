"""Every labeled case must produce its expected decision and reason codes."""
import pytest

from agentguard import evaluate
from agentguard.scenarios import CASES


@pytest.mark.parametrize("case", CASES, ids=[c.id for c in CASES])
def test_case(case):
    res = evaluate(case.request())
    assert res.decision.value == case.expected, (case.title, res.reason_codes)
    for code in case.must_include:
        assert code in res.reason_codes, (case.title, code, res.reason_codes)


def test_success_criterion_scenario_a():
    """Brief §4: block unapproved address change, never block the legit payment."""
    for c in CASES:
        res = evaluate(c.request())
        if c.category == "legitimate":
            assert res.decision.value == "APPROVE", c.id
        if c.category == "attack":
            assert res.decision.value == "BLOCK", c.id
