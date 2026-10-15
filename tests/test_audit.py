import sqlite3

from agentguard import evaluate
from agentguard.audit import AuditLog
from agentguard.scenarios import CASES


def test_audit_chain_and_tamper_detection(tmp_path):
    db = tmp_path / "audit.db"
    log = AuditLog(db)
    for c in CASES[:5]:
        r = c.request()
        log.record(r, evaluate(r))
    assert log.verify_chain() == (True, None)
    assert len(log.rows()) == 5

    # Rewrite an APPROVE as BLOCK after the fact -> chain must break at that row.
    with sqlite3.connect(db) as conn:
        conn.execute("UPDATE audit_log SET decision='BLOCK' WHERE seq=3")
    ok, bad = log.verify_chain()
    assert not ok and bad == 3


def test_audit_stores_full_evidence(tmp_path):
    log = AuditLog(tmp_path / "a.db")
    r = CASES[6].request()  # A07 injection attack
    rec = log.record(r, evaluate(r))
    assert "DESTINATION_NOT_AUTHORIZED" in rec["reason_codes"]
    assert "ignore all previous instructions" in rec["request_json"]
