"""Address-poisoning intel: lookup against a detector-shaped live.db, findings, and the service refusing to sign."""
import sqlite3
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from agentguard import evaluate
from agentguard.guard import Guard
from agentguard.ledger import Ledger
from agentguard.models import Decision, EvaluationRequest
from agentguard.poisoning_intel import PoisoningIntel, low_entropy, poisoning_findings
from agentguard.scenarios import base
from agentguard.service import build_app
from agentguard.signer import SimChainSigner
from agentguard.store import Store, load_mandates

ROOT = Path(__file__).resolve().parents[1]
NOW = datetime(2026, 11, 14, 12, 0, tzinfo=timezone.utc)
T = NOW.timestamp()
# A real pair the detector caught on Base mainnet (also on the project's slides).
REAL = "0xa742314be408fc06f304d9b84b69ad0c3ad8b9c3"
FAKE = "0xa742debd5ae04e578b7a6c0130a3aacd409ab9c3"
VANITY_FAKE = "0x0000aa11bb22cc33dd44ee55ff6677889900ffff"
VANITY_REAL = "0x0000123456789abcdef0123456789abcdefaffff"

# Copied from the detector's live.db schema (poison/live.py), only the tables AgentGuard reads.
SCHEMA = """
CREATE TABLE pairs (victim TEXT, lookalike TEXT, mimics TEXT, prefix_match INT, suffix_match INT, pattern TEXT,
                    first_block INT, first_tx TEXT, last_block INT, events INT, detected_at REAL,
                    PRIMARY KEY (victim, lookalike));
CREATE TABLE loss_alerts (victim TEXT, lookalike TEXT, mimics TEXT, block INT, li INT, tx TEXT,
                          amount_units INT, detected_at REAL);
CREATE TABLE meta (k TEXT PRIMARY KEY, v TEXT NOT NULL);
"""


def make_intel(path: Path, updated_at=T - 60, losses=()) -> Path:
    con = sqlite3.connect(path)
    con.executescript(SCHEMA)
    for i, (look, mim) in enumerate([(FAKE, REAL)] * 3 + [(VANITY_FAKE, VANITY_REAL)]):
        con.execute("INSERT INTO pairs VALUES (?,?,?,4,4,'zero_value_spoof',?,?,?,?,NULL)",
                    (f"0x{i:040x}", look, mim, 100 + i, f"0x{i:064x}", 200 + i, 1 + i))
    for victim, units in losses:
        con.execute("INSERT INTO loss_alerts VALUES (?,?,?,300,0,'0x01',?,?)", (victim, FAKE, REAL, units, T))
    con.execute("INSERT INTO meta VALUES ('next_block', '1000')")
    if updated_at is not None:
        con.execute("INSERT INTO meta VALUES ('updated_at', ?)", (str(updated_at),))
    con.commit()
    con.close()
    return path


def intel(tmp_path, **kw) -> PoisoningIntel:
    return PoisoningIntel(make_intel(tmp_path / "live.db", **kw), clock=lambda: T)


def test_low_entropy_rule():
    assert low_entropy(VANITY_FAKE) and not low_entropy(FAKE)


def test_lookup_hit_aggregates_all_victims(tmp_path):
    r = intel(tmp_path, losses=[("0x" + "11" * 20, 1_500_000)]).lookup(FAKE.upper().replace("0X", "0x"))
    h = r["hit"]
    assert (h["wallets_poisoned"], h["poison_events"], h["first_block"], h["last_block"]) == (3, 6, 100, 202)
    assert h["mimics"] == [REAL] and h["mimics_count"] == 1 and not h["vanity_only"]
    assert (h["losses_recorded"], h["usdc_lost"]) == (1, "1.5")
    assert r["snapshot"]["intel_age_s"] == 60


def test_findings_by_case(tmp_path):
    i = intel(tmp_path)
    [f] = poisoning_findings(i, FAKE)
    assert (f.code, f.severity.value) == ("KNOWN_POISONING_ADDRESS", "block") and REAL in f.message
    [f] = poisoning_findings(i, VANITY_FAKE)
    assert (f.code, f.severity.value) == ("POSSIBLE_POISONING_ADDRESS", "review")
    [f] = poisoning_findings(i, REAL)                      # the real address is not a threat
    assert (f.code, f.severity.value) == ("POISONING_INTEL_CLEAR", "info")


def test_stale_or_unreadable_intel_is_reported_not_decisive(tmp_path):
    stale = PoisoningIntel(make_intel(tmp_path / "a.db", updated_at=T - 7200), clock=lambda: T)
    codes = [f.code for f in poisoning_findings(stale, FAKE)]
    assert codes == ["POISONING_INTEL_STALE", "KNOWN_POISONING_ADDRESS"]   # stale intel still blocks what it knows
    [f] = poisoning_findings(PoisoningIntel(tmp_path / "missing.db"), FAKE)
    assert (f.code, f.severity.value) == ("POISONING_INTEL_UNAVAILABLE", "info")
    [f] = poisoning_findings(PoisoningIntel(tmp_path / "missing.db"), FAKE, required=True)
    assert f.severity.value == "review"


def test_intel_is_opened_read_only(tmp_path):
    i = intel(tmp_path)
    with pytest.raises(sqlite3.OperationalError):
        i._connect().execute("DELETE FROM pairs")


def wallet_history_request(to: str) -> EvaluationRequest:
    """The agent has no trusted address for the payee and copies one from the wallet's own history."""
    d = base()
    d["intent"]["approved_destinations"] = []
    d["policy"]["vendor_registry"] = []
    d["transaction"]["to"] = to
    d["context"] = [{"id": "hist-1", "source_type": "wallet_history",
                     "content": "Last outgoing USDC transfer", "extracted_address": to}]
    d["action"]["destination_source_id"] = "hist-1"
    return EvaluationRequest.model_validate(d)


def test_intel_turns_unverified_review_into_block(tmp_path):
    req = wallet_history_request(FAKE)
    before = evaluate(req)
    assert before.decision == Decision.REVIEW and "UNVERIFIED_DESTINATION" in before.reason_codes
    after = evaluate(req, extra_findings=poisoning_findings(intel(tmp_path), FAKE))
    assert after.decision == Decision.BLOCK and after.reason_codes[0] == "KNOWN_POISONING_ADDRESS"


def test_clear_intel_does_not_change_decision_or_score():
    d = base()
    req = EvaluationRequest.model_validate(d)
    plain = evaluate(req)
    from agentguard.models import Finding, Severity
    clear = Finding(code="POISONING_INTEL_CLEAR", severity=Severity.INFO, message="", evidence={})
    withc = evaluate(req, extra_findings=[clear])
    assert (withc.decision, withc.risk_score) == (plain.decision, plain.risk_score)


# ---------------------------------------------------------------- through the enforcing service


@pytest.fixture(scope="module")
def config_db(tmp_path_factory):
    db = tmp_path_factory.mktemp("cfg") / "config.db"
    subprocess.run([sys.executable, str(ROOT / "scripts" / "load_excel.py"),
                    str(ROOT / "data" / "agentguard_test_data.xlsx"), str(db)], check=True, capture_output=True)
    return db


def make_service(config_db, tmp_path, intel_db_path, poison_dest: bool):
    state = tmp_path / "state.db"
    store, chain = Store(config_db, state), SimChainSigner(state)
    guard = Guard(Ledger(str(state)), clock=lambda: NOW)
    con = sqlite3.connect(config_db)
    m = load_mandates(con)["MND-101"]
    con.close()
    acme = m.body.destinations[0]
    if poison_dest:   # the registry/mandate address itself shows up as a poisoner
        c = sqlite3.connect(intel_db_path)
        c.execute("INSERT INTO pairs VALUES ('0x' || hex(randomblob(20)), ?, ?, 4, 4, 'zero_value_spoof',"
                  " 1, '0x02', 1, 1, NULL)", (acme.lower(), "0x" + "ab" * 20))
        c.commit()
        c.close()
    client = TestClient(build_app(store, guard, chain, clock=lambda: NOW, observer=chain,
                                  intel=PoisoningIntel(intel_db_path, clock=lambda: T)))
    key = store.issue_agent_key("agent-billing-01", NOW)
    r = client.post("/v2/payments", headers={"X-Agent-Key": key}, json={
        "request_id": "P-1", "mandate": m.model_dump(mode="json"), "payee_name": "Acme Cloud Ltd",
        "purpose": "hosting", "transaction": {"to": acme, "amount": "75", "token": "USDC", "chain": "base"}}).json()
    return r, chain, guard


def test_service_approves_when_intel_is_clear(config_db, tmp_path):
    r, chain, _ = make_service(config_db, tmp_path, make_intel(tmp_path / "live.db"), poison_dest=False)
    assert r["decision"] == "APPROVE" and "POISONING_INTEL_CLEAR" in r["reason_codes"]
    assert len(chain.observed()) == 1


def test_service_blocks_poisoned_trusted_address_and_signs_nothing(config_db, tmp_path):
    r, chain, guard = make_service(config_db, tmp_path, make_intel(tmp_path / "live.db"), poison_dest=True)
    assert r["decision"] == "BLOCK" and r["reason_codes"][0] == "KNOWN_POISONING_ADDRESS"
    assert r["tx_hash"] is None and chain.observed() == [] and guard.ledger.all() == []


def test_analyst_queries_over_the_audit_log(config_db, tmp_path):
    """Two payments through the service, one to a poisoned address: the SQL reports exactly that one."""
    sys.path.insert(0, str(ROOT / "scripts"))
    import intel_queries
    from agentguard.audit import AuditLog
    state = tmp_path / "state.db"
    store, chain = Store(config_db, state), SimChainSigner(state)
    guard = Guard(Ledger(str(state)), audit=AuditLog(state), clock=lambda: NOW)
    con = sqlite3.connect(config_db)
    m = load_mandates(con)["MND-101"]
    con.close()
    client = TestClient(build_app(store, guard, chain, clock=lambda: NOW, observer=chain,
                                  intel=PoisoningIntel(make_intel(tmp_path / "live.db"), clock=lambda: T)))
    key = store.issue_agent_key("agent-billing-01", NOW)
    for rid, to in (("P-ok", m.body.destinations[0]), ("P-bad", FAKE)):
        client.post("/v2/payments", headers={"X-Agent-Key": key}, json={
            "request_id": rid, "mandate": m.model_dump(mode="json"), "payee_name": "Acme Cloud Ltd",
            "purpose": "hosting", "transaction": {"to": to, "amount": "75", "token": "USDC", "chain": "base"}})
    out = intel_queries.run(state)
    [b] = out["intel_blocks"]
    assert (b["request_id"], b["imitates"], b["wallets_poisoned"], b["only_intel"]) == ("P-bad", REAL, 3, 0)
    assert out["intel_value"] == [{"caught_by": "other rules too", "payments": 1, "value": 75.0}]
    assert out["review_queue_intel"] == []
