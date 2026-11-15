"""EIP-7702 delegation check: designator parsing, and the service refusing to sign around delegated wallets."""
import sqlite3
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from agentguard.delegation import delegate_of, delegation_findings
from agentguard.guard import Guard
from agentguard.ledger import Ledger
from agentguard.service import build_app
from agentguard.signer import SimChainSigner
from agentguard.store import Store, load_mandates

ROOT = Path(__file__).resolve().parents[1]
NOW = datetime(2026, 11, 14, 12, 0, tzinfo=timezone.utc)
DELEGATE = "0x" + "77" * 20
SWEEPER = "0xef0100" + "77" * 20          # what eth_getCode returns for a delegated EOA


class FakeChain:
    def __init__(self, codes=None, fail=False):
        self.codes, self.fail = {k.lower(): v for k, v in (codes or {}).items()}, fail

    def code(self, address):
        if self.fail:
            raise RuntimeError("rpc down")
        return self.codes.get(address.lower(), "0x")


def test_designator_parsing():
    assert delegate_of(SWEEPER) == DELEGATE
    assert delegate_of(SWEEPER.upper().replace("0X", "0x")) == DELEGATE
    assert delegate_of("0x") is None
    assert delegate_of("0x6080604052") is None                 # an ordinary contract
    assert delegate_of("0xef0100" + "77" * 19) is None          # wrong length


def test_findings_by_case():
    w, to = "0x" + "aa" * 20, "0x" + "bb" * 20
    assert delegation_findings(FakeChain(), w, to) == []
    [f] = delegation_findings(FakeChain({w: SWEEPER}), w, to)
    assert (f.code, f.severity.value) == ("SOURCE_WALLET_DELEGATED", "block")
    [f] = delegation_findings(FakeChain({to: SWEEPER}), w, to)
    assert (f.code, f.severity.value) == ("DESTINATION_7702_DELEGATED", "review")
    [f] = delegation_findings(FakeChain({to: SWEEPER}), w, to, trusted_delegates=[DELEGATE.upper().replace("0X", "0x")])
    assert (f.code, f.severity.value) == ("DESTINATION_DELEGATE_TRUSTED", "info")
    [f] = delegation_findings(FakeChain({to: "0x6080"}), w, to) or [None]
    assert f is None                                             # plain contracts are not this check's business
    [f] = delegation_findings(FakeChain(fail=True), w, to)
    assert (f.code, f.severity.value) == ("CHAIN_CHECK_FAILED", "review")


@pytest.fixture(scope="module")
def config_db(tmp_path_factory):
    db = tmp_path_factory.mktemp("cfg") / "config.db"
    subprocess.run([sys.executable, str(ROOT / "scripts" / "load_excel.py"),
                    str(ROOT / "data" / "agentguard_test_data.xlsx"), str(db)], check=True, capture_output=True)
    return db


def make(config_db, tmp_path, reader):
    tmp_path.mkdir(parents=True, exist_ok=True)
    state = tmp_path / "state.db"
    store, chain = Store(config_db, state), SimChainSigner(state)
    guard = Guard(Ledger(str(state)), clock=lambda: NOW)
    client = TestClient(build_app(store, guard, chain, clock=lambda: NOW, observer=chain, code_reader=reader))
    con = sqlite3.connect(config_db)
    m = load_mandates(con)["MND-101"]
    con.close()
    key = store.issue_agent_key("agent-billing-01", NOW)

    def pay(rid="P-1"):
        return client.post("/v2/payments", headers={"X-Agent-Key": key}, json={
            "request_id": rid, "mandate": m.model_dump(mode="json"), "payee_name": "Acme Cloud Ltd",
            "purpose": "hosting", "transaction": {"to": m.body.destinations[0], "amount": "75", "token": "USDC",
                                                  "chain": "base"}}).json()
    return store, chain, guard, m.body.destinations[0], pay


def test_clean_chain_still_approves(config_db, tmp_path):
    _, chain, _, _, pay = make(config_db, tmp_path, FakeChain())
    r = pay()
    assert r["decision"] == "APPROVE" and len(chain.observed()) == 1


def test_delegated_source_wallet_blocks_and_nothing_is_signed_or_reserved(config_db, tmp_path):
    store, chain, guard, _, _ = make(config_db, tmp_path, None)
    wallet = store.wallets["agent-billing-01"]
    store2, chain, guard, _, pay = make(config_db, tmp_path / "b", FakeChain({wallet: SWEEPER}))
    r = pay()
    assert r["decision"] == "BLOCK" and "SOURCE_WALLET_DELEGATED" in r["reason_codes"]
    assert r["tx_hash"] is None and chain.observed() == [] and guard.ledger.all() == []


def test_delegated_destination_goes_to_review(config_db, tmp_path):
    _, _, _, acme, _ = make(config_db, tmp_path, None)
    _, chain, _, _, pay = make(config_db, tmp_path / "b", FakeChain({acme: SWEEPER}))
    r = pay()
    assert r["decision"] == "REVIEW" and r["reason_codes"][0] == "DESTINATION_7702_DELEGATED"
    assert chain.observed() == []


def test_unreadable_chain_fails_closed(config_db, tmp_path):
    _, chain, _, _, pay = make(config_db, tmp_path, FakeChain(fail=True))
    r = pay()
    assert r["decision"] == "REVIEW" and "CHAIN_CHECK_FAILED" in r["reason_codes"] and chain.observed() == []
