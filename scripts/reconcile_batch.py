"""Reconcile AgentGuard approvals against on-chain activity, and store the results in SQL.

    python scripts/reconcile_batch.py [onchain_activity.xlsx] [database.db]

Reads approvals from the database (decision = APPROVE), the executor's
submissions and the chain export from the workbook, then writes:
  payment_approved, payment_submitted, payment_observed   (the data contract, as tables)
  recon_items                                             (one row per approval or unexplained transfer)
If the workbook has a `labels` sheet, it also prints how many statuses match.
"""
from __future__ import annotations

import json
import sqlite3
import sys
from datetime import datetime, timezone
from decimal import Decimal
from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from agentguard.reconcile import (  # noqa: E402
    PaymentApproved, PaymentObserved, PaymentSubmitted, ReconConfig, reconcile,
)

XLSX = Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "data" / "onchain_activity.xlsx"
DB = Path(sys.argv[2]) if len(sys.argv) > 2 else ROOT / "data" / "agentguard.db"

SCHEMA = """
DROP TABLE IF EXISTS payment_approved;
DROP TABLE IF EXISTS payment_submitted;
DROP TABLE IF EXISTS payment_observed;
DROP TABLE IF EXISTS recon_items;
DROP TABLE IF EXISTS recon_labels;
CREATE TABLE payment_approved (
    request_id TEXT PRIMARY KEY, approved_at TEXT, agent_id TEXT, mandate_id TEXT, from_wallet TEXT,
    to_address TEXT, amount TEXT, token TEXT, chain TEXT, decision_hash TEXT);
CREATE TABLE payment_submitted (request_id TEXT, tx_hash TEXT, submitted_at TEXT, attempt INTEGER);
CREATE TABLE payment_observed (
    chain TEXT, tx_hash TEXT, log_index INTEGER, block_number INTEGER, block_time TEXT, token TEXT,
    from_address TEXT, to_address TEXT, amount TEXT, status TEXT, PRIMARY KEY (chain, tx_hash, log_index));
CREATE TABLE recon_items (
    item_id INTEGER PRIMARY KEY, subject TEXT, request_id TEXT, tx_hashes TEXT, status TEXT, severity TEXT,
    match_method TEXT, explanation TEXT, action TEXT, handling TEXT, evidence TEXT);
CREATE TABLE recon_labels (subject TEXT, ref TEXT, expected_status TEXT, injected_fault TEXT);
"""


def utc(s: str) -> datetime:
    return datetime.strptime(str(s)[:19], "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)


def sheet(name: str) -> list[dict]:
    try:
        df = pd.read_excel(XLSX, sheet_name=name, dtype=str)
    except ValueError:
        return []
    return [{k: (None if (isinstance(v, float) and v != v) else v) for k, v in r.items()} for r in df.to_dict("records")]


def main() -> None:
    con = sqlite3.connect(DB)
    con.row_factory = sqlite3.Row
    con.executescript(SCHEMA)

    rows = con.execute("""
        SELECT p.request_id, p.ts, p.agent_id, p.mandate_id, a.wallet_address, p.to_address, p.amount, p.token,
               p.chain, (SELECT record_hash FROM audit_log l WHERE l.request_id = p.request_id) AS decision_hash
        FROM payment_requests p JOIN decisions d USING (request_id) JOIN agents a USING (agent_id)
        WHERE d.decision = 'APPROVE'""").fetchall()
    approved = [PaymentApproved(request_id=r["request_id"], approved_at=utc(r["ts"]), agent_id=r["agent_id"],
                                mandate_id=r["mandate_id"], from_wallet=r["wallet_address"], to_address=r["to_address"],
                                amount=Decimal(str(r["amount"])).quantize(Decimal("0.01")), token=r["token"],
                                chain=r["chain"], decision_hash=r["decision_hash"]) for r in rows]
    submitted = [PaymentSubmitted(request_id=s["request_id"], tx_hash=s["tx_hash"], submitted_at=utc(s["submitted_at"]),
                                  attempt=int(s["attempt"])) for s in sheet("submissions")]
    observed = [PaymentObserved(chain=t["chain"], tx_hash=t["tx_hash"], log_index=int(t["log_index"]),
                                block_number=int(t["block_number"]), block_time=utc(t["block_time"]), token=t["token"],
                                from_address=t["from_address"], to_address=t["to_address"], amount=Decimal(t["amount"]),
                                status=t["status"]) for t in sheet("transfers")]
    state = sheet("chain_state")
    heads = {s["chain"]: int(s["head_block"]) for s in state}
    as_of = utc(state[0]["as_of"]) if state else datetime.now(timezone.utc)
    wallets = {r["wallet_address"] for r in con.execute("SELECT wallet_address FROM agents") if r["wallet_address"]}

    items = reconcile(approved, observed, submitted, as_of=as_of, heads=heads, agent_wallets=wallets,
                      cfg=ReconConfig())

    con.executemany("INSERT INTO payment_approved VALUES (?,?,?,?,?,?,?,?,?,?)",
                    [(a.request_id, a.approved_at.isoformat(), a.agent_id, a.mandate_id, a.from_wallet, a.to_address,
                      str(a.amount), a.token, a.chain, a.decision_hash) for a in approved])
    con.executemany("INSERT INTO payment_submitted VALUES (?,?,?,?)",
                    [(s.request_id, s.tx_hash, s.submitted_at.isoformat(), s.attempt) for s in submitted])
    con.executemany("INSERT INTO payment_observed VALUES (?,?,?,?,?,?,?,?,?,?)",
                    [(o.chain, o.tx_hash, o.log_index, o.block_number, o.block_time.isoformat(), o.token,
                      o.from_address, o.to_address, str(o.amount), o.status) for o in observed])
    con.executemany("INSERT INTO recon_items (subject, request_id, tx_hashes, status, severity, match_method, "
                    "explanation, action, handling, evidence) VALUES (?,?,?,?,?,?,?,?,?,?)",
                    [(i.subject, i.request_id, ";".join(i.tx_hashes), i.status.value, i.severity, i.match_method,
                      i.explanation, i.action, i.handling, json.dumps(i.evidence, default=str)) for i in items])
    labels = sheet("labels")
    con.executemany("INSERT INTO recon_labels VALUES (?,?,?,?)",
                    [(l["subject"], l["ref"], l["expected_status"], l["injected_fault"]) for l in labels])
    con.commit()

    counts: dict[str, int] = {}
    for i in items:
        counts[i.status.value] = counts.get(i.status.value, 0) + 1
    print(f"reconciled {len(approved)} approvals against {len(observed)} transfers (as of {as_of:%Y-%m-%d %H:%M} UTC)")
    print("  " + ", ".join(f"{k} {v}" for k, v in sorted(counts.items())))
    if labels:
        got = {(i.subject, i.request_id if i.subject == "approval" else i.tx_hashes[0]): i.status.value for i in items}
        wrong = [(l["ref"], l["expected_status"], got.get((l["subject"], l["ref"]), "(none)")) for l in labels
                 if got.get((l["subject"], l["ref"])) != l["expected_status"]]
        extra = len(items) - len(labels)
        print(f"  matches labels: {len(labels) - len(wrong)}/{len(labels)}; items without a label: {extra}")
        for ref, exp, act in wrong[:15]:
            print(f"    {ref[:14]}  expected {exp:<20} got {act}")
    con.close()


if __name__ == "__main__":
    main()
