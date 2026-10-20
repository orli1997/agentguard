"""Explain one payment end to end and write its evidence bundle.

    python scripts/explain.py REQ-00042            -> prints the story, writes reports/evidence/REQ-00042.json
    python scripts/explain.py --exceptions          -> one bundle per open reconciliation exception

The bundle links: the request the agent made -> the mandate -> the engine's
decision and every finding -> the audit-log record (and whether the hash chain
is intact) -> what was submitted and observed on-chain -> the reconciliation verdict.
"""
from __future__ import annotations

import json
import sqlite3
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from agentguard.audit import AuditLog  # noqa: E402

DB = ROOT / "data" / "agentguard.db"
OUT = ROOT / "reports" / "evidence"


def q(con, sql, *args):
    return [dict(r) for r in con.execute(sql, args)]


def bundle(con, request_id: str, chain_ok: tuple) -> dict:
    req = q(con, "SELECT * FROM payment_requests WHERE request_id = ?", request_id)
    if not req:
        raise SystemExit(f"unknown request_id {request_id}")
    req = req[0]
    mandate = q(con, "SELECT mandate_id, principal, agent_id, payee_name, destinations, max_amount_per_tx, max_total, "
                     "max_tx_count, valid_from, expires_at, purpose, key_id FROM mandates WHERE mandate_id = ?",
                req["mandate_id"])
    audit = q(con, "SELECT seq, ts_utc, decision, record_hash, prev_hash FROM audit_log WHERE request_id = ?", request_id)
    recon = q(con, "SELECT status, severity, match_method, explanation, action, handling, tx_hashes, evidence "
                   "FROM recon_items WHERE request_id = ?", request_id)
    for r in recon:
        r["evidence"] = json.loads(r["evidence"])
    return {
        "request": req,
        "mandate": mandate[0] if mandate else None,
        "decision": q(con, "SELECT decision, risk_score, primary_reason, engine_version FROM decisions "
                           "WHERE request_id = ?", request_id)[0],
        "findings": q(con, "SELECT severity, code, message, evidence FROM decision_findings WHERE request_id = ? "
                           "ORDER BY seq", request_id),
        "audit_record": audit[0] if audit else None,
        "audit_chain_intact": chain_ok[0],
        "submitted": q(con, "SELECT tx_hash, submitted_at, attempt FROM payment_submitted WHERE request_id = ?",
                       request_id),
        "reconciliation": recon[0] if recon else None,
    }


def story(b: dict) -> str:
    r, d, rc = b["request"], b["decision"], b["reconciliation"]
    lines = [f"{r['request_id']}  {r['ts']} UTC  {r['agent_id']} -> {r['payee_name']}  {r['amount']} {r['token']} "
             f"on {r['chain']}",
             f"  mandate     {r['mandate_id'] or '(none)'}",
             f"  decision    {d['decision']} (risk {d['risk_score']}), main reason {d['primary_reason']}"]
    for f in b["findings"]:
        if f["severity"] != "info":
            lines.append(f"                - [{f['severity']}] {f['code']}: {f['message']}")
    if b["audit_record"]:
        a = b["audit_record"]
        lines.append(f"  audit       record #{a['seq']} hash {a['record_hash'][:16]}…  chain intact: "
                     f"{'yes' if b['audit_chain_intact'] else 'NO'}")
    if rc:
        lines += [f"  on-chain    {rc['status']} ({rc['severity']}, {rc['handling']}), matched by {rc['match_method']}",
                  f"              {rc['explanation']}",
                  f"  action      {rc['action']}"]
    elif d["decision"] == "APPROVE":
        lines.append("  on-chain    not reconciled yet (run scripts/reconcile_batch.py)")
    else:
        lines.append("  on-chain    nothing expected: the payment was not approved")
    return "\n".join(lines)


def main() -> None:
    con = sqlite3.connect(DB)
    con.row_factory = sqlite3.Row
    chain_ok = AuditLog(DB).verify_chain()
    if len(sys.argv) > 1 and sys.argv[1] == "--exceptions":
        ids = [r["request_id"] for r in con.execute(
            "SELECT request_id FROM recon_items WHERE handling = 'OPEN' AND request_id IS NOT NULL ORDER BY request_id")]
        orphans = q(con, "SELECT tx_hashes, explanation, action FROM recon_items WHERE request_id IS NULL")
    else:
        ids, orphans = sys.argv[1:] or ["REQ-00001"], []
    OUT.mkdir(parents=True, exist_ok=True)
    for rid in ids:
        b = bundle(con, rid, chain_ok)
        (OUT / f"{rid}.json").write_text(json.dumps(b, indent=2, default=str), encoding="utf-8")
        print(story(b), end="\n\n")
    for o in orphans:
        print(f"UNAPPROVED  {o['tx_hashes'][:18]}…\n  {o['explanation']}\n  action  {o['action']}\n")
    print(f"evidence bundles: {OUT}")


if __name__ == "__main__":
    main()
