"""End-to-end: Excel -> SQLite -> engine -> SQL (-> reconcile). Uses the committed datasets."""
import re
import sqlite3
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
XLSX = ROOT / "data" / "agentguard_test_data.xlsx"
CHAIN = ROOT / "data" / "onchain_activity.xlsx"
PHASE3 = ("recon_", "wallet_reconciliation", "match_methods")


def run(script, *args):
    return subprocess.run([sys.executable, str(ROOT / "scripts" / script), *map(str, args)],
                          check=True, capture_output=True, text=True)


def queries():
    sql = (ROOT / "sql" / "analysis.sql").read_text(encoding="utf-8")
    for block in re.split(r"^-- name: ", sql, flags=re.M)[1:]:
        name, body = block.split("\n", 1)
        yield name.strip(), body.strip().rstrip(";")


def test_excel_pipeline(tmp_path):
    db = tmp_path / "pipe.db"
    run("load_excel.py", XLSX, db)
    run("run_batch.py", db)
    con = sqlite3.connect(db)
    total, issues = (con.execute("SELECT COUNT(*) FROM decisions").fetchone()[0],
                     con.execute("SELECT COUNT(*) FROM load_issues").fetchone()[0])
    assert total == 258 and issues == 0
    # Only the known gaps disagree with the labels: Scenario B (not built) and genuine wallet rotations (too strict).
    wrong = {r[0] for r in con.execute(
        "SELECT p.scenario_type FROM payment_requests p JOIN decisions d USING (request_id) "
        "WHERE d.decision <> p.ground_truth")}
    assert wrong == {"purpose_mismatch", "vendor_rotated_wallet"}
    # Every attack row is blocked; ledger total equals approved amount.
    assert con.execute("SELECT COUNT(*) FROM payment_requests p JOIN decisions d USING (request_id) "
                       "WHERE p.ground_truth = 'BLOCK' AND d.decision <> 'BLOCK'").fetchone()[0] == 0
    ledger, approved = con.execute(
        "SELECT (SELECT ROUND(SUM(CAST(amount AS REAL)), 2) FROM ledger), "
        "(SELECT ROUND(SUM(p.amount), 2) FROM payment_requests p JOIN decisions d USING (request_id) "
        "WHERE d.decision = 'APPROVE')").fetchone()
    assert ledger == approved
    # Every Phase 1-2 query runs (Phase 3 queries need the reconcile tables: see below).
    for name, body in queries():
        if not name.startswith(PHASE3):
            con.execute(body).fetchall()
    con.close()


def test_reconcile_pipeline(tmp_path):
    db = tmp_path / "pipe.db"
    run("load_excel.py", XLSX, db)
    run("run_batch.py", db)
    out = run("reconcile_batch.py", CHAIN, db).stdout
    assert "matches labels: 221/221" in out
    con = sqlite3.connect(db)
    # Every outgoing transfer is accounted for: claimed by an approval or reported as unapproved.
    unexplained = con.execute("""
        SELECT COUNT(*) FROM payment_observed o
        WHERE o.status = 'success' AND o.from_address IN (SELECT wallet_address FROM agents)
          AND NOT EXISTS (SELECT 1 FROM recon_items r WHERE instr(r.tx_hashes, o.tx_hash) > 0)""").fetchone()[0]
    assert unexplained == 0
    for _, body in queries():   # with the reconcile tables present, every query in analysis.sql runs
        con.execute(body).fetchall()
    con.close()
