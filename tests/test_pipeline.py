"""End-to-end: Excel -> SQLite -> engine -> SQL. Uses the committed dataset."""
import sqlite3
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
XLSX = ROOT / "data" / "agentguard_test_data.xlsx"


def test_excel_pipeline(tmp_path):
    db = tmp_path / "pipe.db"
    for script, args in (("load_excel.py", [str(XLSX), str(db)]), ("run_batch.py", [str(db)])):
        subprocess.run([sys.executable, str(ROOT / "scripts" / script), *args], check=True, capture_output=True)
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
    # Every analysis query runs.
    import re
    sql = (ROOT / "sql" / "analysis.sql").read_text(encoding="utf-8")
    for block in re.split(r"^-- name: ", sql, flags=re.M)[1:]:
        con.execute(block.split("\n", 1)[1].strip().rstrip(";")).fetchall()
    con.close()
