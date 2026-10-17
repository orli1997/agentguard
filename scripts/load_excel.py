"""Load the Excel test dataset into SQLite, with data-quality checks.

    python scripts/load_excel.py [workbook.xlsx] [database.db]

Defaults: data/agentguard_test_data.xlsx -> data/agentguard.db
Rows that fail validation are skipped and listed in the load_issues table.
"""
from __future__ import annotations

import sqlite3
import sys
from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from agentguard.address import is_valid_evm  # noqa: E402

XLSX = Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "data" / "agentguard_test_data.xlsx"
DB = Path(sys.argv[2]) if len(sys.argv) > 2 else ROOT / "data" / "agentguard.db"
SHEETS = ["principal_keys", "agents", "vendors", "denylist", "mandates", "payment_requests"]


def _clean(v):
    if v is None or (isinstance(v, float) and v != v):   # NaN
        return None
    v = str(v).strip()
    return v or None


def read(sheet: str) -> list[dict]:
    # dtype=str: keep values exactly as typed (signed mandate fields must not become 400.0).
    # Rows are plain dicts: pandas 3 turns None back into NaN inside a DataFrame.
    df = pd.read_excel(XLSX, sheet_name=sheet, dtype=str)
    rows = [{str(k).strip(): _clean(v) for k, v in r.items()} for r in df.to_dict("records")]
    return [r for r in rows if any(v is not None for v in r.values())]


def main() -> None:
    issues: list[tuple[str, str, str]] = []
    frames = {s: read(s) for s in SHEETS}

    req = frames["payment_requests"]
    mandate_ids = {m["mandate_id"] for m in frames["mandates"]}
    agent_ids = {a["agent_id"] for a in frames["agents"]}
    keep = []
    seen = set()
    for i, r in enumerate(req):
        ref = f"row {i + 2} ({r.get('request_id')})"
        problems = []
        if not r["request_id"]:
            problems.append("missing request_id")
        elif r["request_id"] in seen:
            problems.append("duplicate request_id")
        seen.add(r["request_id"])
        if r["agent_id"] not in agent_ids:
            problems.append(f"unknown agent_id {r['agent_id']}")
        if r["mandate_id"] and r["mandate_id"] not in mandate_ids:
            problems.append(f"unknown mandate_id {r['mandate_id']}")
        try:
            if float(r["amount"]) <= 0:
                problems.append("amount must be > 0")
        except (TypeError, ValueError):
            problems.append(f"amount not a number: {r['amount']!r}")
        try:
            pd.Timestamp(r["ts"])
        except (TypeError, ValueError):
            problems.append(f"bad timestamp {r['ts']!r}")
        if r["ground_truth"] not in ("APPROVE", "REVIEW", "BLOCK"):
            problems.append(f"ground_truth must be APPROVE/REVIEW/BLOCK, got {r['ground_truth']!r}")
        # A malformed address is NOT a load error: it is a legitimate test input the engine must block.
        if r["to_address"] and not is_valid_evm(r["to_address"]):
            issues.append(("payment_requests", ref, "warning: to_address is not a valid EVM address (kept)"))
        if problems:
            issues.extend(("payment_requests", ref, p) for p in problems)
        else:
            keep.append(r)
    frames["payment_requests"] = keep

    for a in frames["agents"]:
        a["require_signed_mandate"] = int(str(a["require_signed_mandate"]).lower() in ("true", "1", "yes"))

    DB.parent.mkdir(exist_ok=True)
    con = sqlite3.connect(DB)
    con.executescript((ROOT / "sql" / "schema.sql").read_text(encoding="utf-8"))
    for name, data in frames.items():
        if not data:
            continue
        cols = list(data[0].keys())
        con.executemany(f"INSERT INTO {name} ({', '.join(cols)}) VALUES ({', '.join('?' * len(cols))})",
                        [tuple(r[c] for c in cols) for r in data])
    con.executemany("INSERT INTO load_issues VALUES (?, ?, ?)", issues)
    con.commit()

    print(f"loaded {XLSX.name} -> {DB}")
    for name in SHEETS:
        n = con.execute(f"SELECT COUNT(*) FROM {name}").fetchone()[0]
        print(f"  {name:<17} {n:5d} rows")
    errors = [x for x in issues if not x[2].startswith("warning")]
    print(f"  load_issues       {len(issues):5d}  ({len(errors)} rows skipped)")
    for s, ref, msg in issues[:20]:
        print(f"    {s} {ref}: {msg}")
    con.close()


if __name__ == "__main__":
    main()
