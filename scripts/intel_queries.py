"""Run the analyst queries in sql/poisoning_intel.sql against a service state database.

    python scripts/intel_queries.py [data/service.db]
"""
from __future__ import annotations

import re
import sqlite3
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SQL = ROOT / "sql" / "poisoning_intel.sql"


def queries() -> list[tuple[str, str]]:
    blocks = re.split(r"^-- name: ", SQL.read_text(encoding="utf-8"), flags=re.M)[1:]
    return [(b.split("\n", 1)[0].strip(), b.split("\n", 1)[1]) for b in blocks]


def run(db: Path) -> dict[str, list[dict]]:
    con = sqlite3.connect(f"{db.resolve().as_uri()}?mode=ro", uri=True)
    con.row_factory = sqlite3.Row
    try:
        return {name: [dict(r) for r in con.execute(sql)] for name, sql in queries()}
    finally:
        con.close()


def main() -> None:
    db = Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "data" / "service.db"
    for name, rows in run(db).items():
        print(f"\n== {name} ({len(rows)} rows)")
        if rows:
            cols = list(rows[0])
            print(" | ".join(cols))
            for r in rows:
                print(" | ".join("" if r[c] is None else str(r[c]) for c in cols))


if __name__ == "__main__":
    main()
