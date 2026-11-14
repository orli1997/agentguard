"""Replay every payment request in data/agentguard.db through the Guard, in time order.

    python scripts/run_batch.py [database.db]

The engine clock is set to each request's timestamp, and approved payments go
into the ledger table, so budgets, splitting and velocity behave exactly as
they would have live. Results land in tables `decisions` and `decision_findings`.
"""
from __future__ import annotations

import json
import sqlite3
import sys
from datetime import datetime, timezone
from decimal import Decimal
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from agentguard.audit import AuditLog  # noqa: E402
from agentguard.guard import Guard  # noqa: E402
from agentguard.ledger import Ledger  # noqa: E402
from agentguard.mandate import SignedMandate  # noqa: E402
from agentguard.store import load_mandates, load_policies  # noqa: E402
from agentguard.models import (  # noqa: E402
    AgentAction, AuthorizationPolicy, ContextItem, EvaluationRequest, PrincipalKey, TransactionRequest,
    VendorRecord,
)

DB = Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "data" / "agentguard.db"

OUTPUT_SCHEMA = """
DROP TABLE IF EXISTS decisions;
DROP TABLE IF EXISTS decision_findings;
DROP TABLE IF EXISTS ledger;
DROP TABLE IF EXISTS audit_log;
CREATE TABLE decisions (
    request_id      TEXT PRIMARY KEY REFERENCES payment_requests(request_id),
    decision        TEXT NOT NULL,
    risk_score      INTEGER NOT NULL,
    primary_reason  TEXT,             -- most severe finding (first after sorting)
    reason_codes    TEXT NOT NULL,    -- semicolon-separated, worst first
    latency_ms      REAL NOT NULL,
    engine_version  TEXT NOT NULL
);
CREATE TABLE decision_findings (
    request_id  TEXT NOT NULL REFERENCES payment_requests(request_id),
    seq         INTEGER NOT NULL,
    code        TEXT NOT NULL,
    severity    TEXT NOT NULL,       -- block | review | info
    message     TEXT NOT NULL,
    evidence    TEXT,                -- JSON
    PRIMARY KEY (request_id, seq)
);
"""


def rows(con, sql, *args):
    con.row_factory = sqlite3.Row
    return [dict(r) for r in con.execute(sql, args)]


def build_policies(con) -> dict[str, AuthorizationPolicy]:
    return load_policies(con)


def build_mandates(con) -> dict[str, SignedMandate]:
    return load_mandates(con)


def main() -> None:
    con = sqlite3.connect(DB)
    con.executescript(OUTPUT_SCHEMA)
    policies, mandates = build_policies(con), build_mandates(con)
    requests = rows(con, "SELECT * FROM payment_requests ORDER BY ts, request_id")

    clock = {"now": None}
    guard = Guard(Ledger(str(DB)), audit=AuditLog(DB), clock=lambda: clock["now"])
    counts: dict[str, int] = {}
    for r in requests:
        clock["now"] = datetime.strptime(r["ts"], "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
        policy = policies.get(r["agent_id"])
        req = EvaluationRequest(
            request_id=r["request_id"],
            mandate=mandates.get(r["mandate_id"]) if r["mandate_id"] else None,
            # Unknown agent: give it an empty policy so the engine blocks it instead of the script crashing.
            policy=policy or AuthorizationPolicy(agent_id="__none__", max_amount_per_tx=Decimal("0.000001"),
                                                 allowed_tokens=[], allowed_chains=[], require_signed_mandate=True),
            action=AgentAction(agent_id=r["agent_id"], stated_purpose=r["scenario_type"] or "",
                               payee_name=r["payee_name"], destination_source_id="ctx-1"),
            transaction=TransactionRequest(to=r["to_address"], amount=Decimal(str(r["amount"])),
                                           token=r["token"], chain=r["chain"]),
            context=[ContextItem(id="ctx-1", source_type=r["context_source"], content=r["context_text"] or "",
                                 extracted_address=r["to_address"])],
        )
        res = guard.check(req)
        counts[res.decision.value] = counts.get(res.decision.value, 0) + 1
        con.execute("INSERT INTO decisions VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (res.request_id, res.decision.value, res.risk_score,
                     res.findings[0].code if res.findings else None, ";".join(res.reason_codes),
                     res.latency_ms, res.engine_version))
        con.executemany("INSERT INTO decision_findings VALUES (?, ?, ?, ?, ?, ?)",
                        [(res.request_id, i, f.code, f.severity.value, f.message, json.dumps(f.evidence, default=str))
                         for i, f in enumerate(res.findings)])
        con.commit()  # release the write lock: the ledger and audit log write through their own connections
    guard.ledger.close()

    agree = con.execute("SELECT SUM(d.decision = p.ground_truth), COUNT(*) FROM decisions d "
                        "JOIN payment_requests p USING (request_id)").fetchone()
    print(f"evaluated {len(requests)} requests -> {DB.name}")
    print("  " + "  ".join(f"{k}: {v}" for k, v in sorted(counts.items())))
    print(f"  agrees with ground_truth: {agree[0]}/{agree[1]}")
    print("  next: python scripts/report.py   (or open the .db in a SQL tool and run sql/analysis.sql)")
    con.close()


if __name__ == "__main__":
    main()
