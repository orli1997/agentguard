"""Simulate the execution side for the approved payments in data/agentguard.db.

    python scripts/simulate_chain.py   -> data/onchain_activity.xlsx

Produces what Reconcile would really receive:
  transfers     an explorer-style export of USDC Transfer events (plus one reverted receipt)
  submissions   the executor's log: which tx_hash it broadcast for which request_id
  chain_state   head block per chain at the reconciliation cut-off
  labels        the expected reconciliation status for every approval and injected transfer

Most approvals settle cleanly. A fixed, seeded set gets realistic faults. Labels
are written from the injected fault, not from the reconciler's output.
"""
from __future__ import annotations

import hashlib
import random
import sqlite3
import sys
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from pathlib import Path

from openpyxl import Workbook
from openpyxl.styles import Font, PatternFill

ROOT = Path(__file__).resolve().parents[1]
DB = ROOT / "data" / "agentguard.db"
OUT = ROOT / "data" / "onchain_activity.xlsx"
rng = random.Random(20261020)

T0 = datetime(2026, 10, 1, tzinfo=timezone.utc)
B0 = 50_000_000                      # block at T0 (fixture)
AS_OF = datetime(2026, 11, 1, tzinfo=timezone.utc)
TREASURY = "0x" + hashlib.sha256(b"org-treasury").hexdigest()[:40]
THIEF = "0x" + hashlib.sha256(b"post-approval-thief").hexdigest()[:40]
DRAIN = ["0x" + hashlib.sha256(f"drain-{i}".encode()).hexdigest()[:40] for i in range(3)]


def block_at(t: datetime) -> int:
    return B0 + int((t - T0).total_seconds() // 2)       # Base: ~2 s blocks


def txh(*parts) -> str:
    return "0x" + hashlib.sha256(":".join(map(str, parts)).encode()).hexdigest()


def main() -> None:
    con = sqlite3.connect(DB)
    con.row_factory = sqlite3.Row
    approvals = [dict(r) for r in con.execute("""
        SELECT p.request_id, p.ts, p.agent_id, p.to_address, p.amount, p.token, p.chain, a.wallet_address
        FROM payment_requests p JOIN decisions d USING (request_id) JOIN agents a USING (agent_id)
        WHERE d.decision = 'APPROVE' ORDER BY p.ts, p.request_id""")]
    con.close()
    for a in approvals:
        a["approved_at"] = datetime.strptime(a["ts"], "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
        a["amount"] = Decimal(str(a["amount"])).quantize(Decimal("0.01"))

    # Pick which approvals get which fault. The last approval is kept for the "pending" case.
    pending_one = approvals[-1]
    # Most traffic is cent-sized API calls; draw the money-relevant faults from larger payments first
    # so they are visible in a demo, then the rest from the micro-payments.
    larger = [a for a in approvals[:-1] if a["amount"] >= 1]
    micro = [a for a in approvals[:-1] if a["amount"] < 1]
    rng.shuffle(larger)
    rng.shuffle(micro)
    pool = larger + micro
    plan: dict[str, str] = {}
    for fault, n in [("amount_x10", 1), ("amount_fee", 1), ("dest_swap", 1), ("duplicate_linked", 2),
                     ("missing_unlinked", 1), ("duplicate_unlinked", 1), ("dest_swap", 1),
                     ("duplicate_linked", 1), ("missing_linked", 2), ("missing_unlinked", 1), ("reverted", 1)]:
        for _ in range(n):
            plan[pool.pop(0)["request_id"]] = fault
    pool = [a for a in approvals[:-1] if a["request_id"] not in plan]
    plan[pending_one["request_id"]] = "pending"
    no_hash = {a["request_id"] for a in pool if rng.random() < 0.15}   # executor forgot to report the hash

    transfers, submissions, labels = [], [], []

    def emit(a, to, amount, when, attempt=1, status="success", report=True):
        h = txh(a["request_id"], attempt)
        if report:
            submissions.append(dict(request_id=a["request_id"], tx_hash=h, submitted_at=when - timedelta(seconds=3),
                                    attempt=attempt))
        transfers.append(dict(chain=a["chain"], tx_hash=h, log_index=0, block_number=block_at(when), block_time=when,
                              token=a["token"], from_address=a["wallet_address"], to_address=to,
                              amount=amount, status=status))

    for a in approvals:
        rid, f = a["request_id"], plan.get(a["request_id"], "clean")
        when = a["approved_at"] + timedelta(seconds=rng.randint(4, 40))
        expected = "CONFIRMED"
        if f == "clean":
            emit(a, a["to_address"], a["amount"], when, report=rid not in no_hash)
        elif f == "duplicate_linked":       # retry after a timeout although the first tx had settled
            emit(a, a["to_address"], a["amount"], when)
            emit(a, a["to_address"], a["amount"], when + timedelta(seconds=rng.randint(60, 300)), attempt=2)
            expected = "DUPLICATE"
        elif f == "duplicate_unlinked":
            emit(a, a["to_address"], a["amount"], when, report=False)
            emit(a, a["to_address"], a["amount"], when + timedelta(minutes=3), attempt=2, report=False)
            expected = "DUPLICATE"
        elif f == "amount_x10":             # decimals bug: 6 vs 7 decimals
            emit(a, a["to_address"], a["amount"] * 10, when)
            expected = "AMOUNT_MISMATCH"
        elif f == "amount_fee":             # executor deducted a fee from the payment
            emit(a, a["to_address"], a["amount"] - Decimal("0.30") if a["amount"] > 1 else a["amount"] / 2, when)
            expected = "AMOUNT_MISMATCH"
        elif f == "dest_swap":              # transaction altered after approval
            emit(a, THIEF, a["amount"], when)
            expected = "DESTINATION_MISMATCH"
        elif f == "missing_linked":         # broadcast but dropped from the mempool: hash reported, never mined
            submissions.append(dict(request_id=rid, tx_hash=txh(rid, 1), submitted_at=when, attempt=1))
            expected = "MISSING"
        elif f == "missing_unlinked":       # executor never ran
            expected = "MISSING"
        elif f == "reverted":
            emit(a, a["to_address"], a["amount"], when, status="reverted")
            expected = "FAILED"
        elif f == "pending":                # stuck with low gas, mined seconds before the cut-off
            emit(a, a["to_address"], a["amount"], AS_OF - timedelta(seconds=10))
            expected = "PENDING"
        labels.append(dict(subject="approval", ref=rid, expected_status=expected, injected_fault=f))

    # Outflows that never went through AgentGuard.
    wallets = sorted({a["wallet_address"] for a in approvals})
    for i, dest in enumerate(DRAIN):
        w = wallets[i % len(wallets)]
        when = T0 + timedelta(days=rng.randint(3, 28), hours=rng.randint(0, 23), minutes=rng.randint(0, 59))
        h = txh("drain", i)
        amt = Decimal(rng.choice([180, 240, 95])) + Decimal(i) / 10
        transfers.append(dict(chain="base", tx_hash=h, log_index=0, block_number=block_at(when), block_time=when,
                              token="USDC", from_address=w, to_address=dest, amount=amt, status="success"))
        labels.append(dict(subject="transfer", ref=h, expected_status="UNAPPROVED_OUTFLOW", injected_fault="bypass"))
    # Treasury top-ups INTO agent wallets: inbound, must be ignored.
    for i, w in enumerate(wallets):
        when = T0 + timedelta(hours=1 + i)
        transfers.append(dict(chain="base", tx_hash=txh("topup", i), log_index=0, block_number=block_at(when),
                              block_time=when, token="USDC", from_address=TREASURY, to_address=w,
                              amount=Decimal(1000), status="success"))

    transfers.sort(key=lambda t: (t["block_number"], t["tx_hash"]))
    wb = Workbook()
    wb.remove(wb.active)
    sheets = {
        "transfers": (transfers, ["chain", "tx_hash", "log_index", "block_number", "block_time", "token",
                                  "from_address", "to_address", "amount", "status"]),
        "submissions": (submissions, ["request_id", "tx_hash", "submitted_at", "attempt"]),
        "chain_state": ([dict(chain="base", head_block=block_at(AS_OF), as_of=AS_OF)], ["chain", "head_block", "as_of"]),
        "labels": (labels, ["subject", "ref", "expected_status", "injected_fault"]),
    }
    for name, (rows, cols) in sheets.items():
        ws = wb.create_sheet(name)
        ws.append(cols)
        for r in rows:
            ws.append([r[c].strftime("%Y-%m-%d %H:%M:%S") if isinstance(r[c], datetime)
                       else str(r[c]) if isinstance(r[c], Decimal) else r[c] for c in cols])
        for c in ws[1]:
            c.font, c.fill = Font(name="Arial", bold=True, color="FFFFFF"), PatternFill("solid", fgColor="1F3864")
        for col, w in zip("ABCDEFGHIJ", [8, 68, 10, 14, 20, 8, 44, 44, 12, 10]):
            ws.column_dimensions[col].width = w
        ws.freeze_panes = "A2"
    wb.save(OUT)
    faults = {}
    for l in labels:
        faults[l["expected_status"]] = faults.get(l["expected_status"], 0) + 1
    print(f"wrote {OUT}: {len(transfers)} transfers, {len(submissions)} submissions, "
          f"{len(no_hash)} approvals without a reported tx hash")
    print("  expected: " + ", ".join(f"{k} {v}" for k, v in sorted(faults.items())))


if __name__ == "__main__":
    main()
