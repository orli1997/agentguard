"""The engine's own record of payments it let through.

Behavioral checks (cumulative budget, splitting, velocity) need history. That
history must come from here, never from the request: an agent that supplies
its own history can simply leave payments out.

Check-and-reserve is atomic. Guard.evaluate() holds a write lock across
"read history -> decide -> record", so two parallel requests cannot both spend
the last of a budget (a classic race used to bypass limits).
"""
from __future__ import annotations

import sqlite3
import threading
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime
from decimal import Decimal
from typing import Iterator

from . import address as addr

_SCHEMA = """
CREATE TABLE IF NOT EXISTS ledger (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ts          REAL NOT NULL,          -- unix seconds, engine clock
    request_id  TEXT NOT NULL,
    agent_id    TEXT NOT NULL,
    mandate_id  TEXT,
    dest        TEXT NOT NULL,          -- normalized address
    amount      TEXT NOT NULL,          -- Decimal as text: no float rounding on money
    token       TEXT NOT NULL,
    chain       TEXT NOT NULL,
    status      TEXT NOT NULL           -- approved | manual_approved
);
CREATE INDEX IF NOT EXISTS ix_agent_ts ON ledger(agent_id, ts);
CREATE INDEX IF NOT EXISTS ix_mandate ON ledger(mandate_id);
"""


@dataclass(frozen=True)
class PastTx:
    ts: float
    dest: str
    amount: Decimal
    mandate_id: str | None


class HistoryView:
    """Read/write access valid only inside Ledger.locked()."""

    def __init__(self, conn: sqlite3.Connection):
        self._c = conn

    def mandate_usage(self, mandate_id: str) -> tuple[Decimal, int]:
        rows = self._c.execute("SELECT amount FROM ledger WHERE mandate_id = ?", (mandate_id,)).fetchall()
        return sum((Decimal(r[0]) for r in rows), Decimal(0)), len(rows)

    def agent_since(self, agent_id: str, since_ts: float) -> list[PastTx]:
        rows = self._c.execute(
            "SELECT ts, dest, amount, mandate_id FROM ledger WHERE agent_id = ? AND ts >= ? ORDER BY ts",
            (agent_id, since_ts)).fetchall()
        return [PastTx(r[0], r[1], Decimal(r[2]), r[3]) for r in rows]

    def record(self, *, ts: float, request_id: str, agent_id: str, mandate_id: str | None,
               dest: str, amount: Decimal, token: str, chain: str, status: str = "approved") -> None:
        self._c.execute(
            "INSERT INTO ledger (ts, request_id, agent_id, mandate_id, dest, amount, token, chain, status) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (ts, request_id, agent_id, mandate_id, addr.normalize(dest), str(amount), token.upper(),
             chain.lower(), status))


class Ledger:
    def __init__(self, path: str = ":memory:"):
        self.path = path
        # One connection per Ledger object; the lock makes it safe across threads
        # in-process, BEGIN IMMEDIATE makes it safe across processes sharing a file.
        self._conn = sqlite3.connect(path, isolation_level=None, check_same_thread=False, timeout=30)
        self._lock = threading.Lock()
        self._conn.executescript(_SCHEMA)

    @contextmanager
    def locked(self) -> Iterator[HistoryView]:
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                yield HistoryView(self._conn)
                self._conn.execute("COMMIT")
            except BaseException:
                self._conn.execute("ROLLBACK")
                raise

    def seed(self, rows: list[dict]) -> None:
        """Load prior payments (fixtures, or migration from an existing system)."""
        with self.locked() as h:
            for r in rows:
                h.record(**r)

    def all(self) -> list[dict]:
        cur = self._conn.execute("SELECT * FROM ledger ORDER BY ts DESC")
        cols = [d[0] for d in cur.description]
        return [dict(zip(cols, r)) for r in cur.fetchall()]

    def close(self) -> None:
        self._conn.close()


def ts(dt: datetime) -> float:
    return dt.timestamp()
