"""Signers: the only component that can move money.

The service calls a signer *only* after the Guard returned APPROVE. The agent
never sees a signing key, so it has no path to the chain that skips the check.

  SimChainSigner   a local, deterministic stand-in for a chain (SQLite). Used by
                   tests and the demo, and by Reconcile as its "observed" source.
  (EvmSigner)      Phase B: real transfers on Base Sepolia. Not in this file yet.
"""
from __future__ import annotations

import hashlib
import sqlite3
import threading
from datetime import datetime
from decimal import Decimal
from pathlib import Path
from typing import Protocol

from .reconcile import PaymentObserved

_SCHEMA = """
CREATE TABLE IF NOT EXISTS sim_chain (
    seq          INTEGER PRIMARY KEY AUTOINCREMENT,
    chain        TEXT NOT NULL,
    tx_hash      TEXT NOT NULL UNIQUE,
    block_number INTEGER NOT NULL,
    block_time   TEXT NOT NULL,
    token        TEXT NOT NULL,
    from_address TEXT NOT NULL,
    to_address   TEXT NOT NULL,
    amount       TEXT NOT NULL,
    status       TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS sim_head (chain TEXT PRIMARY KEY, block INTEGER NOT NULL);
"""


class Signer(Protocol):
    def transfer(self, *, chain: str, token: str, from_wallet: str, to: str, amount: Decimal,
                 now: datetime) -> str: ...


class SimChainSigner:
    """Each transfer is mined in its own block; mine(n) adds empty blocks so confirmations accrue."""

    def __init__(self, path: str | Path, start_block: int = 1_000_000):
        self._c = sqlite3.connect(str(path), isolation_level=None, check_same_thread=False, timeout=30)
        self._c.executescript(_SCHEMA)
        self._lock = threading.Lock()
        self._start = start_block

    def _next_block(self, chain: str) -> int:
        row = self._c.execute("SELECT block FROM sim_head WHERE chain = ?", (chain,)).fetchone()
        nxt = (row[0] if row else self._start) + 1
        self._c.execute("INSERT INTO sim_head VALUES (?, ?) ON CONFLICT(chain) DO UPDATE SET block = excluded.block",
                        (chain, nxt))
        return nxt

    def transfer(self, *, chain: str, token: str, from_wallet: str, to: str, amount: Decimal, now: datetime,
                 status: str = "success") -> str:
        with self._lock:
            self._c.execute("BEGIN IMMEDIATE")
            try:
                n = self._c.execute("SELECT COUNT(*) FROM sim_chain").fetchone()[0]
                tx = "0x" + hashlib.sha256(f"{chain}:{from_wallet}:{to}:{amount}:{now.isoformat()}:{n}".encode()).hexdigest()
                self._c.execute("INSERT INTO sim_chain (chain, tx_hash, block_number, block_time, token, from_address, "
                                "to_address, amount, status) VALUES (?,?,?,?,?,?,?,?,?)",
                                (chain, tx, self._next_block(chain), now.isoformat(), token.upper(), from_wallet.lower(),
                                 to.lower(), str(amount), status))
                self._c.execute("COMMIT")
            except BaseException:
                self._c.execute("ROLLBACK")
                raise
        return tx

    def mine(self, chain: str, blocks: int) -> None:
        with self._lock:
            for _ in range(blocks):
                self._next_block(chain)

    # ---- observer side (what Reconcile reads)

    def observed(self) -> list[PaymentObserved]:
        rows = self._c.execute("SELECT chain, tx_hash, block_number, block_time, token, from_address, to_address, "
                               "amount, status FROM sim_chain ORDER BY seq").fetchall()
        return [PaymentObserved(chain=r[0], tx_hash=r[1], block_number=r[2], block_time=datetime.fromisoformat(r[3]),
                                token=r[4], from_address=r[5], to_address=r[6], amount=Decimal(r[7]), status=r[8])
                for r in rows]

    def heads(self) -> dict[str, int]:
        return {r[0]: r[1] for r in self._c.execute("SELECT chain, block FROM sim_head")}

    def close(self) -> None:
        self._c.close()
