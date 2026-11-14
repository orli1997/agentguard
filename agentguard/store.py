"""Server-owned configuration and service state.

Everything the engine trusts lives here, not in the request:
  * per-agent policy, vendor registry, denylist, principal public keys  (config DB, loaded from Excel)
  * which API key belongs to which agent (only a hash is stored)        (state DB)
  * idempotency records: one request_id, one outcome                      (state DB)
  * executor submissions: request_id -> tx_hash                          (state DB)

An agent authenticates with its API key; its identity comes from the key, never
from the request body.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import sqlite3
import threading
from contextlib import contextmanager
from datetime import datetime
from decimal import Decimal
from pathlib import Path
from typing import Iterator, Optional

from .mandate import MandateBody, SignedMandate
from .models import AuthorizationPolicy, PrincipalKey, VendorRecord

_STATE_SCHEMA = """
CREATE TABLE IF NOT EXISTS agent_keys (
    key_hash   TEXT PRIMARY KEY,
    agent_id   TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS idempotency (
    agent_id    TEXT NOT NULL,
    request_id  TEXT NOT NULL,
    state       TEXT NOT NULL,            -- in_progress | done
    response    TEXT,                     -- JSON returned to the agent
    created_at  TEXT NOT NULL,
    PRIMARY KEY (agent_id, request_id)
);
CREATE TABLE IF NOT EXISTS submissions (
    request_id   TEXT NOT NULL,
    tx_hash      TEXT NOT NULL,
    submitted_at TEXT NOT NULL,
    attempt      INTEGER NOT NULL
);
"""


def _rows(con: sqlite3.Connection, sql: str, *args) -> list[dict]:
    con.row_factory = sqlite3.Row
    return [dict(r) for r in con.execute(sql, args)]


def load_policies(con: sqlite3.Connection) -> dict[str, AuthorizationPolicy]:
    """Build one AuthorizationPolicy per agent from the config tables (see sql/schema.sql)."""
    keys = [PrincipalKey(**k) for k in _rows(con, "SELECT key_id, principal, public_key_hex FROM principal_keys")]
    registry: dict[tuple, list[str]] = {}
    for v in _rows(con, "SELECT * FROM vendors"):
        registry.setdefault((v["vendor_name"], v["chain"]), []).append(v["address"])
    vendors = [VendorRecord(name=n, chain=c, addresses=a) for (n, c), a in registry.items()]
    deny = [r["address"] for r in _rows(con, "SELECT address FROM denylist")]
    out = {}
    for a in _rows(con, "SELECT * FROM agents"):
        out[a["agent_id"]] = AuthorizationPolicy(
            agent_id=a["agent_id"], max_amount_per_tx=Decimal(str(a["max_amount_per_tx"])),
            allowed_tokens=[t.strip() for t in a["allowed_tokens"].split(",")],
            allowed_chains=[c.strip() for c in a["allowed_chains"].split(",")],
            vendor_registry=vendors, denylist=deny, principal_keys=keys,
            require_signed_mandate=bool(a["require_signed_mandate"]),
            velocity_max_tx=int(a["velocity_max_tx"]), velocity_window_minutes=float(a["velocity_window_minutes"]),
            split_window_hours=float(a["split_window_hours"]),
            split_near_limit_ratio=Decimal(str(a["split_near_limit_ratio"])))
    return out


def load_mandates(con: sqlite3.Connection) -> dict[str, SignedMandate]:
    out = {}
    for m in _rows(con, "SELECT * FROM mandates"):
        body = MandateBody(
            mandate_id=m["mandate_id"], principal=m["principal"], agent_id=m["agent_id"], purpose=m["purpose"] or "",
            payee_name=m["payee_name"], destinations=[d.strip() for d in m["destinations"].split(";") if d.strip()],
            token=m["token"], chain=m["chain"], max_amount_per_tx=Decimal(m["max_amount_per_tx"]),
            max_total=Decimal(m["max_total"]) if m["max_total"] else None,
            max_tx_count=int(m["max_tx_count"]) if m["max_tx_count"] else None,
            valid_from=m["valid_from"], expires_at=m["expires_at"])
        out[m["mandate_id"]] = SignedMandate(body=body, key_id=m["key_id"], signature=m["signature"])
    return out


def _hash_key(raw: str) -> str:
    return hashlib.sha256(raw.encode()).hexdigest()


class Store:
    def __init__(self, config_db: str | Path, state_db: str | Path):
        cfg = sqlite3.connect(str(config_db))
        try:
            self.policies = load_policies(cfg)
            self.wallets = {r["agent_id"]: r["wallet_address"]
                            for r in _rows(cfg, "SELECT agent_id, wallet_address FROM agents")}
        finally:
            cfg.close()
        self._state = sqlite3.connect(str(state_db), isolation_level=None, check_same_thread=False, timeout=30)
        self._state.row_factory = sqlite3.Row
        self._state.executescript(_STATE_SCHEMA)
        self._lock = threading.Lock()

    @contextmanager
    def _tx(self) -> Iterator[sqlite3.Connection]:
        with self._lock:
            self._state.execute("BEGIN IMMEDIATE")
            try:
                yield self._state
                self._state.execute("COMMIT")
            except BaseException:
                self._state.execute("ROLLBACK")
                raise

    # ---------------------------------------------------------- agents

    def issue_agent_key(self, agent_id: str, now: datetime) -> str:
        """Return a new raw API key for an agent. Only its hash is stored; show the raw key once."""
        if agent_id not in self.policies:
            raise KeyError(f"no policy configured for {agent_id}")
        raw = "agk_" + secrets.token_urlsafe(32)
        with self._tx() as c:
            c.execute("INSERT INTO agent_keys VALUES (?, ?, ?)", (_hash_key(raw), agent_id, now.isoformat()))
        return raw

    def agent_for_key(self, raw: Optional[str]) -> Optional[str]:
        if not raw:
            return None
        h = _hash_key(raw)
        row = self._state.execute("SELECT key_hash, agent_id FROM agent_keys WHERE key_hash = ?", (h,)).fetchone()
        return row["agent_id"] if row and hmac.compare_digest(row["key_hash"], h) else None

    # ---------------------------------------------------------- idempotency

    def claim_request(self, agent_id: str, request_id: str, now: datetime) -> tuple[str, Optional[dict]]:
        """('new', None) the first time; ('done', response) or ('in_progress', None) on a repeat."""
        with self._tx() as c:
            row = c.execute("SELECT state, response FROM idempotency WHERE agent_id = ? AND request_id = ?",
                            (agent_id, request_id)).fetchone()
            if row:
                return row["state"], json.loads(row["response"]) if row["response"] else None
            c.execute("INSERT INTO idempotency VALUES (?, ?, 'in_progress', NULL, ?)",
                      (agent_id, request_id, now.isoformat()))
            return "new", None

    def finish_request(self, agent_id: str, request_id: str, response: dict) -> None:
        with self._tx() as c:
            c.execute("UPDATE idempotency SET state = 'done', response = ? WHERE agent_id = ? AND request_id = ?",
                      (json.dumps(response, default=str), agent_id, request_id))

    # ---------------------------------------------------------- submissions

    def record_submission(self, request_id: str, tx_hash: str, now: datetime, attempt: int = 1) -> None:
        with self._tx() as c:
            c.execute("INSERT INTO submissions VALUES (?, ?, ?, ?)", (request_id, tx_hash, now.isoformat(), attempt))

    def submissions(self) -> list[dict]:
        return [dict(r) for r in self._state.execute("SELECT * FROM submissions ORDER BY submitted_at")]

    def close(self) -> None:
        self._state.close()
