"""Append-only audit log in SQLite with a hash chain.

Each record stores the hash of the previous record, so editing or deleting a
row breaks verify_chain(). This makes tampering *detectable*, not impossible:
someone with write access can rewrite the whole chain. Production would anchor
the head hash externally (e.g. WORM storage or periodic on-chain commitment).
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
from datetime import datetime, timezone
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

from .models import EvaluationRequest, EvaluationResult

GENESIS = "0" * 64

_SCHEMA = """
CREATE TABLE IF NOT EXISTS audit_log (
    seq            INTEGER PRIMARY KEY AUTOINCREMENT,
    ts_utc         TEXT NOT NULL,
    request_id     TEXT NOT NULL,
    agent_id       TEXT NOT NULL,
    user_id        TEXT NOT NULL,
    decision       TEXT NOT NULL,
    risk_score     INTEGER NOT NULL,
    reason_codes   TEXT NOT NULL,
    request_json   TEXT NOT NULL,
    result_json    TEXT NOT NULL,
    engine_version TEXT NOT NULL,
    prev_hash      TEXT NOT NULL,
    record_hash    TEXT NOT NULL
);
"""


def _canonical(obj) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str)


def _hash(prev_hash: str, payload: dict) -> str:
    return hashlib.sha256((prev_hash + _canonical(payload)).encode()).hexdigest()


class AuditLog:
    def __init__(self, path: str | Path = "agentguard_audit.db"):
        self.path = str(path)
        with self._conn() as c:
            c.executescript(_SCHEMA)

    @contextmanager
    def _conn(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self.path, isolation_level=None)  # explicit transactions
        conn.row_factory = sqlite3.Row
        try:
            yield conn
        finally:
            conn.close()

    def record(self, req: EvaluationRequest, res: EvaluationResult) -> dict:
        with self._conn() as c:
            c.execute("BEGIN IMMEDIATE")  # serialise writers so the chain stays linear
            try:
                h, prev, payload = self._append(c, req, res)
                c.execute("COMMIT")
            except Exception:
                c.execute("ROLLBACK")
                raise
        return {**payload, "prev_hash": prev, "record_hash": h}

    @staticmethod
    def _append(c, req, res):
        row = c.execute("SELECT record_hash FROM audit_log ORDER BY seq DESC LIMIT 1").fetchone()
        prev = row["record_hash"] if row else GENESIS
        payload = {
            "ts_utc": datetime.now(timezone.utc).isoformat(),
            "request_id": req.request_id,
            "agent_id": req.action.agent_id,
            "user_id": req.intent.user_id,
            "decision": res.decision.value,
            "risk_score": res.risk_score,
            "reason_codes": _canonical(res.reason_codes),
            "request_json": _canonical(req.model_dump(mode="json")),
            "result_json": _canonical(res.model_dump(mode="json")),
            "engine_version": res.engine_version,
        }
        h = _hash(prev, payload)
        c.execute(
            f"INSERT INTO audit_log ({', '.join(payload)}, prev_hash, record_hash) "
            f"VALUES ({', '.join('?' * len(payload))}, ?, ?)",
            (*payload.values(), prev, h),
        )
        return h, prev, payload

    def rows(self, limit: int = 200) -> list[dict]:
        with self._conn() as c:
            return [dict(r) for r in c.execute(
                "SELECT * FROM audit_log ORDER BY seq DESC LIMIT ?", (limit,))]

    def verify_chain(self) -> tuple[bool, int | None]:
        """Returns (ok, first_bad_seq)."""
        prev = GENESIS
        with self._conn() as c:
            for r in c.execute("SELECT * FROM audit_log ORDER BY seq ASC"):
                r = dict(r)
                payload = {k: r[k] for k in (
                    "ts_utc", "request_id", "agent_id", "user_id", "decision", "risk_score",
                    "reason_codes", "request_json", "result_json", "engine_version")}
                if r["prev_hash"] != prev or _hash(prev, payload) != r["record_hash"]:
                    return False, r["seq"]
                prev = r["record_hash"]
        return True, None
