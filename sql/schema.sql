-- AgentGuard analysis database (SQLite).
-- Input tables are loaded from data/agentguard_test_data.xlsx by scripts/load_excel.py.
-- Output tables (decisions, decision_findings, ledger, audit_log) are written by scripts/run_batch.py.

DROP TABLE IF EXISTS payment_requests;
DROP TABLE IF EXISTS mandates;
DROP TABLE IF EXISTS agents;
DROP TABLE IF EXISTS vendors;
DROP TABLE IF EXISTS denylist;
DROP TABLE IF EXISTS principal_keys;
DROP TABLE IF EXISTS load_issues;

CREATE TABLE principal_keys (
    key_id          TEXT PRIMARY KEY,
    principal       TEXT NOT NULL,
    public_key_hex  TEXT NOT NULL
);

CREATE TABLE agents (
    agent_id                 TEXT PRIMARY KEY,
    max_amount_per_tx        NUMERIC NOT NULL,
    allowed_tokens           TEXT NOT NULL,   -- comma-separated
    allowed_chains           TEXT NOT NULL,   -- comma-separated
    velocity_max_tx          INTEGER NOT NULL,
    velocity_window_minutes  NUMERIC NOT NULL,
    split_window_hours       NUMERIC NOT NULL,
    split_near_limit_ratio   NUMERIC NOT NULL,
    require_signed_mandate   INTEGER NOT NULL -- 0/1
);

CREATE TABLE vendors (
    vendor_name  TEXT NOT NULL,
    chain        TEXT NOT NULL,
    address      TEXT NOT NULL,
    PRIMARY KEY (vendor_name, chain, address)
);

CREATE TABLE denylist (
    address  TEXT PRIMARY KEY,
    reason   TEXT
);

-- Signed fields are kept as TEXT exactly as entered: the signature covers their text form.
CREATE TABLE mandates (
    mandate_id         TEXT PRIMARY KEY,
    principal          TEXT NOT NULL,
    agent_id           TEXT NOT NULL,
    payee_name         TEXT NOT NULL,
    destinations       TEXT NOT NULL,          -- semicolon-separated
    token              TEXT NOT NULL,
    chain              TEXT NOT NULL,
    max_amount_per_tx  TEXT NOT NULL,
    max_total          TEXT,                   -- NULL = no cap
    max_tx_count       TEXT,                   -- NULL = unlimited
    valid_from         TEXT NOT NULL,
    expires_at         TEXT NOT NULL,
    purpose            TEXT,
    key_id             TEXT NOT NULL,
    signature          TEXT NOT NULL,
    test_note          TEXT
);

CREATE TABLE payment_requests (
    request_id      TEXT PRIMARY KEY,
    ts              TEXT NOT NULL,             -- UTC 'YYYY-MM-DD HH:MM:SS'
    agent_id        TEXT NOT NULL,
    mandate_id      TEXT,                      -- NULL = no mandate sent
    payee_name      TEXT NOT NULL,
    to_address      TEXT NOT NULL,
    amount          NUMERIC NOT NULL,
    token           TEXT NOT NULL,
    chain           TEXT NOT NULL,
    context_source  TEXT NOT NULL,
    context_text    TEXT,
    scenario_type   TEXT,
    ground_truth    TEXT CHECK (ground_truth IN ('APPROVE', 'REVIEW', 'BLOCK')),
    notes           TEXT
);
CREATE INDEX ix_req_ts ON payment_requests(ts);

-- Data-quality problems found while loading (the load continues; bad rows are skipped).
CREATE TABLE load_issues (
    sheet     TEXT,
    row_ref   TEXT,
    issue     TEXT
);
