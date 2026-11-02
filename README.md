# AgentGuard: Pre-Signing Risk Engine (Phase 2 prototype)

> A technically valid transaction is not necessarily an authorized transaction.

AgentGuard takes a payment that an AI agent wants signed and decides **APPROVE / REVIEW / BLOCK** *before* the signature happens. Each decision comes with reason codes, evidence, and a hash-chained audit record.

- **Phase 1: Payment Address Injection (Scenario A).** A user authorizes "pay Acme 50 USDC". The agent then reads an invoice that has a hidden instruction swapping the destination address.
- **Phase 2: Signed Mandates and behavior over time (Scenario C).** The user signs a structured mandate with Ed25519, covering destinations, per-payment cap, total budget, payment count, validity window and agent. The engine verifies the signature and enforces the mandate across a *sequence* of payments using its own ledger. That ledger catches cumulative overspend, split payments, and bursts.

**Status:** research prototype. Everything is simulated: no wallet, no keys, no real funds, no testnet.

## Run

```bash
python -m venv .venv
.venv/Scripts/pip install -r requirements.txt     # macOS/Linux: .venv/bin/pip
.venv/Scripts/python -m pytest -q                 # tests
.venv/Scripts/python scripts/evaluate.py          # metrics on labeled cases
.venv/Scripts/streamlit run app.py                # demo UI
.venv/Scripts/uvicorn agentguard.api:app --reload # HTTP API: POST /v1/evaluate
```

## How it decides

| Principle | Implementation |
|---|---|
| Trust comes only from the user and the organisation | Approved destinations come from `UserIntent.approved_destinations` and `AuthorizationPolicy.vendor_registry`. Context items (invoice, email, web, API) are **always** untrusted. Their `source_type` label is descriptive and never grants trust (case A10). |
| Deterministic rules decide | Each check emits `Finding`s with severity `block` / `review` / `info`. The decision is the worst severity present. The risk score is shown but never used to decide. |
| Injection detection is evidence, not the control | The regex scanner (`injection.py`) explains *why* an address changed. A swapped address with perfectly clean wording is still blocked (A13). An injected invoice that the agent ignored still passes (A04). |
| Fail closed | No trusted address on record → REVIEW. Engine exception → REVIEW (`ENGINE_ERROR`). |
| Tamper-evident audit | Each SQLite record holds `prev_hash` and `record_hash`. Editing any row breaks `verify_chain()`. |

### Reason codes

| Code | Severity | Meaning |
|---|---|---|
| `DESTINATION_NOT_AUTHORIZED` | block | A trusted address exists for this payee and the destination isn't one of them |
| `LOOKALIKE_ADDRESS` | block | Same visible prefix/suffix as an approved address (address poisoning) |
| `DENYLISTED_DESTINATION` | block | Destination is on the org denylist |
| `INVALID_ADDRESS_FORMAT` | block | Not a valid EVM address |
| `AMOUNT_EXCEEDS_POLICY_LIMIT` | block | Above the per-transaction limit |
| `AMOUNT_ABOVE_INTENT` | block | Above what the user authorized (plus tolerance) |
| `TOKEN_/CHAIN_NOT_ALLOWED`, `TOKEN_/CHAIN_MISMATCH_INTENT` | block | Asset or network differs from policy or from the user's intent |
| `AGENT_NOT_AUTHORIZED` | block | The policy belongs to a different agent |
| `UNVERIFIED_DESTINATION` | review | No trusted address on record, so the destination can't be verified |
| `TRUSTED_SOURCES_CONFLICT` | review | The user-approved address and the vendor registry disagree |
| `AMOUNT_BELOW_INTENT` | review | Paying less than asked |
| `PAYEE_MISMATCH` | review | The agent's payee name differs from the user's |
| `PROVENANCE_MISMATCH` / `PROVENANCE_MISSING` | review* | The cited source doesn't contain this address, or wasn't supplied |
| `DESTINATION_VERIFIED` | info | Destination matches a trusted record |
| `DESTINATION_FROM_UNTRUSTED_SOURCE` | info | Where the agent got the unverified address |
| `UNTRUSTED_ADDRESS_IN_CONTEXT` | info | An unapproved address sat in the context and wasn't used |
| `INSTRUCTION_IN_UNTRUSTED_CONTENT` | info | Instruction-like text was found in external content |

\* These drop to `info` when the destination is already verified.

## Phase 2: mandates and behavior

| Principle | Implementation |
|---|---|
| Authority must be signed | `SignedMandate` = body + Ed25519 signature over canonical JSON. The trust root is `policy.principal_keys` (org config). Any edit to the body breaks the signature (case M02). A self-signed or spoofed key is rejected (M03, M04). |
| A mandate is exhaustive | When a mandate names destinations, the vendor registry cannot widen them (M10). An unsigned `intent` in the same request is ignored (M09). With `require_signed_mandate`, a request without one is blocked (M08). |
| History is the engine's, not the agent's | `Ledger` (SQLite) records only payments the Guard approved, plus manual approvals of REVIEWs. An agent can't omit history it never controlled. |
| No race-condition overspend | `Guard.check()` reads history, decides and reserves inside one `BEGIN IMMEDIATE` lock. A test fires 8 parallel requests at a 4-payment budget: exactly 4 pass. |
| Splitting ≠ repetition | A split = ≥2 payments to the same destination, each ≥ 50% of the single-payment limit, summing above that limit within 24h → REVIEW. Micro-payments (C06) and monthly repeats (C07) don't qualify. If the signed mandate explicitly authorizes the total (C01), the pattern is recorded as info only. |

| Code | Severity | Meaning |
|---|---|---|
| `MANDATE_REQUIRED` / `_UNKNOWN_SIGNER` / `_INVALID_SIGNATURE` | block | No mandate, key not registered for that principal, or content altered/forged |
| `MANDATE_EXPIRED` / `_NOT_YET_VALID` / `_AGENT_MISMATCH` | block | Outside the validity window, or granted to another agent |
| `AMOUNT_ABOVE_MANDATE` | block | Above the mandate's per-payment cap |
| `CUMULATIVE_BUDGET_EXCEEDED` / `TX_COUNT_EXCEEDED` | block | Would exceed the mandate's total or its number of payments |
| `SPLIT_PAYMENT_SUSPECTED` | review | Near-limit payments to one destination add up past the single-payment limit |
| `VELOCITY_LIMIT` | review | More than N payments by the agent in the window (default 10 / 60 min) |
| `HISTORY_UNAVAILABLE` | review / info | No ledger connected. REVIEW if the mandate has cumulative caps (fail closed) |
| `SPLIT_PATTERN_WITHIN_MANDATE`, `BUDGET_OK`, `MANDATE_VERIFIED`, `REQUEST_INTENT_IGNORED` | info | Evidence |

## Excel + SQL test pipeline

Excel → SQLite → engine → SQL analysis → Excel report.

```bash
.venv/Scripts/python scripts/make_test_data.py   # (re)generate data/agentguard_test_data.xlsx
.venv/Scripts/python scripts/load_excel.py       # Excel -> data/agentguard.db (with data-quality checks)
.venv/Scripts/python scripts/run_batch.py        # replay every request through the Guard, in time order
.venv/Scripts/python scripts/report.py           # sql/analysis.sql -> reports/agentguard_results.xlsx
```

- **Input workbook** (`data/agentguard_test_data.xlsx`) covers October 2026 with 258 payment requests, 3 agents, 9 signed mandates, a vendor registry, a denylist and the principal's public key. The **`ground_truth`** column holds the decision an analyst would want at signing time. You can edit rows or add new ones. Changing any signed field of a mandate invalidates its signature.
- **Database** (`data/agentguard.db`) has the input tables (`sql/schema.sql`) plus outputs: `decisions`, `decision_findings` (one row per rule hit), `ledger` and `audit_log`. Open it with any SQLite tool, such as DB Browser for SQLite or the VS Code SQLite extension.
- **Queries** (`sql/analysis.sql`): confusion matrix, KPIs, accuracy by scenario, disagreements, rule frequency, mandate budget usage, suspicious wallets, daily activity, review queue, blocked value.
- **Report** (`reports/agentguard_results.xlsx`): the Summary sheet uses live Excel formulas (COUNTIFS/SUMPRODUCT) over `all_decisions`, plus one sheet per query.

**Current result:** 252/258 match the labels, every BLOCK-labelled attack is blocked, and there are 0 false alarms. The 6 disagreements are known gaps, kept in the data on purpose:
- **4 × `purpose_mismatch`.** Right vendor, wrong purpose ("gift cards" bought through DesignHub). The engine approves them because Scenario B (semantic intent) isn't built.
- **2 × `vendor_rotated_wallet`.** A genuine vendor wallet change. The engine blocks it, where a human review would be more appropriate.

## Phase 3: Reconcile (approved vs. executed)

AgentGuard decides *before* signing. Reconcile checks *after* execution: did what happened on-chain match what was approved? The chain alone doesn't know what was approved, so the data contract has three events:

| Event | Source | Fields |
|---|---|---|
| `PaymentApproved` | AgentGuard's APPROVE decisions + audit hash | request_id, approved_at, agent wallet, destination, amount, token, chain |
| `PaymentSubmitted` (optional) | the executor's log | request_id → tx_hash, attempt |
| `PaymentObserved` | chain: ERC-20 Transfer logs + receipts (`observe_rpc.py`, read-only JSON-RPC) | tx_hash, block, time, from, to, amount, status |

Each approval ends in exactly one status, and every outflow from an agent wallet is either claimed by an approval or reported:

| Status | Severity | Meaning |
|---|---|---|
| `CONFIRMED` | none | Paid once, right amount and destination, enough confirmations |
| `PENDING` | low | Within the grace period, or seen with fewer than 12 confirmations |
| `FAILED` | medium | Mined but reverted; safe to retry with the same request_id |
| `MISSING` | high | Approved but never seen after the grace period, with or without a reported hash |
| `DUPLICATE` | high | One approval paid more than once (e.g. a retry after the first tx had settled; see x402 issue #452) |
| `AMOUNT_MISMATCH` | high | Amount differs; an exact power-of-10 ratio is flagged as a likely decimals bug |
| `DESTINATION_MISMATCH` | critical | The executed transaction paid someone else: it changed after approval |
| `UNAPPROVED_OUTFLOW` | critical | Money left an agent wallet with no approval: the guard was bypassed |

Matching uses the reported tx hash when there is one. Otherwise it falls back to wallet + destination + exact amount + time window, and the explanation says so. **Known limit:** with no reported hash, a wrong-amount payment cannot be tied to its approval. It shows up as `MISSING` + `UNAPPROVED_OUTFLOW` (both flagged), not as `AMOUNT_MISMATCH`. There's a test documenting this.

```bash
.venv/Scripts/python scripts/simulate_chain.py     # approved payments -> data/onchain_activity.xlsx, with labelled faults
.venv/Scripts/python scripts/reconcile_batch.py    # -> payment_approved / _submitted / _observed, recon_items
.venv/Scripts/python scripts/explain.py --exceptions   # story + JSON evidence bundle per open exception
.venv/Scripts/python scripts/report.py             # report now includes recon_summary, recon_exceptions, wallet_reconciliation
```

**Current result (synthetic):** 218 approvals and 224 transfers. All 221 labelled outcomes match (204 confirmed, of which 32 were matched without a tx hash, plus 17 exceptions). The simulator and reconciler were written together, so this shows rule coverage, not field performance. The RPC observer was checked once against live Base mainnet and parsed 83 real USDC transfers from one block. Free public nodes rate-limit `eth_getLogs` (429) and some refuse receipts (403), so real use needs a keyed RPC provider.

## Verification (2026-11-02)

- **Clean clone:** fresh `git clone` → full pipeline → same results (252/258, 221/221, 44/44). Regenerated Excel files have identical data, so generation is deterministic.
- **Red-team** (`tests/test_redteam.py`): 15 probes written against cases the rules weren't designed for. **4 failed on first run and were fixed:**

| Finding | Effect before the fix | Fix |
|---|---|---|
| Same tx hash reported for two requests | One transfer confirmed **two** approvals (double counting) | A transfer pays one approval; the second gets `MISSING` and is told which request owns the tx |
| Block timestamp a few seconds before the engine's approval time | Legit payment → `MISSING` + `UNAPPROVED_OUTFLOW` | 120 s clock-skew tolerance (`ReconConfig.clock_skew_seconds`) |
| Batch loader rounded amounts to cents | 6-decimal USDC amounts would mismatch | Exact `Decimal` end to end |
| Splitting grouped by address, not payee | Alternating a vendor's two wallets delayed the flag (with N wallets: no flag) | Split groups = all trusted addresses of the payee |

Behaviour that held: `0X`-prefixed and whitespace-padded addresses are blocked, a 0.000001 overpayment is blocked, a mandate can't be replayed on another chain, a key registered to another principal is rejected, naive datetimes are treated as UTC, and address and hash casing doesn't matter.

## Results on the labeled cases (44 cases: 24 Phase 1 + 20 Phase 2)

`scripts/evaluate.py` reports 44/44 correct decisions, a 0% false-positive rate, and decisions in well under 1 ms. The suite has 70 tests, including the concurrency test.

**These numbers are not evidence of real-world performance.** I wrote the cases at the same time as the rules, so the dev/test split isn't an independent holdout. The cases measure rule coverage and guard against regressions. They do not measure detection.

## Known limitations (facts, not caveats)

1. **No enforcement.** The engine returns a decision. Nothing stops an agent from calling the signer directly. In production the *signer* (or an MPC/policy co-signer) has to call AgentGuard and refuse to sign without APPROVE.
2. **The trust boundary moved; it didn't vanish.** Phase 2 mandates close the "forged intent" gap, but now the principal's signing key and the `principal_keys` config are the boundary. Key management (where the user signs, rotation, revocation) isn't built. There's no revocation list yet: a leaked mandate is valid until it expires.
3. **EVM only, and no EIP-55 checksum validation.** That needs keccak-256, which isn't in the Python stdlib.
4. **Behavioral rules are fixed thresholds** (50% near-limit, 24h, 10/hour). They're placeholders, not calibrated on real payment data, and a patient attacker can stay under them (e.g. 3 payments a day). Semantic purpose mismatch (Scenario B) is Phase 3.
5. **The injection regex is easy to bypass.** That's acceptable only because it never decides anything.
6. **Payee matching is exact string matching** after case and whitespace normalisation.
7. **The audit chain is tamper-evident, not tamper-proof.** Anyone with DB write access can rewrite the whole chain unless the head hash is anchored externally.
8. **Ledger records approvals, not settlement.** An APPROVE is assumed to be paid. A signed-but-failed transaction still counts against the budget, which is the conservative direction. Reconciling the ledger with on-chain settlement is not built.

## Hypotheses still to test (not claims)

- Wallet providers (Coinbase Agentic Wallets, Crossmint, Openfort, Turnkey-style policy engines) may already enforce destination allowlists. If so, Scenario A on its own is **not** a differentiator. The open question is whether the *intent-bound* version (allowlist derived per task from the user instruction, plus provenance) adds value over static allowlists.
- Customers would pay for an independent layer. Unvalidated.

## Layout

```
agentguard/
  models.py     schema: UserIntent, AuthorizationPolicy, AgentAction, ContextItem, TransactionRequest, results
  engine.py     deterministic checks + decision (authority -> static -> authority -> behavior)
  mandate.py    Ed25519 signed mandates
  ledger.py     engine-owned payment history, atomic check-and-reserve
  guard.py      engine + ledger + audit as one pre-signing call
  reconcile.py  Phase 3: approved vs. executed, statuses + explanations
  observe_rpc.py  read-only ERC-20 transfer reader for EVM JSON-RPC
  address.py    EVM format, normalisation, lookalike detection
  injection.py  instruction-in-content heuristics (evidence only)
  audit.py      hash-chained SQLite audit log
  scenarios.py  24 labeled Phase 1 cases
  scenarios_phase2.py  20 labeled Phase 2 cases (fixture keys, fixed clock)
data/           agentguard_test_data.xlsx (input); agentguard.db is generated
sql/            schema.sql, analysis.sql
scripts/        make_test_data, load_excel, run_batch, report, evaluate,
                simulate_chain, reconcile_batch, explain
reports/        agentguard_results.xlsx (generated)
  metrics.py    detection / FP / FN / latency
  api.py        FastAPI
app.py          Streamlit demo
tests/          pytest
```
