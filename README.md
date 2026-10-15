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

## Results on the labeled cases (44 cases: 24 Phase 1 + 20 Phase 2)

`scripts/evaluate.py` reports 44/44 correct decisions, a 0% false-positive rate, and decisions in well under 1 ms. The suite has 70 tests, including the concurrency test.

**These numbers are not evidence of real-world performance.** I wrote the cases at the same time as the rules, so the dev/test split isn't an independent holdout. The cases measure rule coverage and guard against regressions. They do not measure detection.

## Known limitations (facts, not caveats)

1. **No enforcement.** The engine returns a decision. Nothing stops an agent from calling the signer directly. In production the *signer* (or an MPC/policy co-signer) has to call AgentGuard and refuse to sign without APPROVE.
2. **The trust boundary moved; it didn't vanish.** Phase 2 mandates close the "forged intent" gap, but now the principal's signing key and the `principal_keys` config are the boundary. Key management (where the user signs, rotation, revocation) isn't built. There's no revocation list yet: a leaked mandate is valid until it expires.
3. **EVM only, and no EIP-55 checksum validation.** That needs keccak-256, which isn't in the Python stdlib.
4. **Behavioral rules are fixed thresholds** (50% near-limit, 24h, 10/hour). They're placeholders, not calibrated on real payment data, and a patient attacker can stay under them (e.g. 3 payments a day). Semantic purpose mismatch (Scenario B) is Phase 3.
8. **Ledger records approvals, not settlement.** An APPROVE is assumed to be paid. A signed-but-failed transaction still counts against the budget, which is the conservative direction. Reconciling the ledger with on-chain settlement is not built.
5. **The injection regex is easy to bypass.** That's acceptable only because it never decides anything.
6. **Payee matching is exact string matching** after case and whitespace normalisation.
7. **The audit chain is tamper-evident, not tamper-proof.** Anyone with DB write access can rewrite the whole chain unless the head hash is anchored externally.

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
  address.py    EVM format, normalisation, lookalike detection
  injection.py  instruction-in-content heuristics (evidence only)
  audit.py      hash-chained SQLite audit log
  scenarios.py  24 labeled Phase 1 cases
  scenarios_phase2.py  20 labeled Phase 2 cases (fixture keys, fixed clock)
  metrics.py    detection / FP / FN / latency
  api.py        FastAPI
app.py          Streamlit demo
tests/          pytest
```
