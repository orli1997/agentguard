# AgentGuard: Pre-Signing Risk Engine (Phase 1 prototype)

> A technically valid transaction is not necessarily an authorized transaction.

AgentGuard takes a payment that an AI agent wants signed and decides **APPROVE / REVIEW / BLOCK** *before* the signature happens. Each decision comes with reason codes, evidence, and a hash-chained audit record.

Phase 1 covers **Scenario A: Payment Address Injection**. A user authorizes "pay Acme 50 USDC". The agent then reads an invoice that has a hidden instruction swapping the destination address.

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

## Results on the labeled cases (24 cases, Scenario A)

`scripts/evaluate.py` reports 24/24 correct decisions, a 0% false-positive rate, and decisions in well under 1 ms.

**These numbers are not evidence of real-world performance.** I wrote the cases at the same time as the rules, so the dev/test split isn't an independent holdout. The cases measure rule coverage and guard against regressions. They do not measure detection.

## Known limitations (facts, not caveats)

1. **No enforcement.** The engine returns a decision. Nothing stops an agent from calling the signer directly. In production the *signer* (or an MPC/policy co-signer) has to call AgentGuard and refuse to sign without APPROVE.
2. **Garbage in, garbage out on trusted inputs.** If the integration fills `approved_destinations` from something the agent can write to, the whole model collapses. Where the user's intent is captured is the real security boundary, and it sits outside this code.
3. **EVM only, and no EIP-55 checksum validation.** That needs keccak-256, which isn't in the Python stdlib.
4. **Single transaction only.** Splitting (Scenario C) and semantic purpose mismatch (Scenario B) are Phase 2 and Phase 3.
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
  engine.py     deterministic checks + decision
  address.py    EVM format, normalisation, lookalike detection
  injection.py  instruction-in-content heuristics (evidence only)
  audit.py      hash-chained SQLite audit log
  scenarios.py  24 labeled Scenario A cases
  metrics.py    detection / FP / FN / latency
  api.py        FastAPI
app.py          Streamlit demo
tests/          pytest
```
