# Independent verification — 2026-11-02

Reviewed local commit `4f4b7c9`, whose working tree was clean. No remote is configured;
the clean clone therefore uses the local Git repository, not an independently hosted copy.
This review was performed by a different agent after reading the implementation. It is
an independent code review, not a blind external holdout or production security audit.

## Reconciliation findings and fixes

Six newly written checks failed against the original implementation:

- A reported hash could confirm an approval using an observation on another chain.
- A reported hash could confirm an approval paid in another token.
- Repeated submission records for one transfer caused a false DUPLICATE alert.
- Repeated observations for one event caused a false DUPLICATE alert.
- Duplicate heuristics folded an unrelated-token outflow into an existing approval.
- Event identity treated chain casing as significant.

Hash matching now requires the same chain, token and sender. Duplicate heuristics
also require that route. Observations and submission hits are deduplicated by
normalized `(chain, tx_hash, log_index)`. Conflicting payloads for one event raise
ValueError explicitly instead of silently choosing a version. Confirmation-head
lookup uses normalized chain names too.

Ten permanent tests in `tests/test_independent_recon.py` cover these findings,
wrong senders, conflicting observations, case variants, and real duplicate payments.
The existing environment passes all **110 tests**. Running the full generation,
load, decision, simulation, reconciliation and report pipeline preserves **252/258**,
**221/221** and **44/44**. Tests using local sockets require execution outside the
restricted sandbox on this Windows host.

## Installation finding

The scripts import openpyxl directly, but neither requirements.txt nor pyproject.toml
declared it. A machine with openpyxl already installed hides this dependency gap.
Both dependency lists now include openpyxl.

Reproduced in a fresh Python 3.12 venv installed only from the original requirements:
`python scripts/make_test_data.py` failed with `ModuleNotFoundError: openpyxl`.
After applying this patch and installing the corrected requirements, the fresh
environment passes **110 tests** and the entire README pipeline, with the same
**252/258**, **221/221**, and **44/44** results. There is one upstream TestClient
deprecation warning. The fresh environment uses newly resolved dependency versions;
it does not reuse the original project's site-packages.

## Workbook comparison

Regenerated input and simulated-chain workbooks have identical cell values and
formulas to the supplied files. The generated report differs: the KPI timing cells
change and recon_exceptions now includes item_id (11 columns versus 10 in the
supplied report). Therefore the claim that every workbook difference is only
internal metadata is not supported. The decision and reconciliation totals agree.

## Remaining limits

- The documented purpose-mismatch and wallet-rotation gaps remain (six labeled disagreements).
- Tx hashes can contain multiple Transfer logs. General batch-payment allocation and
  per-log anomaly classification need a separate design; these regressions do not
  establish correctness for arbitrary multi-log transactions.
- Policy and principal keys still arrive through the request; the integrator must provide
  them through a trusted path, as the models document. The HTTP API does not supply
  authentication or a server-owned policy store.
- The ledger reserves approvals rather than settlements and does not implement a complete
  signer/executor idempotency protocol. A request_id alone is not proof of exactly-once execution.
- Dependencies remain unpinned. A successful fresh install does not guarantee that future
  package releases will reproduce the same environment.
- No live-chain, real-funds, or browser interaction test was performed in this review.
