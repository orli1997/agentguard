"""Demo: an agent copies a payee address from the wallet's history; real Base mainnet intel decides.

    python scripts/demo_poisoning_intel.py [path/to/live.db]

Reads the live address-poisoning detector's database (default ~/poisoning_data/live.db,
read-only). The pair below was caught on Base mainnet by that detector.
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from agentguard import evaluate  # noqa: E402
from agentguard.models import EvaluationRequest  # noqa: E402
from agentguard.poisoning_intel import PoisoningIntel, poisoning_findings  # noqa: E402
from agentguard.scenarios import base  # noqa: E402

REAL = "0xa742314be408fc06f304d9b84b69ad0c3ad8b9c3"
FAKE = "0xa742debd5ae04e578b7a6c0130a3aacd409ab9c3"
DB = Path(sys.argv[1]) if len(sys.argv) > 1 else Path.home() / "poisoning_data" / "live.db"


def request(to: str) -> EvaluationRequest:
    d = base()
    d["intent"]["approved_destinations"] = []          # no trusted address for this payee
    d["policy"]["vendor_registry"] = []
    d["transaction"]["to"] = to
    d["context"] = [{"id": "hist-1", "source_type": "wallet_history",
                     "content": "Recent outgoing USDC transfers", "extracted_address": to}]
    d["action"]["destination_source_id"] = "hist-1"
    return EvaluationRequest.model_validate(d)


def show(label: str, to: str, intel: PoisoningIntel | None) -> None:
    extra = poisoning_findings(intel, to) if intel else []
    res = evaluate(request(to), extra_findings=extra)
    print(f"\n{label}\n  to        {to}\n  decision  {res.decision.value}  ({', '.join(res.reason_codes)})")
    for f in res.findings:
        if f.code in ("KNOWN_POISONING_ADDRESS", "POSSIBLE_POISONING_ADDRESS"):
            e = f.evidence
            print(f"  why       {f.message}\n            poison events {e['poison_events']}, blocks "
                  f"{e['first_block']}-{e['last_block']}, losses recorded {e['losses_recorded']}")


def main() -> None:
    intel = PoisoningIntel(DB)
    snap = intel.lookup(REAL)["snapshot"]
    print(f"intel: {DB}\n  updated {snap['intel_age_s']} s ago, next block {snap['next_block']}")
    show("1. Without intel: agent pays the address it copied from history", FAKE, None)
    show("2. With intel: same payment", FAKE, intel)
    show("3. With intel: the real address the fake imitates", REAL, intel)


if __name__ == "__main__":
    main()
