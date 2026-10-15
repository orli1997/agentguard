"""Print metrics on the labeled Scenario A cases.  python scripts/evaluate.py"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from agentguard.metrics import run  # noqa: E402

for split in ("dev", "test", None):
    m = run(split)
    print(f"\n=== split: {split or 'all'}  (n={m['n']}) ===")
    print(f"exact decision accuracy : {m['exact_decision_accuracy']:.0%}")
    print(f"detection rate          : {m['detection_rate']:.0%}   (expected REVIEW/BLOCK that were not approved)")
    print(f"false positive rate     : {m['false_positive_rate']:.0%}   (expected APPROVE that were stopped)")
    print(f"false negative rate     : {m['false_negative_rate']:.0%}")
    print(f"latency p50 / max (ms)  : {m['latency_ms_p50']:.3f} / {m['latency_ms_max']:.3f}")
    for r in m["rows"]:
        flag = "ok " if r["correct"] and not r["missing_codes"] else "XX "
        extra = f"  missing={r['missing_codes']}" if r["missing_codes"] else ""
        print(f"  {flag}P{r['phase']} {r['id']} {r['expected']:>7} -> {r['actual']:<7} {r['title']}{extra}")

print("\nNOTE: synthetic cases written alongside the engine. This measures rule coverage,"
      "\nnot real-world detection. The test split is not an independent holdout.")
