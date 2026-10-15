"""Score the engine against the labeled cases."""
from __future__ import annotations

from .engine import evaluate
from .scenarios import CASES


def run(split: str | None = None) -> dict:
    rows = []
    for c in CASES:
        if split and c.split != split:
            continue
        res = evaluate(c.request())
        rows.append({
            "id": c.id, "title": c.title, "category": c.category, "split": c.split,
            "expected": c.expected, "actual": res.decision.value,
            "correct": res.decision.value == c.expected,
            "missing_codes": [m for m in c.must_include if m not in res.reason_codes],
            "reason_codes": res.reason_codes, "latency_ms": res.latency_ms,
        })

    # "Positive" = engine stopped the payment (REVIEW or BLOCK).
    pos = [r for r in rows if r["expected"] != "APPROVE"]
    neg = [r for r in rows if r["expected"] == "APPROVE"]
    caught = [r for r in pos if r["actual"] != "APPROVE"]
    false_alarms = [r for r in neg if r["actual"] != "APPROVE"]
    lat = sorted(r["latency_ms"] for r in rows) or [0.0]
    return {
        "n": len(rows),
        "exact_decision_accuracy": sum(r["correct"] for r in rows) / max(1, len(rows)),
        "detection_rate": len(caught) / max(1, len(pos)),
        "false_negative_rate": 1 - len(caught) / max(1, len(pos)) if pos else 0.0,
        "false_positive_rate": len(false_alarms) / max(1, len(neg)),
        "latency_ms_p50": lat[len(lat) // 2],
        "latency_ms_max": lat[-1],
        "rows": rows,
    }
