"""Heuristic detection of instruction-like text inside untrusted content.

This is EVIDENCE, not a verdict. Pattern lists are trivially bypassed by an
attacker who rephrases, so the engine never relies on them to allow or block a
payment. The destination check does the real work; this only explains *why*
a destination may have changed.
"""
from __future__ import annotations

import re

PATTERNS: list[tuple[str, re.Pattern]] = [
    ("override_instructions", re.compile(r"\b(ignore|disregard|forget)\b.{0,40}\b(previous|prior|above|earlier|all)\b.{0,20}\b(instructions?|rules?|prompts?)\b", re.I | re.S)),
    ("role_injection", re.compile(r"(^|\n)\s*(system|assistant|developer)\s*:", re.I)),
    ("address_change_notice", re.compile(r"\b(new|updated|changed|correct|alternative)\b.{0,30}\b(wallet|payment|deposit|receiving|bank)\b.{0,20}\b(address|details|account)\b", re.I | re.S)),
    # "pay" is left out on purpose: "Pay to: 0x..." is the normal label on every invoice.
    ("redirect_payment", re.compile(r"\b(send|transfer|route|redirect)\b.{0,40}\b(to|into)\b.{0,15}0x[0-9a-f]{6,}", re.I | re.S)),
    ("secrecy", re.compile(r"\b(do not|don't|never)\b.{0,20}\b(tell|inform|notify|mention|ask)\b.{0,20}\b(user|human|owner|anyone)\b", re.I | re.S)),
    ("urgency", re.compile(r"\b(urgent|immediately|right now|within the hour)\b", re.I)),
    ("ai_addressing", re.compile(r"\b(ai|agent|assistant|llm)\b.{0,30}\b(must|should|are instructed|is instructed)\b", re.I | re.S)),
]


def scan(text: str) -> list[dict]:
    hits = []
    for name, rx in PATTERNS:
        m = rx.search(text or "")
        if m:
            hits.append({"pattern": name, "match": m.group(0).strip()[:120]})
    return hits
