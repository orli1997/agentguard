"""Address-poisoning threat intel, checked right before signing.

The intel comes from a separate project, the live address-poisoning detector
(github.com/orli1997/address-poisoning-base). It watches every USDC transfer on
Base mainnet and records each lookalike address that was used to plant a fake
transfer in a victim's history, together with the real address it imitates.
This module only READS that detector's SQLite database (live.db); it imports
nothing from the other project, so the two stay independent.

Why an agent needs this. The engine's LOOKALIKE_ADDRESS check compares the
destination with the payee's *trusted* addresses, so it is blind when there are
none (that case is only UNVERIFIED_DESTINATION, a review). An agent that takes an
address from the wallet's own transaction history is exactly the victim address
poisoning is built for, and it has no human instinct to compare the middle
characters.

Findings:

  KNOWN_POISONING_ADDRESS (block)  The destination was itself used to poison
      wallets. Evidence: the real address(es) it imitates, how many wallets it
      poisoned, first/last block seen. This also fires when the address is a
      *trusted* one: a poisoning address in a vendor registry or a mandate means
      someone copied it from a poisoned history into the trusted record.
  POSSIBLE_POISONING_ADDRESS (review)  Same, but every match is between
      low-entropy addresses (e.g. 0x0000...0000), which can match each other
      without any attack. The detector's own evaluation counts these as uncertain.
  POISONING_INTEL_CLEAR (info)  Not in the intel; records which snapshot was checked.
  POISONING_INTEL_STALE (info)  The detector has not written for a while, so new
      attackers may be missing. Absence from the intel never proved safety anyway.
  POISONING_INTEL_UNAVAILABLE (info, or review if required=True)  The database
      could not be read. Default is info: the intel is an extra layer on top of the
      engine's own rules, and the engine's decision without it is unchanged.

Scope: the intel is observed on Base mainnet USDC, but an EVM address is
controlled by the same key on every EVM chain, so a known poisoning address is
checked for every chain. The detector has a 4+4 exact-match rule and no recall
measurement: an address that is not in the intel can still be an attacker.
"""
from __future__ import annotations

import sqlite3
import time
from pathlib import Path
from typing import Callable, Optional

from . import address as addr
from .models import Finding, Severity

OBSERVED_ON = "base mainnet, USDC transfers"
MAX_MIMICS_IN_EVIDENCE = 5


def low_entropy(a: str) -> bool:
    """First 4 or last 4 hex chars are one repeated character (same rule as the detector's evaluation)."""
    h = addr.normalize(a)[2:]
    return len(set(h[:4])) == 1 or len(set(h[-4:])) == 1


class PoisoningIntel:
    """Read-only view of the detector's live.db (tables `pairs`, `loss_alerts`, `meta`)."""

    def __init__(self, path: str | Path, stale_after_s: float = 3600,
                 clock: Callable[[], float] = time.time):
        self.path, self.stale_after_s, self.clock = Path(path), stale_after_s, clock

    def _connect(self) -> sqlite3.Connection:
        if not self.path.is_file():
            raise FileNotFoundError(f"intel database not found: {self.path}")
        # mode=ro: this process can never write to the detector's database.
        return sqlite3.connect(f"{self.path.resolve().as_uri()}?mode=ro", uri=True, timeout=5)

    def lookup(self, address: str) -> dict:
        """{'snapshot': {...}, 'hit': None | {...}} for one address."""
        a = addr.normalize(address)
        con = self._connect()
        try:
            meta = dict(con.execute("SELECT k, v FROM meta"))
            updated = float(meta["updated_at"]) if meta.get("updated_at") else None
            snapshot = {"intel_updated_at": updated,
                        "intel_age_s": None if updated is None else round(self.clock() - updated),
                        "next_block": int(meta["next_block"]) if meta.get("next_block") else None}
            victims, events, first, last = con.execute(
                "SELECT COUNT(*), COALESCE(SUM(events), 0), MIN(first_block), MAX(last_block) "
                "FROM pairs WHERE lookalike = ?", (a,)).fetchone()
            if not victims:
                return {"snapshot": snapshot, "hit": None}
            mimics = [m for (m,) in con.execute(
                "SELECT mimics FROM pairs WHERE lookalike = ? GROUP BY mimics ORDER BY COUNT(*) DESC, mimics",
                (a,))]
            losses, lost_units = con.execute(
                "SELECT COUNT(*), COALESCE(SUM(amount_units), 0) FROM loss_alerts WHERE lookalike = ?",
                (a,)).fetchone()
        finally:
            con.close()
        return {"snapshot": snapshot, "hit": {
            "wallets_poisoned": victims, "poison_events": events,
            "first_block": first, "last_block": last,
            "mimics": mimics[:MAX_MIMICS_IN_EVIDENCE], "mimics_count": len(mimics),
            "losses_recorded": losses, "usdc_lost": str(lost_units / 10**6),
            "vanity_only": low_entropy(a) and all(low_entropy(m) for m in mimics),
        }}


def poisoning_findings(intel: PoisoningIntel, to: str, required: bool = False) -> list[Finding]:
    try:
        r = intel.lookup(to)
    except Exception as e:  # noqa: BLE001
        sev = Severity.REVIEW if required else Severity.INFO
        return [Finding(code="POISONING_INTEL_UNAVAILABLE", severity=sev,
                        message="Address-poisoning intel could not be read; destination not checked against it.",
                        evidence={"error": f"{type(e).__name__}: {e}", "required": required})]
    snap, hit, out = r["snapshot"], r["hit"], []
    age = snap["intel_age_s"]
    if age is None or age > intel.stale_after_s:
        out.append(Finding(code="POISONING_INTEL_STALE", severity=Severity.INFO,
                           message="Address-poisoning intel has not been updated recently; "
                                   "attackers seen since then are missing.",
                           evidence={**snap, "stale_after_s": intel.stale_after_s}))
    if hit is None:
        out.append(Finding(code="POISONING_INTEL_CLEAR", severity=Severity.INFO,
                           message="Destination is not a known poisoning address (absence is not proof of safety).",
                           evidence={"destination": to, "observed_on": OBSERVED_ON, **snap}))
        return out
    ev = {"destination": to, "observed_on": OBSERVED_ON, **hit, **snap}
    main = hit["mimics"][0]
    if hit["vanity_only"]:
        out.append(Finding(code="POSSIBLE_POISONING_ADDRESS", severity=Severity.REVIEW,
                           message=f"Destination matches poisoning records, but only between low-entropy addresses "
                                   f"(e.g. {addr.short(main)}), which can match without an attack.", evidence=ev))
    else:
        out.append(Finding(code="KNOWN_POISONING_ADDRESS", severity=Severity.BLOCK,
                           message=f"Destination {addr.short(to)} was used to poison {hit['wallets_poisoned']} "
                                   f"wallet(s), imitating {main}. It is not the real address.", evidence=ev))
    return out
