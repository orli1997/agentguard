"""EIP-7702 delegation check, run against the chain right before signing.

Since Ethereum's Pectra upgrade (and the matching OP-stack upgrade on Base), an
ordinary wallet (EOA) can point its code at a contract with one signed
"authorization". From then on, any call to that wallet runs the contract's code.
The wallet's private key still works, but whoever controls the delegate contract
controls what the wallet does. Drainers use this to install "sweepers" that empty
a wallet automatically.

On-chain the delegation is visible: eth_getCode(wallet) returns exactly
0xef0100 followed by the 20-byte delegate address (the "delegation designator").

What this module checks, and why:

  SOURCE_WALLET_DELEGATED (block)  The service's own wallet carries a delegation the
      service never made. Its behaviour is no longer just "the key signs"; stop all
      payments until a person looks. The service itself only ever signs plain type-2
      ERC-20 transfers, never a type-4 authorization, so it cannot create one.
  DESTINATION_7702_DELEGATED (review)  The payee's wallet runs someone's contract code.
      Legitimate smart-account wallets do this too, so it is a review, not a block,
      unless the delegate is on the trusted list.
  CHAIN_CHECK_FAILED (review)  The chain could not be read; fail closed.

Limits: this is a point-in-time read. A delegation set after the check and before
the transfer is mined is not seen here (Reconcile sees the outcome, not the code).
Which delegates are "trusted" is configuration, not knowledge we have.
"""
from __future__ import annotations

from typing import Iterable, Optional, Protocol

from .models import Finding, Severity

DESIGNATOR_PREFIX = "0xef0100"


class CodeReader(Protocol):
    def code(self, address: str) -> str: ...


def delegate_of(code: str) -> Optional[str]:
    """The delegate address if `code` is an EIP-7702 designator, else None."""
    c = (code or "").lower()
    if c.startswith(DESIGNATOR_PREFIX) and len(c) == 2 + 46:     # 0x + 23 bytes
        return "0x" + c[len(DESIGNATOR_PREFIX):]
    return None


def delegation_findings(reader: CodeReader, from_wallet: str, to: str,
                        trusted_delegates: Iterable[str] = ()) -> list[Finding]:
    trusted = {a.lower() for a in trusted_delegates}
    try:
        src, dst = reader.code(from_wallet), reader.code(to)
    except Exception as e:   # noqa: BLE001  fail closed
        return [Finding(code="CHAIN_CHECK_FAILED", severity=Severity.REVIEW,
                        message="Could not read wallet code from the chain; human review required.",
                        evidence={"error": f"{type(e).__name__}: {e}"})]
    out: list[Finding] = []
    d = delegate_of(src)
    if d and d not in trusted:
        out.append(Finding(code="SOURCE_WALLET_DELEGATED", severity=Severity.BLOCK,
                           message=f"The paying wallet {from_wallet} is delegated (EIP-7702) to {d}, which the "
                                   "service did not set. Payments stop until a person checks the wallet.",
                           evidence={"wallet": from_wallet, "delegate": d}))
    d = delegate_of(dst)
    if d and d not in trusted:
        out.append(Finding(code="DESTINATION_7702_DELEGATED", severity=Severity.REVIEW,
                           message=f"The destination {to} is delegated (EIP-7702) to {d}: its behaviour is set by "
                                   "that contract. Confirm with the payee before paying.",
                           evidence={"destination": to, "delegate": d}))
    elif d:
        out.append(Finding(code="DESTINATION_DELEGATE_TRUSTED", severity=Severity.INFO,
                           message=f"Destination is delegated to trusted delegate {d}.",
                           evidence={"destination": to, "delegate": d}))
    return out
