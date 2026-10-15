"""Address helpers. MVP scope: EVM-style addresses only."""
from __future__ import annotations

import re

_EVM_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")


def is_valid_evm(address: str) -> bool:
    # Format check only. EIP-55 checksum is NOT verified (needs keccak-256,
    # which the stdlib lacks) -- known gap, listed in README.
    return bool(_EVM_RE.match(address or ""))


def normalize(address: str) -> str:
    return (address or "").strip().lower()


def same_address(a: str, b: str) -> bool:
    return normalize(a) == normalize(b)


def is_lookalike(candidate: str, reference: str, prefix: int = 4, suffix: int = 4) -> bool:
    """True if two *different* addresses share the visible prefix and suffix.

    This is the address-poisoning pattern: wallets and humans usually display
    0x1234...abcd, so an attacker grinds a vanity address with the same ends.
    """
    c, r = normalize(candidate), normalize(reference)
    if c == r or not (is_valid_evm(c) and is_valid_evm(r)):
        return False
    c_hex, r_hex = c[2:], r[2:]
    return c_hex[:prefix] == r_hex[:prefix] and c_hex[-suffix:] == r_hex[-suffix:]


def short(address: str) -> str:
    a = address or ""
    return a if len(a) < 12 else f"{a[:6]}...{a[-4:]}"
