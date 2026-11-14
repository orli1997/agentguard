"""Phase B: a real signer and observer for an EVM testnet (Base Sepolia).

EvmSigner sends ERC-20 transfers (USDC) signed with a key that lives only in
the service process. TestnetObserver reads them back for Reconcile.

TESTNET ONLY. Keys are plain files on disk (secrets/, git-ignored). A real
deployment needs an HSM/MPC signer and must never keep keys like this.
"""
from __future__ import annotations

import json
import secrets
import threading
import time
from datetime import datetime, timezone
from decimal import Decimal
from pathlib import Path

from eth_account import Account

from .observe_rpc import USDC, Rpc, head, transfers
from .reconcile import PaymentObserved

CHAIN_ID = {"base-sepolia": 84532}
EXPLORER = {"base-sepolia": "https://sepolia.basescan.org"}
RPC_URL = {"base-sepolia": "https://sepolia.base.org"}
TRANSFER_SELECTOR = "a9059cbb"          # transfer(address,uint256)
BALANCE_OF_SELECTOR = "70a08231"        # balanceOf(address)


def _word(hex_no_prefix: str) -> str:
    return hex_no_prefix.rjust(64, "0")


def load_or_create_wallets(path: Path, names: list[str]) -> dict[str, dict]:
    """{name: {"address", "key"}}; creates missing ones. The file must stay out of git."""
    data = json.loads(path.read_text()) if path.exists() else {}
    changed = False
    for n in names:
        if n not in data:
            acct = Account.from_key("0x" + secrets.token_hex(32))
            data[n] = {"address": acct.address, "key": acct.key.hex()}
            changed = True
    if changed:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(data, indent=2))
    return data


def eth_balance(rpc: Rpc, address: str) -> Decimal:
    return Decimal(int(rpc.call("eth_getBalance", [address, "latest"]), 16)) / Decimal(10) ** 18


def token_balance(rpc: Rpc, contract: str, address: str, decimals: int = 6) -> Decimal:
    data = "0x" + BALANCE_OF_SELECTOR + _word(address.lower()[2:])
    raw = rpc.call("eth_call", [{"to": contract, "data": data}, "latest"])
    return Decimal(int(raw, 16)) / Decimal(10) ** decimals


class EvmSigner:
    """Signs and broadcasts USDC transfers for the wallets it holds keys for. Waits for the receipt."""

    def __init__(self, rpc: Rpc, network: str, keys: dict[str, str], decimals: int = 6, wait_seconds: float = 90):
        self.rpc, self.network, self.decimals, self.wait = rpc, network, decimals, wait_seconds
        self._keys = {Account.from_key(k).address.lower(): k for k in keys.values()}
        self._lock = threading.Lock()
        self.chain_id = CHAIN_ID[network]
        actual = int(rpc.call("eth_chainId", []), 16)
        if actual != self.chain_id:
            raise RuntimeError(f"RPC is on chain {actual}, expected {network} ({self.chain_id}); refusing to sign")

    def transfer(self, *, chain: str, token: str, from_wallet: str, to: str, amount: Decimal, now: datetime) -> str:
        if chain != self.network or token.upper() != "USDC":
            raise ValueError(f"this signer only sends USDC on {self.network}, not {token} on {chain}")
        key = self._keys.get(from_wallet.lower())
        if key is None:
            raise PermissionError(f"no signing key for {from_wallet}")
        units = int((amount * Decimal(10) ** self.decimals).to_integral_exact())
        data = "0x" + TRANSFER_SELECTOR + _word(to.lower()[2:]) + _word(format(units, "x"))
        sender = Account.from_key(key).address
        with self._lock:   # one nonce at a time
            nonce = int(self.rpc.call("eth_getTransactionCount", [sender, "pending"]), 16)
            base_fee = int(self.rpc.call("eth_getBlockByNumber", ["latest", False])["baseFeePerGas"], 16)
            try:
                tip = int(self.rpc.call("eth_maxPriorityFeePerGas", []), 16)
            except RuntimeError:
                tip = 1_000_000
            gas = int(self.rpc.call("eth_estimateGas", [{"from": sender, "to": USDC[self.network], "data": data}]), 16)
            tx = {"type": 2, "chainId": self.chain_id, "nonce": nonce, "to": USDC[self.network], "value": 0,
                  "data": data, "gas": int(gas * 1.25), "maxPriorityFeePerGas": tip,
                  "maxFeePerGas": base_fee * 2 + tip}
            signed = Account.sign_transaction(tx, key)
            tx_hash = self.rpc.call("eth_sendRawTransaction", ["0x" + signed.raw_transaction.hex().removeprefix("0x")])
        deadline = time.time() + self.wait
        while time.time() < deadline:
            if self.rpc.call("eth_getTransactionReceipt", [tx_hash]) is not None:
                break
            time.sleep(2)
        return tx_hash

    def explorer(self, tx_hash: str) -> str:
        return f"{EXPLORER[self.network]}/tx/{tx_hash}"


class TestnetObserver:
    """Reads USDC Transfer events to/from the service wallets since a starting block."""

    def __init__(self, rpc: Rpc, network: str, wallets: list[str], from_block: int):
        self.rpc, self.network, self.wallets, self.from_block = rpc, network, wallets, from_block

    def observed(self) -> list[PaymentObserved]:
        return transfers(self.rpc, self.network, USDC[self.network], self.wallets, self.from_block, head(self.rpc),
                         step=500)

    def heads(self) -> dict[str, int]:
        return {self.network: head(self.rpc)}


def now_utc() -> datetime:
    return datetime.now(timezone.utc)
