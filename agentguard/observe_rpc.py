"""Observe: read ERC-20 transfers for given wallets from a public EVM JSON-RPC node.

Read-only. Uses only the standard JSON-RPC methods (eth_blockNumber, eth_getLogs,
eth_getBlockByNumber, eth_getTransactionReceipt). No keys, no third-party SDK.

Limits worth knowing:
  * Reverted transactions emit no Transfer log, so a FAILED payment is only
    visible through the receipt of a tx hash the executor reported.
  * Public RPC endpoints cap eth_getLogs block ranges; callers page through.
"""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from decimal import Decimal

from .reconcile import PaymentObserved

TRANSFER_TOPIC = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"

# Native USDC (Circle) contracts. 6 decimals on both.
USDC = {
    "base": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
    "base-sepolia": "0x036CbD53842c5426634e7929541eC2318f3dCF7e",
}
PUBLIC_RPC = {"base": "https://mainnet.base.org", "base-sepolia": "https://sepolia.base.org"}


class Rpc:
    def __init__(self, url: str, timeout: float = 20):
        self.url, self.timeout, self._id = url, timeout, 0

    def call(self, method: str, params: list, retries: int = 5):
        self._id += 1
        body = json.dumps({"jsonrpc": "2.0", "id": self._id, "method": method, "params": params}).encode()
        req = urllib.request.Request(self.url, data=body, headers={"Content-Type": "application/json",
                                                                   "User-Agent": "agentguard-observer/0.3"})
        for attempt in range(retries):
            try:
                with urllib.request.urlopen(req, timeout=self.timeout) as r:
                    out = json.loads(r.read())
                break
            except urllib.error.HTTPError as e:
                # Public nodes rate-limit (429) and hiccup (5xx): back off and retry; anything else is real.
                if e.code not in (429, 500, 502, 503, 504) or attempt == retries - 1:
                    raise
                time.sleep(min(2 ** attempt, 16))
        if "error" in out:
            raise RuntimeError(f"{method}: {out['error']}")
        return out["result"]


def _topic(address: str) -> str:
    return "0x" + "0" * 24 + address.lower()[2:]


def _addr(topic: str) -> str:
    return "0x" + topic[-40:]


def head(rpc: Rpc) -> int:
    return int(rpc.call("eth_blockNumber", []), 16)


def transfers(rpc: Rpc, chain: str, token_contract: str, wallets: list[str], from_block: int, to_block: int,
              token: str = "USDC", decimals: int = 6, step: int = 2000) -> list[PaymentObserved]:
    """All Transfer logs where a wallet is sender or recipient, between two blocks (inclusive)."""
    logs, block_times = [], {}
    wallet_topics = [_topic(w) for w in wallets] or None
    for start in range(from_block, to_block + 1, step):
        end = min(start + step - 1, to_block)
        for topics in ([TRANSFER_TOPIC, wallet_topics], [TRANSFER_TOPIC, None, wallet_topics]):
            logs += rpc.call("eth_getLogs", [{"address": token_contract, "fromBlock": hex(start),
                                             "toBlock": hex(end), "topics": topics}])
    seen, out = set(), []
    for lg in logs:
        k = (lg["transactionHash"], lg["logIndex"])
        if k in seen:
            continue
        seen.add(k)
        bn = int(lg["blockNumber"], 16)
        if bn not in block_times:
            blk = rpc.call("eth_getBlockByNumber", [hex(bn), False])
            block_times[bn] = datetime.fromtimestamp(int(blk["timestamp"], 16), tz=timezone.utc)
        out.append(PaymentObserved(
            chain=chain, tx_hash=lg["transactionHash"], log_index=int(lg["logIndex"], 16), block_number=bn,
            block_time=block_times[bn], token=token, from_address=_addr(lg["topics"][1]),
            to_address=_addr(lg["topics"][2]), amount=Decimal(int(lg["data"], 16)) / Decimal(10) ** decimals))
    return sorted(out, key=lambda o: (o.block_number, o.log_index))


def receipt_status(rpc: Rpc, tx_hash: str) -> str | None:
    """'success', 'reverted', or None if the tx is not mined (or unknown to this node)."""
    r = rpc.call("eth_getTransactionReceipt", [tx_hash])
    if r is None:
        return None
    return "success" if int(r["status"], 16) == 1 else "reverted"
