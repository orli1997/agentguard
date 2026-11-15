"""Create a vendor wallet that carries an EIP-7702 delegation, on Base Sepolia. TESTNET ONLY.

    python scripts/testnet_7702_setup.py

Plays the attacker's side once, so the demo has a real delegated wallet to look at:
  1. creates wallet "acme_compromised" (secrets/, git-ignored)
  2. the service wallet sends it a little test ETH for gas (a plain ETH transfer)
  3. the wallet signs a type-4 (EIP-7702) transaction delegating itself to 0x...dEaD

0x...dEaD has no code, so the delegation does nothing harmful; what matters is that
eth_getCode now returns the delegation designator (0xef0100 + delegate), exactly as
it would for a sweeper. Running it again does nothing if the delegation is in place.
"""
from __future__ import annotations

import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from eth_account import Account  # noqa: E402

from agentguard.delegation import delegate_of  # noqa: E402
from agentguard.evm import CHAIN_ID, EXPLORER, RPC_URL, eth_balance, load_or_create_wallets  # noqa: E402
from agentguard.observe_rpc import Rpc  # noqa: E402

NET = "base-sepolia"
WALLETS = ROOT / "secrets" / "testnet_wallets.json"
DELEGATE = "0x000000000000000000000000000000000000dEaD"


def send(rpc: Rpc, key: str, tx: dict) -> str:
    sender = Account.from_key(key).address
    base = int(rpc.call("eth_getBlockByNumber", ["latest", False])["baseFeePerGas"], 16)
    tip = 1_000_000
    tx = {"type": 2, "chainId": CHAIN_ID[NET], "value": 0, "data": "0x", "maxPriorityFeePerGas": tip,
          "maxFeePerGas": base * 2 + tip, "nonce": int(rpc.call("eth_getTransactionCount", [sender, "pending"]), 16),
          **tx}
    h = rpc.call("eth_sendRawTransaction", ["0x" + Account.sign_transaction(tx, key).raw_transaction.hex().removeprefix("0x")])
    for _ in range(45):
        r = rpc.call("eth_getTransactionReceipt", [h])
        if r:
            if int(r["status"], 16) != 1:
                raise RuntimeError(f"tx failed: {h}")
            return h
        time.sleep(2)
    raise TimeoutError(h)


def main() -> None:
    rpc = Rpc(RPC_URL[NET])
    assert int(rpc.call("eth_chainId", []), 16) == CHAIN_ID[NET]
    w = load_or_create_wallets(WALLETS, ["service_agent_wallet", "vendor_acme", "acme_compromised"])
    victim, vkey = w["acme_compromised"]["address"], w["acme_compromised"]["key"]
    if delegate_of(rpc.call("eth_getCode", [victim, "latest"])):
        print(f"{victim} is already delegated: {rpc.call('eth_getCode', [victim, 'latest'])}")
        return
    if eth_balance(rpc, victim) < 10 ** -5:
        h = send(rpc, w["service_agent_wallet"]["key"], {"to": victim, "value": 2 * 10 ** 13, "gas": 21_000})
        print(f"gas money sent:      {EXPLORER[NET]}/tx/{h}")
    n = int(rpc.call("eth_getTransactionCount", [victim, "pending"]), 16)
    # self-sponsored: the tx itself uses nonce n, so the authorization must carry n + 1
    auth = Account.sign_authorization({"chainId": CHAIN_ID[NET], "address": DELEGATE, "nonce": n + 1}, vkey)
    h = send(rpc, vkey, {"type": 4, "to": victim, "gas": 100_000, "authorizationList": [auth]})
    print(f"delegation (type 4): {EXPLORER[NET]}/tx/{h}")
    print(f"eth_getCode({victim}) = {rpc.call('eth_getCode', [victim, 'latest'])}")


if __name__ == "__main__":
    main()
