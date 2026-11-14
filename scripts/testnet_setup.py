"""Create the testnet wallets (once) and show what they hold.

    python scripts/testnet_setup.py

Wallets are stored in secrets/testnet_wallets.json (git-ignored). TESTNET ONLY:
never send real funds to these addresses.
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from agentguard.evm import RPC_URL, eth_balance, load_or_create_wallets, token_balance  # noqa: E402
from agentguard.observe_rpc import USDC, Rpc  # noqa: E402

WALLETS = ROOT / "secrets" / "testnet_wallets.json"
NET = "base-sepolia"


def main() -> None:
    w = load_or_create_wallets(WALLETS, ["service_agent_wallet", "vendor_acme"])
    rpc = Rpc(RPC_URL[NET])
    print(f"Network: Base Sepolia (testnet, chain id 84532). Keys: {WALLETS} (never commit, never fund with real money)\n")
    for name, info in w.items():
        a = info["address"]
        try:
            eth, usdc = eth_balance(rpc, a), token_balance(rpc, USDC[NET], a)
            bal = f"{eth:.6f} ETH   {usdc} USDC"
        except Exception as e:  # noqa: BLE001
            bal = f"(could not read balance: {e})"
        print(f"  {name:<22} {a}   {bal}")
    svc = w["service_agent_wallet"]["address"]
    print(f"\nTo run the testnet demo, fund the service wallet:\n  {svc}\n"
          "  - a little Base Sepolia ETH for gas (0.001 is plenty)\n"
          "  - a few test USDC on Base Sepolia (faucet.circle.com)")


if __name__ == "__main__":
    main()
