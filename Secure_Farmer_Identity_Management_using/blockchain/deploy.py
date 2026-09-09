"""
blockchain/deploy.py
=====================
Compiles blockchain/contracts/FarmerIdentity.sol and deploys it to a local
Ethereum-compatible chain (Ganache by default), then writes the resulting
address + ABI into blockchain/contract_config.json so blockchain_utils.py
(and the rest of the app) can load it.

Requires (on your machine, with network access):
    pip install web3 py-solc-x
    Ganache running at config.BLOCKCHAIN_RPC_URL (default http://127.0.0.1:7545)

Run:
    python -m blockchain.deploy
"""

import json
import os

from web3 import Web3
import solcx

import config

CONTRACT_SOL_PATH = os.path.join(config.PROJECT_ROOT, "blockchain", "contracts", "FarmerIdentity.sol")
SOLC_VERSION = "0.8.20"


def compile_contract():
    solcx.install_solc(SOLC_VERSION)

    compiled = solcx.compile_files(
        [CONTRACT_SOL_PATH],
        output_values=["abi", "bin"],
        solc_version=SOLC_VERSION,
        evm_version="paris",   # <-- Add this
    )

    key = [k for k in compiled if k.endswith(":FarmerIdentity")][0]
    return compiled[key]["abi"], compiled[key]["bin"]

def deploy():
    w3 = Web3(Web3.HTTPProvider(config.BLOCKCHAIN_RPC_URL))
    if not w3.is_connected():
        raise ConnectionError(
            f"Cannot connect to blockchain at {config.BLOCKCHAIN_RPC_URL}. "
            f"Start Ganache first (see README 'Blockchain Setup')."
        )

    deployer = w3.eth.accounts[2]  # Ganache's first pre-funded account
    abi, bytecode = compile_contract()

    Contract = w3.eth.contract(abi=abi, bytecode=bytecode)
    tx_hash = Contract.constructor().transact({
    "from": deployer,
    "gas": 6000000
})
    receipt = w3.eth.wait_for_transaction_receipt(tx_hash)

    contract_address = receipt.contractAddress
    print(f"Deployed FarmerIdentity at {contract_address} (tx {tx_hash.hex()})")

    with open(config.CONTRACT_CONFIG_PATH, "w") as f:
        json.dump({"address": contract_address, "abi": abi, "deployer": deployer}, f, indent=2)

    print(f"Wrote contract config to {config.CONTRACT_CONFIG_PATH}")
    return contract_address, abi


if __name__ == "__main__":
    deploy()
