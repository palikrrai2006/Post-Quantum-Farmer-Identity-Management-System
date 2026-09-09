"""
blockchain/blockchain_utils.py
===============================
Web3.py wrapper around the deployed FarmerIdentity contract.

Requires: pip install web3, a running Ganache instance, and a completed
`python -m blockchain.deploy` (which writes blockchain/contract_config.json).
"""

import json
import time

import config


class BlockchainUnavailableError(RuntimeError):
    pass


def _load_contract_config():
    try:
        with open(config.CONTRACT_CONFIG_PATH) as f:
            cfg = json.load(f)
    except FileNotFoundError:
        raise BlockchainUnavailableError(f"{config.CONTRACT_CONFIG_PATH} not found. Run `python -m blockchain.deploy` first.")
    if not cfg.get("address"):
        raise BlockchainUnavailableError("Contract not yet deployed — run `python -m blockchain.deploy` first.")
    return cfg


def connect_to_blockchain():
    """Returns (w3, contract). Raises BlockchainUnavailableError if unreachable."""
    try:
        from web3 import Web3
    except ImportError:
        raise BlockchainUnavailableError("web3.py is not installed. Run: pip install web3")

    w3 = Web3(Web3.HTTPProvider(config.BLOCKCHAIN_RPC_URL))
    if not w3.is_connected():
        raise BlockchainUnavailableError(
            f"Cannot connect to blockchain node at {config.BLOCKCHAIN_RPC_URL}. Start Ganache first."
        )

    cfg = _load_contract_config()
    contract = w3.eth.contract(address=cfg["address"], abi=cfg["abi"])
    return w3, contract, cfg["deployer"]


def store_fingerprint_record(farmer_id: str, finger_position: str, ipfs_cid: str, integrity_hash_hex: str):
    """
    Calls registerFingerprintRecord() on-chain.
    Returns: {"tx_hash": str, "storage_time_ns": int, "block_number": int}
    """
    w3, contract, deployer = connect_to_blockchain()
    integrity_hash_bytes32 = bytes.fromhex(integrity_hash_hex)

    start = time.perf_counter_ns()
    tx_hash = contract.functions.registerFingerprintRecord(
        farmer_id, finger_position, ipfs_cid, integrity_hash_bytes32
    ).transact({"from": deployer})
    receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
    elapsed = time.perf_counter_ns() - start

    return {
        "tx_hash": tx_hash.hex(),
        "storage_time_ns": elapsed,
        "block_number": receipt.blockNumber,
        "status": receipt.status,
    }


def retrieve_fingerprint_record(farmer_id: str, finger_position: str):
    """
    Calls getFingerprintRecord() (a view function — no gas, no tx).
    Returns: {"ipfs_cid", "integrity_hash", "timestamp", "status", "recorded_by", "retrieval_time_ns"}
    """
    w3, contract, _ = connect_to_blockchain()

    start = time.perf_counter_ns()
    ipfs_cid, integrity_hash, timestamp, status, recorded_by = contract.functions.getFingerprintRecord(
        farmer_id, finger_position
    ).call()
    elapsed = time.perf_counter_ns() - start

    return {
        "ipfs_cid": ipfs_cid,
        "integrity_hash": integrity_hash.hex(),
        "timestamp": timestamp,
        "status": status,
        "recorded_by": recorded_by,
        "retrieval_time_ns": elapsed,
    }


def update_fingerprint_record(farmer_id: str, finger_position: str, new_cid: str, new_hash_hex: str):
    w3, contract, deployer = connect_to_blockchain()
    new_hash_bytes32 = bytes.fromhex(new_hash_hex)
    tx_hash = contract.functions.updateFingerprintRecord(
        farmer_id, finger_position, new_cid, new_hash_bytes32
    ).transact({"from": deployer})
    receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
    return {"tx_hash": tx_hash.hex(), "block_number": receipt.blockNumber, "status": receipt.status}


def fingerprint_record_exists(farmer_id: str, finger_position: str) -> bool:
    _, contract, _ = connect_to_blockchain()
    return contract.functions.fingerprintRecordExists(farmer_id, finger_position).call()


if __name__ == "__main__":
    try:
        w3, contract, deployer = connect_to_blockchain()
        print("Connected. Deployer account:", deployer)
        print("Chain ID:", w3.eth.chain_id, "Block number:", w3.eth.block_number)
    except BlockchainUnavailableError as e:
        print(e)
