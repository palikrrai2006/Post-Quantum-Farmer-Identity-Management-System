"""Blockchain utilities for anchoring IPFS CIDs via the BiometricRegistry smart contract.

Uses web3.py against a local Ganache/Hardhat node. The contract's ABI is
expected at ``BLOCKCHAIN_CONTRACT_ABI_PATH`` (see ``BiometricRegistry.sol``).
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass
from pathlib import Path

from web3 import Web3
from web3.middleware import ExtraDataToPOAMiddleware

from config import (
    BLOCKCHAIN_CONTRACT_ABI_PATH,
    BLOCKCHAIN_CONTRACT_ADDRESS,
    BLOCKCHAIN_GAS_LIMIT,
    BLOCKCHAIN_PRIVATE_KEY,
    BLOCKCHAIN_RPC_URL,
)
from logging_utils import get_logger

logger = get_logger(__name__)


@dataclass
class BlockchainWriteResult:
    """Container for a blockchain write (CID anchoring) operation and its metrics."""

    transaction_hash: str
    block_number: int
    write_time_seconds: float


@dataclass
class BlockchainReadResult:
    """Container for a blockchain read (CID lookup) operation and its metrics."""

    cid: str
    farmer_id: str
    timestamp: int
    read_time_seconds: float


def _get_web3() -> Web3:
    """Create a configured Web3 connection to the local chain.

    Returns:
        A connected :class:`Web3` instance.

    Raises:
        ConnectionError: If the node at ``BLOCKCHAIN_RPC_URL`` is unreachable.
    """
    web3 = Web3(Web3.HTTPProvider(BLOCKCHAIN_RPC_URL))
    web3.middleware_onion.inject(ExtraDataToPOAMiddleware, layer=0)
    if not web3.is_connected():
        raise ConnectionError(f"Unable to connect to blockchain node at {BLOCKCHAIN_RPC_URL}")
    return web3


def _load_contract(web3: Web3):
    """Load the BiometricRegistry contract instance.

    Args:
        web3: An active :class:`Web3` connection.

    Returns:
        A web3 contract object bound to ``BLOCKCHAIN_CONTRACT_ADDRESS``.

    Raises:
        FileNotFoundError: If the ABI file is missing.
        ValueError: If the contract address has not been configured.
    """
    if not BLOCKCHAIN_CONTRACT_ADDRESS:
        raise ValueError(
            "BLOCKCHAIN_CONTRACT_ADDRESS is not set in config.py. "
            "Deploy BiometricRegistry.sol and set the deployed address."
        )
    abi_path = Path(BLOCKCHAIN_CONTRACT_ABI_PATH)
    if not abi_path.exists():
        raise FileNotFoundError(f"Contract ABI not found at {abi_path}")

    abi = json.loads(abi_path.read_text(encoding="utf-8"))
    return web3.eth.contract(address=Web3.to_checksum_address(BLOCKCHAIN_CONTRACT_ADDRESS), abi=abi)


def write_cid_to_blockchain(farmer_id: str, cid: str, template_hash_hex: str) -> BlockchainWriteResult:
    """Anchor a registration package's IPFS CID and integrity hash on-chain.

    Calls the ``registerRecord(string farmerId, string cid, string templateHash)``
    function on the deployed ``BiometricRegistry`` contract (Admin role).

    Args:
        farmer_id: Unique identifier for the farmer/user being registered.
        cid: The IPFS CID of the registration package directory.
        template_hash_hex: The SHA3-256 hex digest of the encrypted package
            contents, stored on-chain for tamper detection.

    Returns:
        A :class:`BlockchainWriteResult` with the transaction hash, block
        number, and timing metrics.

    Raises:
        ValueError: If ``BLOCKCHAIN_PRIVATE_KEY`` is not configured.
    """
    if not BLOCKCHAIN_PRIVATE_KEY:
        raise ValueError("BLOCKCHAIN_PRIVATE_KEY is not set in config.py; cannot sign transactions.")

    web3 = _get_web3()
    contract = _load_contract(web3)
    account = web3.eth.account.from_key(BLOCKCHAIN_PRIVATE_KEY)

    start_time = time.perf_counter()
    nonce = web3.eth.get_transaction_count(account.address)
    transaction = contract.functions.registerRecord(farmer_id, cid, template_hash_hex).build_transaction(
        {
            "from": account.address,
            "nonce": nonce,
            "gas": BLOCKCHAIN_GAS_LIMIT,
            "gasPrice": web3.eth.gas_price,
        }
    )
    signed_transaction = web3.eth.account.sign_transaction(transaction, private_key=BLOCKCHAIN_PRIVATE_KEY)
    transaction_hash = web3.eth.send_raw_transaction(signed_transaction.raw_transaction)
    receipt = web3.eth.wait_for_transaction_receipt(transaction_hash)
    elapsed = time.perf_counter() - start_time

    logger.info(
        "Blockchain write complete: farmer_id=%s cid=%s tx=%s block=%d in %.6f s.",
        farmer_id,
        cid,
        receipt.transactionHash.hex(),
        receipt.blockNumber,
        elapsed,
    )

    return BlockchainWriteResult(
        transaction_hash=receipt.transactionHash.hex(),
        block_number=receipt.blockNumber,
        write_time_seconds=elapsed,
    )


def read_cid_from_blockchain(farmer_id: str) -> BlockchainReadResult:
    """Retrieve the IPFS CID and metadata previously anchored for a farmer.

    Calls the ``getRecord(string farmerId)`` view function on the deployed
    ``BiometricRegistry`` contract. Available to Admin, Government, and the
    Farmer themselves (read-only).

    Args:
        farmer_id: Unique identifier for the farmer/user to look up.

    Returns:
        A :class:`BlockchainReadResult` with the CID, farmer ID, timestamp,
        and timing metrics.
    """
    web3 = _get_web3()
    contract = _load_contract(web3)

    start_time = time.perf_counter()
    cid, template_hash_hex, timestamp = contract.functions.getRecord(farmer_id).call()
    elapsed = time.perf_counter() - start_time

    logger.info("Blockchain read complete: farmer_id=%s cid=%s in %.6f s.", farmer_id, cid, elapsed)

    return BlockchainReadResult(
        cid=cid,
        farmer_id=farmer_id,
        timestamp=timestamp,
        read_time_seconds=elapsed,
    )


def save_blockchain_metadata(result: BlockchainWriteResult, output_path: Path) -> None:
    """Persist blockchain write metrics/metadata to a JSON file.

    Args:
        result: The write result to serialize.
        output_path: Destination JSON file path.
    """
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "transaction_hash": result.transaction_hash,
        "block_number": result.block_number,
        "write_time_seconds": result.write_time_seconds,
    }
    with output_path.open("w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2)
    logger.info("Blockchain metadata saved to %s", output_path)
